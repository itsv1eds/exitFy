#include <jni.h>
#include <android/dlext.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef char *(*start_core_fn)(const char *);
typedef void (*stop_core_v1_fn)(void);
typedef char *(*stop_core_v2_fn)(void);

#define MAX_ERROR_BYTES 4096U
#define MAX_ERROR_RUNES 1024U
#define UTF8_LOOKAHEAD_BYTES 4U
#define MAX_CONFIG_BYTES (16U * 1024U * 1024U)
#define MAX_PATH_BYTES 4096U
#define MAX_IDENTITY_BYTES 64U

enum conversion_result {
    CONVERSION_FAILED = 0,
    CONVERSION_OK = 1,
    CONVERSION_TOO_LARGE = 2
};

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
/*
 * StartCore is allowed to block while holding g_lock so that StopCore can
 * never enter the same Go runtime concurrently.  Immutable loader metadata
 * must remain observable while that happens: a new Java bridge uses the
 * identity to report "restart required" instead of hanging in its
 * constructor.  Never acquire g_lock while holding g_metadata_lock.
 */
static pthread_mutex_t g_metadata_lock = PTHREAD_MUTEX_INITIALIZER;

/*
 * One slot per core family.  A Go library is never unloaded, so a slot is
 * filled at most once per process.  g_lock still serializes every StartCore
 * and StopCore across both slots: only one core ever runs at a time, and two
 * Go runtimes are never entered concurrently.  Whether a second slot may be
 * filled at all is decided in Java, which keeps the single-core default
 * fail-closed.
 */
#define CORE_SLOT_COUNT 2

struct core_slot {
    void *handle;
    start_core_fn start;
    stop_core_v1_fn stop_v1;
    stop_core_v2_fn stop_v2;
    int core_api;
    char *identity;
    char *path;
    char load_error[512];
};

static struct core_slot g_slots[CORE_SLOT_COUNT];

static int slot_index(const char *identity) {
    if (identity == NULL) return -1;
    if (strcmp(identity, "sing_box") == 0) return 0;
    if (strcmp(identity, "xray") == 0) return 1;
    return -1;
}

#ifdef EXITFY_BUILD_FAKE_CORES
static pthread_mutex_t g_test_metadata_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_test_metadata_condition = PTHREAD_COND_INITIALIZER;
static int g_test_pause_metadata = 0;
static int g_test_metadata_pause_entered = 0;

static void test_pause_before_metadata_publish(void) {
    pthread_mutex_lock(&g_test_metadata_lock);
    if (g_test_pause_metadata) {
        g_test_metadata_pause_entered = 1;
        pthread_cond_broadcast(&g_test_metadata_condition);
        while (g_test_pause_metadata) {
            pthread_cond_wait(&g_test_metadata_condition, &g_test_metadata_lock);
        }
    }
    pthread_mutex_unlock(&g_test_metadata_lock);
}
#else
static void test_pause_before_metadata_publish(void) {
}
#endif

static uint32_t replacement_character(void) {
    return 0xfffdU;
}

static int utf8_sequence(const unsigned char *value, size_t remaining,
                         uint32_t *codepoint, size_t *consumed) {
    unsigned char first = value[0];
    if (first < 0x80U) {
        *codepoint = first;
        *consumed = 1;
        return 1;
    }
    size_t needed;
    uint32_t result;
    uint32_t minimum;
    if ((first & 0xe0U) == 0xc0U) {
        needed = 2;
        result = first & 0x1fU;
        minimum = 0x80U;
    } else if ((first & 0xf0U) == 0xe0U) {
        needed = 3;
        result = first & 0x0fU;
        minimum = 0x800U;
    } else if ((first & 0xf8U) == 0xf0U) {
        needed = 4;
        result = first & 0x07U;
        minimum = 0x10000U;
    } else {
        *codepoint = replacement_character();
        *consumed = 1;
        return 1;
    }
    if (remaining < needed) return 0;
    for (size_t index = 1; index < needed; index++) {
        unsigned char next = value[index];
        if ((next & 0xc0U) != 0x80U) {
            *codepoint = replacement_character();
            *consumed = 1;
            return 1;
        }
        result = (result << 6U) | (next & 0x3fU);
    }
    if (result < minimum || result > 0x10ffffU
            || (result >= 0xd800U && result <= 0xdfffU)) {
        *codepoint = replacement_character();
        *consumed = 1;
        return 1;
    }
    *codepoint = result;
    *consumed = needed;
    return 1;
}

static jstring result(JNIEnv *env, const char *value) {
    if (value == NULL) value = "";
    size_t available = strnlen(value, MAX_ERROR_BYTES + UTF8_LOOKAHEAD_BYTES);
    size_t limit = available > MAX_ERROR_BYTES ? MAX_ERROR_BYTES : available;
    /* Bounded by contract (4096 bytes / 1024 code points), so conversion
     * cannot fail into a misleading empty success merely because malloc did.
     * If NewString itself raises OOME, preserve the pending Java exception;
     * NativeCoreRuntime will quarantine the uncertain native call. */
    jchar utf16[MAX_ERROR_RUNES * 2U];

    size_t input = 0;
    size_t output = 0;
    size_t output_bytes = 0;
    size_t runes = 0;
    while (input < limit && runes < MAX_ERROR_RUNES) {
        uint32_t codepoint = 0;
        size_t consumed = 0;
        if (!utf8_sequence((const unsigned char *) value + input,
                           available - input, &codepoint, &consumed)) {
            codepoint = replacement_character();
            consumed = 1; /* Malformed trailing bytes are replaced individually. */
        }
        if (consumed > limit - input) {
            break; /* A valid code point crosses the byte cap; never split it. */
        }
        input += consumed;
        if (codepoint < 0x20U && codepoint != '\n' && codepoint != '\t') continue;
        size_t encoded_bytes = codepoint <= 0x7fU ? 1U
                : codepoint <= 0x7ffU ? 2U : codepoint <= 0xffffU ? 3U : 4U;
        if (encoded_bytes > MAX_ERROR_BYTES - output_bytes) break;
        if (codepoint <= 0xffffU) {
            utf16[output++] = (jchar) codepoint;
        } else {
            codepoint -= 0x10000U;
            utf16[output++] = (jchar) (0xd800U + (codepoint >> 10U));
            utf16[output++] = (jchar) (0xdc00U + (codepoint & 0x3ffU));
        }
        output_bytes += encoded_bytes;
        runes++;
    }
    return (*env)->NewString(env, utf16, (jsize) output);
}

static int append_utf8(char *output, size_t capacity, size_t *offset, uint32_t codepoint) {
    size_t needed = codepoint <= 0x7fU ? 1U
            : codepoint <= 0x7ffU ? 2U : codepoint <= 0xffffU ? 3U : 4U;
    if (*offset > capacity || needed > capacity - *offset) return 0;
    if (needed == 1U) {
        output[(*offset)++] = (char) codepoint;
    } else if (needed == 2U) {
        output[(*offset)++] = (char) (0xc0U | (codepoint >> 6U));
        output[(*offset)++] = (char) (0x80U | (codepoint & 0x3fU));
    } else if (needed == 3U) {
        output[(*offset)++] = (char) (0xe0U | (codepoint >> 12U));
        output[(*offset)++] = (char) (0x80U | ((codepoint >> 6U) & 0x3fU));
        output[(*offset)++] = (char) (0x80U | (codepoint & 0x3fU));
    } else {
        output[(*offset)++] = (char) (0xf0U | (codepoint >> 18U));
        output[(*offset)++] = (char) (0x80U | ((codepoint >> 12U) & 0x3fU));
        output[(*offset)++] = (char) (0x80U | ((codepoint >> 6U) & 0x3fU));
        output[(*offset)++] = (char) (0x80U | (codepoint & 0x3fU));
    }
    return 1;
}

static size_t utf8_size(uint32_t codepoint) {
    return codepoint <= 0x7fU ? 1U
            : codepoint <= 0x7ffU ? 2U : codepoint <= 0xffffU ? 3U : 4U;
}

#define UTF16_CHUNK_UNITS 1024

static int append_converted_codepoint(char *output, size_t maximum_bytes,
                                      size_t *offset, uint32_t codepoint) {
    /* The C core ABI is NUL-terminated and cannot represent embedded NUL
     * without truncation. Reject it instead of validating one Java string
     * and passing a shorter path/identity/config to native code. */
    if (codepoint == 0U) return CONVERSION_FAILED;
    size_t encoded = utf8_size(codepoint);
    if (*offset > maximum_bytes || encoded > maximum_bytes - *offset) {
        return CONVERSION_TOO_LARGE;
    }
    if (output == NULL) {
        *offset += encoded;
        return CONVERSION_OK;
    }
    return append_utf8(output, maximum_bytes, offset, codepoint)
            ? CONVERSION_OK : CONVERSION_FAILED;
}

static int convert_utf16_pass(JNIEnv *env, jstring value, jsize length,
                              size_t maximum_bytes, char *output,
                              size_t *converted_bytes) {
    jchar chunk[UTF16_CHUNK_UNITS];
    uint32_t pending_high = 0U;
    size_t offset = 0U;
    for (jsize position = 0; position < length;) {
        jsize remaining = length - position;
        jsize count = remaining < UTF16_CHUNK_UNITS
                ? remaining : UTF16_CHUNK_UNITS;
        (*env)->GetStringRegion(env, value, position, count, chunk);
        if ((*env)->ExceptionCheck(env)) return CONVERSION_FAILED;
        position += count;
        for (jsize index = 0; index < count; index++) {
            uint32_t current = chunk[index];
            if (pending_high != 0U) {
                if (current >= 0xdc00U && current <= 0xdfffU) {
                    uint32_t codepoint = 0x10000U
                            + ((pending_high - 0xd800U) << 10U)
                            + (current - 0xdc00U);
                    pending_high = 0U;
                    int converted = append_converted_codepoint(
                            output, maximum_bytes, &offset, codepoint);
                    if (converted != CONVERSION_OK) return converted;
                    continue;
                }
                int converted = append_converted_codepoint(
                        output, maximum_bytes, &offset, replacement_character());
                if (converted != CONVERSION_OK) return converted;
                pending_high = 0U;
            }
            if (current >= 0xd800U && current <= 0xdbffU) {
                pending_high = current;
                continue;
            }
            uint32_t codepoint = current >= 0xdc00U && current <= 0xdfffU
                    ? replacement_character() : current;
            int converted = append_converted_codepoint(
                    output, maximum_bytes, &offset, codepoint);
            if (converted != CONVERSION_OK) return converted;
        }
    }
    if (pending_high != 0U) {
        int converted = append_converted_codepoint(
                output, maximum_bytes, &offset, replacement_character());
        if (converted != CONVERSION_OK) return converted;
    }
    *converted_bytes = offset;
    return CONVERSION_OK;
}

static int jstring_to_utf8(JNIEnv *env, jstring value, size_t maximum_bytes,
                           char **output) {
    *output = NULL;
    if (value == NULL || maximum_bytes > SIZE_MAX - 1U) return CONVERSION_FAILED;
    jsize length = (*env)->GetStringLength(env, value);
    if (length < 0) return CONVERSION_FAILED;
    size_t exact_bytes = 0;
    int measured = convert_utf16_pass(
            env, value, length, maximum_bytes, NULL, &exact_bytes);
    if (measured != CONVERSION_OK) return measured;

    char *converted = malloc(exact_bytes + 1U);
    if (converted == NULL) return CONVERSION_FAILED;
    size_t written = 0;
    int encoded = convert_utf16_pass(
            env, value, length, exact_bytes, converted, &written);
    if (encoded != CONVERSION_OK || written != exact_bytes) {
        free(converted);
        return CONVERSION_FAILED;
    }
    converted[written] = '\0';
    *output = converted;
    return CONVERSION_OK;
}

static void *open_core(int source_fd, const char *path,
                       char *error, size_t error_size) {
    if (source_fd < 0) {
        snprintf(error, error_size, "invalid pinned core descriptor");
        return NULL;
    }

    int fd = fcntl(source_fd, F_DUPFD_CLOEXEC, 0);
    if (fd < 0) {
        snprintf(error, error_size, "cannot duplicate core descriptor: %s",
                 strerror(errno));
        return NULL;
    }
    struct stat status;
    if (fstat(fd, &status) != 0 || !S_ISREG(status.st_mode) || status.st_nlink != 1) {
        snprintf(error, error_size, "pinned core is not a single-link regular file");
        close(fd);
        return NULL;
    }

    android_dlextinfo info;
    memset(&info, 0, sizeof(info));
    info.flags = ANDROID_DLEXT_USE_LIBRARY_FD | ANDROID_DLEXT_FORCE_LOAD;
    info.library_fd = fd;
    void *handle = android_dlopen_ext(path, RTLD_NOW | RTLD_LOCAL, &info);
    close(fd);
    if (handle == NULL) {
        const char *dl_error = dlerror();
        snprintf(error, error_size, "android_dlopen_ext failed: %s",
                 dl_error == NULL ? "unknown" : dl_error);
    }
    return handle;
}

JNIEXPORT jstring JNICALL
Java_com_extera_plugins_exitfy_NativeBridge_nativeOpen(
        JNIEnv *env, jclass clazz, jint library_fd, jstring path_value,
        jstring identity_value, jint core_api) {
    (void) clazz;
    char *path = NULL;
    char *identity = NULL;
    int path_conversion = jstring_to_utf8(
            env, path_value, MAX_PATH_BYTES, &path);
    int identity_conversion = jstring_to_utf8(
            env, identity_value, MAX_IDENTITY_BYTES, &identity);
    if (path_conversion != CONVERSION_OK || identity_conversion != CONVERSION_OK) {
        free(path);
        free(identity);
        return result(env, path_conversion == CONVERSION_TOO_LARGE
                || identity_conversion == CONVERSION_TOO_LARGE
                ? "core path or identity exceeds UTF-8 limit"
                : "core path or identity conversion failed");
    }
    if (strcmp(identity, "sing_box") != 0 && strcmp(identity, "xray") != 0) {
        free(path);
        free(identity);
        return result(env, "invalid core identity");
    }
    if (core_api != 1 && core_api != 2) {
        free(path);
        free(identity);
        return result(env, "unsupported core API");
    }

    int index = slot_index(identity);
    pthread_mutex_lock(&g_lock);
    struct core_slot *slot = &g_slots[index];
    if (slot->handle != NULL) {
        char existing_error[512] = {0};
        if (slot->identity == NULL || slot->path == NULL
                || strcmp(slot->identity, identity) != 0
                || strcmp(slot->path, path) != 0) {
            snprintf(existing_error, sizeof(existing_error),
                     "core %s is already loaded from another path; restart exteraGram",
                     slot->identity == NULL ? "unknown" : slot->identity);
        } else if (slot->core_api != core_api) {
            snprintf(existing_error, sizeof(existing_error),
                     "core API changed in process; restart exteraGram");
        } else if (slot->load_error[0] != '\0') {
            snprintf(existing_error, sizeof(existing_error), "%s", slot->load_error);
        }
        pthread_mutex_unlock(&g_lock);
        free(path);
        free(identity);
        return result(env, existing_error);
    }

    char error[512] = {0};
    void *handle = open_core(library_fd, path, error, sizeof(error));
    if (handle != NULL) {
        slot->handle = handle;
        char *retained_identity = strdup(identity);
        char *retained_path = strdup(path);
        slot->path = retained_path;
        if (retained_identity == NULL || slot->path == NULL) {
            snprintf(error, sizeof(error), "cannot retain loaded core identity");
        }
        dlerror();
        start_core_fn start = (start_core_fn) dlsym(handle, "StartCore");
        const char *start_error = dlerror();
        dlerror();
        void *stop = dlsym(handle, "StopCore");
        const char *stop_error = dlerror();
        if (start == NULL || start_error != NULL || stop == NULL || stop_error != NULL) {
            snprintf(error, sizeof(error), "required exports missing: StartCore=%s StopCore=%s",
                     (start != NULL && start_error == NULL) ? "ok" : "missing",
                     (stop != NULL && stop_error == NULL) ? "ok" : "missing");
            /* A mapped Go library is deliberately never passed to dlclose. */
        } else if (error[0] == '\0') {
            slot->start = start;
            if (core_api == 1) slot->stop_v1 = (stop_core_v1_fn) stop;
            else slot->stop_v2 = (stop_core_v2_fn) stop;
        }
        test_pause_before_metadata_publish();
        /* Publish a valid identity/API pair, or identity/API=0 failure state,
         * in one metadata transaction after retention and export checks. */
        pthread_mutex_lock(&g_metadata_lock);
        slot->identity = retained_identity;
        slot->core_api = error[0] == '\0' ? core_api : 0;
        pthread_mutex_unlock(&g_metadata_lock);
        if (error[0] != '\0') {
            snprintf(slot->load_error, sizeof(slot->load_error), "%s", error);
        }
    }
    pthread_mutex_unlock(&g_lock);
    free(path);
    free(identity);
    return result(env, error);
}

/*
 * Every loaded identity, comma separated in slot order.  A process that
 * mapped one family returns exactly what it returned before two slots
 * existed, so the single-core path reads identically.
 */
JNIEXPORT jstring JNICALL
Java_com_extera_plugins_exitfy_NativeBridge_nativeLoadedIdentity(
        JNIEnv *env, jclass clazz) {
    (void) clazz;
    char joined[2 * (MAX_IDENTITY_BYTES + 1)] = {0};
    size_t used = 0;
    pthread_mutex_lock(&g_metadata_lock);
    for (int index = 0; index < CORE_SLOT_COUNT; index++) {
        const char *identity = g_slots[index].identity;
        if (identity == NULL || identity[0] == '\0') continue;
        int written = snprintf(joined + used, sizeof(joined) - used,
                               used == 0 ? "%s" : ",%s", identity);
        if (written <= 0 || (size_t) written >= sizeof(joined) - used) break;
        used += (size_t) written;
    }
    pthread_mutex_unlock(&g_metadata_lock);
    return result(env, joined);
}

JNIEXPORT jint JNICALL
Java_com_extera_plugins_exitfy_NativeBridge_nativeLoadedCoreApi(
        JNIEnv *env, jclass clazz, jstring identity_value) {
    (void) clazz;
    char *identity = NULL;
    if (jstring_to_utf8(env, identity_value, MAX_IDENTITY_BYTES, &identity)
            != CONVERSION_OK) {
        free(identity);
        return 0;
    }
    int index = slot_index(identity);
    free(identity);
    if (index < 0) return 0;
    pthread_mutex_lock(&g_metadata_lock);
    jint value = (jint) g_slots[index].core_api;
    pthread_mutex_unlock(&g_metadata_lock);
    return value;
}

JNIEXPORT jstring JNICALL
Java_com_extera_plugins_exitfy_NativeBridge_nativeStart(
        JNIEnv *env, jclass clazz, jstring identity_value, jstring config_value) {
    (void) clazz;
    char *identity = NULL;
    if (jstring_to_utf8(env, identity_value, MAX_IDENTITY_BYTES, &identity)
            != CONVERSION_OK) {
        free(identity);
        return result(env, "core identity conversion failed");
    }
    int index = slot_index(identity);
    free(identity);
    if (index < 0) return result(env, "invalid core identity");
    char *config = NULL;
    int conversion = jstring_to_utf8(
            env, config_value, MAX_CONFIG_BYTES, &config);
    if (conversion != CONVERSION_OK) {
        return result(env, conversion == CONVERSION_TOO_LARGE
                ? "config exceeds 16777216 UTF-8 bytes"
                : "config conversion failed");
    }
    pthread_mutex_lock(&g_lock);
    if (g_slots[index].start == NULL) {
        pthread_mutex_unlock(&g_lock);
        free(config);
        return result(env, "core is not loaded");
    }
    char *raw = g_slots[index].start(config);
    jstring output = result(env, raw == NULL ? "" : raw);
    free(raw);
    pthread_mutex_unlock(&g_lock);
    free(config);
    return output;
}

JNIEXPORT jstring JNICALL
Java_com_extera_plugins_exitfy_NativeBridge_nativeStop(
        JNIEnv *env, jclass clazz, jstring identity_value) {
    (void) clazz;
    char *identity = NULL;
    if (jstring_to_utf8(env, identity_value, MAX_IDENTITY_BYTES, &identity)
            != CONVERSION_OK) {
        free(identity);
        return result(env, "core identity conversion failed");
    }
    int index = slot_index(identity);
    free(identity);
    if (index < 0) return result(env, "invalid core identity");
    pthread_mutex_lock(&g_lock);
    struct core_slot *slot = &g_slots[index];
    char *raw = NULL;
    if (slot->core_api == 1 && slot->stop_v1 != NULL) slot->stop_v1();
    else if (slot->core_api == 2 && slot->stop_v2 != NULL) raw = slot->stop_v2();
    jstring output = result(env, raw == NULL ? "" : raw);
    free(raw);
    pthread_mutex_unlock(&g_lock);
    return output;
}

#ifdef EXITFY_BUILD_FAKE_CORES
typedef int (*test_int_fn)(void);

JNIEXPORT void JNICALL
Java_com_extera_plugins_exitfy_NativeBridgeTestHooks_nativeSetMetadataPause(
        JNIEnv *env, jclass clazz, jboolean enabled) {
    (void) env;
    (void) clazz;
    pthread_mutex_lock(&g_test_metadata_lock);
    g_test_pause_metadata = enabled == JNI_TRUE;
    if (g_test_pause_metadata) g_test_metadata_pause_entered = 0;
    else pthread_cond_broadcast(&g_test_metadata_condition);
    pthread_mutex_unlock(&g_test_metadata_lock);
}

JNIEXPORT jboolean JNICALL
Java_com_extera_plugins_exitfy_NativeBridgeTestHooks_nativeMetadataPauseEntered(
        JNIEnv *env, jclass clazz) {
    (void) env;
    (void) clazz;
    pthread_mutex_lock(&g_test_metadata_lock);
    jboolean value = g_test_metadata_pause_entered ? JNI_TRUE : JNI_FALSE;
    pthread_mutex_unlock(&g_test_metadata_lock);
    return value;
}

JNIEXPORT jstring JNICALL
Java_com_extera_plugins_exitfy_NativeBridgeTestHooks_nativeExerciseApiOne(
        JNIEnv *env, jclass clazz, jstring path_value) {
    (void) clazz;
    char *path = NULL;
    int conversion = jstring_to_utf8(env, path_value, MAX_PATH_BYTES, &path);
    if (conversion != CONVERSION_OK) {
        return result(env, conversion == CONVERSION_TOO_LARGE
                ? "legacy core path exceeds UTF-8 limit"
                : "legacy core path conversion failed");
    }
    char error[512] = {0};
    int source_fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (source_fd < 0) {
        free(path);
        return result(env, "cannot safely open legacy fake core");
    }
    void *handle = open_core(source_fd, path, error, sizeof(error));
    close(source_fd);
    free(path);
    if (handle == NULL) return result(env, error);

    dlerror();
    start_core_fn start = (start_core_fn) dlsym(handle, "StartCore");
    const char *start_error = dlerror();
    dlerror();
    stop_core_v1_fn stop = (stop_core_v1_fn) dlsym(handle, "StopCore");
    const char *stop_error = dlerror();
    dlerror();
    test_int_fn is_running = (test_int_fn) dlsym(handle, "ExitFyFakeV1IsRunning");
    const char *running_error = dlerror();
    dlerror();
    test_int_fn stop_count = (test_int_fn) dlsym(handle, "ExitFyFakeV1StopCount");
    const char *count_error = dlerror();
    if (start == NULL || start_error != NULL || stop == NULL || stop_error != NULL
            || is_running == NULL || running_error != NULL
            || stop_count == NULL || count_error != NULL) {
        return result(env, "legacy core test exports missing");
    }

    char *start_result = start("{}");
    if (start_result != NULL) {
        jstring output = result(env, start_result);
        free(start_result);
        return output;
    }
    if (!is_running()) return result(env, "legacy core did not start");
    stop();
    if (is_running() || stop_count() != 1) {
        return result(env, "legacy core first StopCore failed");
    }
    stop();
    if (is_running() || stop_count() != 2) {
        return result(env, "legacy core repeated StopCore failed");
    }
    return result(env, "");
}

JNIEXPORT void JNICALL
Java_com_extera_plugins_exitfy_NativeBridgeTestHooks_nativeResetBridgeForTests(
        JNIEnv *env, jclass clazz) {
    (void) env;
    (void) clazz;
    pthread_mutex_lock(&g_lock);
    pthread_mutex_lock(&g_metadata_lock);
    for (int index = 0; index < CORE_SLOT_COUNT; index++) {
        struct core_slot *slot = &g_slots[index];
        free(slot->identity);
        free(slot->path);
        slot->handle = NULL;
        slot->start = NULL;
        slot->stop_v1 = NULL;
        slot->stop_v2 = NULL;
        slot->core_api = 0;
        slot->identity = NULL;
        slot->path = NULL;
        slot->load_error[0] = '\0';
    }
    pthread_mutex_unlock(&g_metadata_lock);
    pthread_mutex_unlock(&g_lock);
}
#endif
