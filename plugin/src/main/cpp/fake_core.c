#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char *copy_error(const char *value) {
    size_t size = strlen(value) + 1;
    char *result = (char *) malloc(size);
    if (result != NULL) memcpy(result, value, size);
    return result;
}

static int stop_should_fail = 0;

__attribute__((visibility("default")))
char *StartCore(const char *config) {
    if (config == NULL) return copy_error("missing config");
    stop_should_fail = strstr(config, "stop_error") != NULL;
    if (strstr(config, "slow") != NULL) usleep(300000);
    if (strstr(config, "unicode") != NULL) {
        if (strstr(config, "unicode_input") != NULL) {
            return copy_error(strstr(config, "\xf0\x9f\x99\x82") != NULL
                    ? "UTF-8 input ok" : "UTF-8 input corrupted");
        }
        return copy_error("Ошибка ядра 🚀");
    }
    if (strstr(config, "replacement_input") != NULL) {
        return copy_error(strstr(config, "\xef\xbf\xbd") != NULL
                ? "replacement input ok" : "replacement input corrupted");
    }
    if (strstr(config, "malformed") != NULL) {
        char *result = (char *) malloc(9);
        if (result != NULL) {
            memcpy(result, "bad \xf0\x28\x8c\x28", 8);
            result[8] = '\0';
        }
        return result;
    }
    if (strstr(config, "long_error") != NULL) {
        char *result = (char *) malloc(6001);
        if (result != NULL) {
            memset(result, 'x', 6000);
            result[6000] = '\0';
        }
        return result;
    }
    if (strstr(config, "boundary_bad") != NULL
            || strstr(config, "boundary_valid") != NULL) {
        char *result = (char *) malloc(4102);
        if (result != NULL) {
            memset(result, 1, 4093);
            if (strstr(config, "boundary_valid") != NULL) {
                result[4093] = (char) 0xf0;
                result[4094] = (char) 0x9f;
                result[4095] = (char) 0x9a;
                result[4096] = (char) 0x80;
            } else {
                result[4093] = (char) 0xf0;
                result[4094] = '(';
                result[4095] = (char) 0x8c;
                result[4096] = '(';
            }
            result[4097] = 'x';
            result[4098] = 'x';
            result[4099] = 'x';
            result[4100] = 'x';
            result[4101] = '\0';
        }
        return result;
    }
    if (strstr(config, "error") != NULL) return copy_error("fake core error");
    return NULL;
}

__attribute__((visibility("default")))
char *StopCore(void) {
    if (stop_should_fail) {
        stop_should_fail = 0;
        return copy_error("Ошибка остановки 🛑");
    }
    return NULL;
}
