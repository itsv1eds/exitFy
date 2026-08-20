#include <stdlib.h>
#include <string.h>

/* Debug/androidTest-only implementation of the legacy coreApi=1 contract. */
static int running = 0;
static int stop_count = 0;

static char *copy_error(const char *value) {
    size_t size = strlen(value) + 1U;
    char *result = (char *) malloc(size);
    if (result != NULL) memcpy(result, value, size);
    return result;
}

__attribute__((visibility("default")))
char *StartCore(const char *config) {
    if (config == NULL) return copy_error("missing config");
    if (running) return copy_error("legacy fake core is already running");
    running = 1;
    stop_count = 0;
    return NULL;
}

__attribute__((visibility("default")))
void StopCore(void) {
    running = 0;
    stop_count++;
}

__attribute__((visibility("default")))
int ExitFyFakeV1IsRunning(void) {
    return running;
}

__attribute__((visibility("default")))
int ExitFyFakeV1StopCount(void) {
    return stop_count;
}
