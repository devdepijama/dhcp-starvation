#include "memory/memory.h"
#include "log/logger.h"
#include "settings/constants.h"

#include <stdlib.h>

static logger_t logger;

void memory_init() {
    logger_create(&logger, "memory", CONSTANT_LOG_LEVEL);
}

void * memory_alloc(unsigned int size, char *description) {
    void *result = malloc(size);
    if (!result) {
        logger_error(logger, "[addr:0x%X][bytes:%d] Failed to allocate memory for %s. Out of memory, bro? :P", result, size, description);
        exit(-1);
    }

    logger_debug(logger, "[addr:0x%X][bytes:%d] Allocated memory successfully for %s", result, size,  description);
    return result;
}
void memory_free(void *ptr, char *description) {
    logger_debug(logger, "[addr:0x%X] Freeing memory for %s", ptr, description);
    return free(ptr);
}