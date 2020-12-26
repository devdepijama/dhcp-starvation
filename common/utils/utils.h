#ifndef H_UTILS
#define H_UTILS

#include <stdint.h>
#include "log/logger.h"

#define MAX(a,b) ((a >= b) ? a : b)
#define MIN(a,b) ((a <= b) ? a : b)

typedef void (logger_function_t(logger_t logger, char *fmt, ...));

void log_bytes(logger_t logger, logger_function_t level, uint8_t *buffer, size_t size);

#endif