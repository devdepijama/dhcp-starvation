#ifndef H_CONSTANTS
#define H_CONSTANTS

#include "log/logger.h"

#define CONSTANT_LOG_LEVEL LOGGER_LEVEL_DEBUG
#define CONSTANT_NETWORK_INTERFACE_NAME "\\Device\\NPF_{A4BE0B64-2223-4646-B65F-E5B1BE6C75FF}"

#ifndef NULL
    #define NULL 0
#endif

#define TRUE 1
#define FALSE 0

#define ARRAY_SIZE(X) (sizeof(X)/sizeof(X[0]))

#endif