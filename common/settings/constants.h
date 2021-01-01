#ifndef H_CONSTANTS
#define H_CONSTANTS

#include "log/logger.h"

#define CONSTANT_LOG_LEVEL LOGGER_LEVEL_INFO

#define LENGTH_INTERFACE_NAME           128
#define LENGTH_MAC_ADDRESS_AS_BYTES     6
#define LENGTH_MAC_ADDRESS_AS_STRING    18
#define LENGTH_IP_ADDRESS_AS_BYTES      4
#define LENGTH_IP_ADDRESS_AS_STRING     18

#define STARVATION_THREADS              10

#ifndef NULL
    #define NULL 0
#endif

#define TRUE 1
#define FALSE 0

#define ARRAY_SIZE(X) (sizeof(X)/sizeof(X[0]))

#endif