#ifndef H_NETWORK_TYPES
#define H_NETWORK_TYPES

#include <stdint.h>

typedef union {
    uint32_t as_int;
    uint8_t as_bytes[4];
} ip4_t;

#endif