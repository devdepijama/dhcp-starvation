#ifndef H_UTILS
#define H_UTILS

#include <stdint.h>
#include "log/logger.h"
#include "network/network-types.h"

#define MAX(a,b) ((a >= b) ? a : b)
#define MIN(a,b) ((a <= b) ? a : b)

typedef int (logger_function_t(logger_t logger, char *fmt, ...));

void log_bytes(logger_t logger, logger_function_t level, uint8_t *buffer, size_t size);

void mac_address_from_string(char *string, uint8_t *mac);
void mac_address_to_string(char *string, uint8_t *mac);

void ip_from_string(char *string, ip4_t *ip);
void ip_to_string(char *string, ip4_t *ip);

int is_big_endian();

#endif