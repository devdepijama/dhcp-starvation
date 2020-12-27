#include "utils/utils.h"
#include <stdio.h>
#include <string.h>

void log_bytes(logger_t logger, logger_function_t level, uint8_t *buffer, size_t size) {
    const size_t bytes_per_line = 16;
    char line[257];
    char byte_representation[4];
    size_t remaining;

    // Iterate getting chunks of bytes_per_line
    for(size_t i = 0; i < size; i += bytes_per_line) {
        remaining = MIN(size - i, bytes_per_line);

        line[0] = '\0';
        // For each chunk, create unit representation of bytes and then glue them all together to be printed
        for(size_t j = i; j < (i + remaining); j++) {
            snprintf(byte_representation, sizeof(byte_representation), "%02X ", buffer[j]);
            strcat(line, byte_representation);
        }

        level(logger, line);
    }
}