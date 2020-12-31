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

void mac_address_from_string(char *string, uint8_t *mac) {
    sscanf(string, "%02X:%02X:%02X:%02X:%02X:%02X", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
}

void mac_address_to_string(char *string, uint8_t *mac) {
    sprintf(string, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void ip_from_string(char *string, ip4_t *ip) {
    uint32_t first_octet, second_octet, third_octet, fourth_octet;
    sscanf(string, "%d.%d.%d.%d", &first_octet, &second_octet, &third_octet, &fourth_octet);

    ip->as_int = is_big_endian() ?
                 ((first_octet << 24) | (second_octet << 16) | (third_octet << 8) | fourth_octet) :
                 ((fourth_octet << 24) | (third_octet << 16) | (second_octet << 8) | first_octet);
}

void ip_to_string(char *string, ip4_t *ip) {
    sprintf(string, "%d.%d.%d.%d", ip->as_bytes[0], ip->as_bytes[1], ip->as_bytes[2], ip->as_bytes[3]);
}

int is_big_endian() {
    ip4_t address = { 0x01000000 };
    return address.as_bytes[0];
}