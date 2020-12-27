#ifndef H_PACKET_BUILDER
#define H_PACKET_BUILDER

#include <stdint.h>

size_t packet_builder_create_discovery(uint8_t *packet, size_t size, const uint8_t *mac);
size_t packet_builder_create_request(uint8_t *packet, size_t size);

#endif