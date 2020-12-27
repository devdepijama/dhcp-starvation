#ifndef H_PACKET_UNPACKER
#define H_PACKET_UNPACKER

#include <stdint.h>
#include "nettypes.h"

int is_dhcp_packet(const uint8_t *frame, size_t lenght, dhcp_t **dhcp_packet);

#endif