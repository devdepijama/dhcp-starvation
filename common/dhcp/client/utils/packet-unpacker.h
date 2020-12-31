#ifndef H_PACKET_UNPACKER
#define H_PACKET_UNPACKER

#include <stdint.h>
#include "nettypes.h"

int is_dhcp_packet(const uint8_t *frame, size_t lenght, dhcp_t **dhcp_packet);
int read_dhcp_option(const dhcp_t *dhcp_packet, uint8_t option, uint8_t *value, size_t len);
#endif