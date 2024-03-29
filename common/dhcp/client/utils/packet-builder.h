#ifndef H_PACKET_BUILDER
#define H_PACKET_BUILDER

#include <stdint.h>
#include <dhcp/client/client.h>

size_t packet_builder_create_discovery(uint8_t *packet, size_t size, const uint8_t *mac, ip4_t my_ip, uint32_t xid);
size_t packet_builder_create_request(uint8_t *packet, size_t size, dhcp_client_request_data_t data);
size_t packet_builder_create_decline(uint8_t *packet, size_t size, dhcp_client_decline_data_t data);

#endif