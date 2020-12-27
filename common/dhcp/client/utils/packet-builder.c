#include "dhcp/client/utils/packet-builder.h"

#include "utils/utils.h"
#include <string.h>

uint32_t packet_builder_create_discovery(uint8_t *packet, size_t size) {

    strncpy((char *) packet, "mocked_discovery_packet", size);
    return MIN(strlen((char *) packet), size);
}

uint32_t packet_builder_create_request(uint8_t *packet, size_t size) {
    strncpy((char *) packet, "mocked_request_packet", size);
    return MIN(strlen((char *) packet), size);
}