#include "dhcp/client/utils/packet-unpacker.h"
#include "dhcp/client/utils/nettypes.h"
#include "utils/utils.h"

#include <stdint.h>
#include <pcap.h>


int is_dhcp_packet(const uint8_t *frame, size_t lenght, dhcp_t **dhcp_packet) {
    struct ether_header *eframe = (struct ether_header *) frame;
    struct ip *ip_packet;
    struct udphdr *udp_packet;

    // frame is not an IP packet
    if (htons(eframe->ether_type) != ETHERTYPE_IP) {
        return FALSE;
    }

    ip_packet = (struct ip *) (frame + sizeof(struct ether_header));

    // It's not an UDP packet - DHCP responses arrive as UDP
    if (ip_packet->ip_p != IPPROTO_UDP) {
        return FALSE;
    }

    udp_packet = (struct udphdr *) ((uint8_t *) ip_packet + sizeof(struct ip));

    // It's and UDP packet, but not at the expected DHCP response port
    if (ntohs(udp_packet->uh_sport) != DHCP_SERVER_PORT) {
        return FALSE;
    }

    *dhcp_packet = (dhcp_t *) ((uint8_t *) udp_packet + sizeof(struct udphdr));
    return TRUE;
}

int read_dhcp_option(const dhcp_t *dhcp_packet, uint8_t option, uint8_t *value, size_t len) {
    uint8_t *options = &(dhcp_packet->bp_options);
    uint8_t tag;
    uint8_t size;

    do {
        tag = *options;
        options++;

        size = *options;
        options++;

        // The one we're looking for
        if (tag == option) {
            memcpy(value, options, MIN(len, size));
            return TRUE;
        }

        options += size;
    } while (tag != MESSAGE_TYPE_END);

    return FALSE;
}