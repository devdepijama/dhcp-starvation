#include "dhcp/client/utils/packet-unpacker.h"
#include "dhcp/client/utils/nettypes.h"

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