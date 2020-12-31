#include "dhcp/client/utils/packet-builder.h"
#include "dhcp/client/utils/nettypes.h"

#include "utils/utils.h"
#include <string.h>

static size_t ether_output(uint8_t *frame, const uint8_t *mac, const uint8_t *mac_dest, size_t len);
static int fill_dhcp_option(uint8_t *packet, uint8_t code, uint8_t *data, uint8_t len);
static uint16_t in_cksum(uint16_t *addr, size_t len);

size_t packet_builder_create_discovery(uint8_t *packet, size_t size, const uint8_t *mac) {
    size_t len = 0;
    struct ip *ip_header = (struct ip *) (packet + sizeof(struct ether_header));
    struct udphdr *udp_header = (struct udphdr *) (((char *)ip_header) + sizeof(struct ip));
    dhcp_t *dhcp = (dhcp_t *) (((char *)udp_header) + sizeof(struct udphdr));

    uint8_t option = DHCP_OPTION_DISCOVER;
    len += fill_dhcp_option(&dhcp->bp_options[len], MESSAGE_TYPE_DHCP_MESSAGE_TYPE, &option, sizeof(option));
    option = 0;
    len += fill_dhcp_option(&dhcp->bp_options[len], MESSAGE_TYPE_END, &option, sizeof(option));

    len += sizeof(dhcp_t);

    dhcp->opcode = DHCP_BOOTREQUEST;
    dhcp->htype = DHCP_HARDWARE_TYPE_10_EHTHERNET;
    dhcp->hlen = 6;
    memcpy(dhcp->chaddr, mac, ETHER_ADDR_LEN);
    dhcp->magic_cookie = htonl(DHCP_MAGIC_COOKIE);

    if (len & 1) len += 1;
    len += sizeof(struct udphdr);

    udp_header->uh_sport = htons(DHCP_CLIENT_PORT);
    udp_header->uh_dport = htons(DHCP_SERVER_PORT);
    udp_header->uh_ulen = htons(len);
    udp_header->uh_sum = 0;

    len += sizeof(struct ip);

    ip_header->ip_hl = 5;
    ip_header->ip_v = IPVERSION;
    ip_header->ip_tos = 0x10;
    ip_header->ip_len = htons(len);
    ip_header->ip_id = htons(0xffff);
    ip_header->ip_off = 0;
    ip_header->ip_ttl = 16;
    ip_header->ip_p = IPPROTO_UDP;
    ip_header->ip_sum = 0;
    ip_header->ip_src.s_addr = 0;
    ip_header->ip_dst.s_addr = 0xFFFFFFFF;
    ip_header->ip_sum = in_cksum((unsigned short *) ip_header, sizeof(struct ip));

    uint8_t mac_broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    return ether_output(packet, mac, mac_broadcast, len);
}

size_t packet_builder_create_request(uint8_t *packet, size_t size, dhcp_client_request_data_t data) {
    size_t len = 0;
    struct ip *ip_header = (struct ip *) (packet + sizeof(struct ether_header));
    struct udphdr *udp_header = (struct udphdr *) (((char *)ip_header) + sizeof(struct ip));
    dhcp_t *dhcp = (dhcp_t *) (((char *)udp_header) + sizeof(struct udphdr));
    memset(dhcp, 0, sizeof(dhcp_t));

    uint8_t option = DHCP_OPTION_REQUEST;
    uint8_t parameter_req_list[] = {MESSAGE_TYPE_REQ_SUBNET_MASK, MESSAGE_TYPE_ROUTER, MESSAGE_TYPE_DNS, MESSAGE_TYPE_DOMAIN_NAME};

    // 53 - DHCP Message Type
    len += fill_dhcp_option(&dhcp->bp_options[len], MESSAGE_TYPE_DHCP_MESSAGE_TYPE, &option, sizeof(option));
    // 61 - Client Identifier (Mac address)
    uint8_t client_identifier[7];
    client_identifier[0] = 0x01;
    memcpy(&(client_identifier[1]), data.mac, LENGTH_MAC_ADDRESS_AS_BYTES);
    len += fill_dhcp_option(&dhcp->bp_options[len], MESSAGE_TYPE_CLIENT_IDENTIFIER, (uint8_t *) client_identifier, sizeof(client_identifier));
    // 50 - Requested IP Address
    len += fill_dhcp_option(&dhcp->bp_options[len], MESSAGE_TYPE_REQ_IP, (uint8_t *) &(data.offer_data.ip), sizeof(data.offer_data.ip));

    // 54 - DHCP Server Identifier
    len += fill_dhcp_option(&dhcp->bp_options[len], MESSAGE_TYPE_DHCP_IP, (uint8_t *) &(data.offer_data.dhcp_server), sizeof(data.offer_data.dhcp_server));

    // 12 - Hostname
    char hostname[] = "myeggs";
    len += fill_dhcp_option(&dhcp->bp_options[len], MESSAGE_TYPE_CLIENT_HOSTNAME, (uint8_t *) hostname, strlen(hostname));

    // 81 - Client Fully Qualified Domain name - IGNORED
    // 60 - Vendor Class identifier - IGNORED
    // 55 - Request parameter list
    len += fill_dhcp_option(&dhcp->bp_options[len], MESSAGE_TYPE_PARAMETER_REQ_LIST, (uint8_t *)&parameter_req_list, sizeof(parameter_req_list));
    // 255- END
    option = 0;
    len += fill_dhcp_option(&dhcp->bp_options[len], MESSAGE_TYPE_END, &option, sizeof(option));

    len += sizeof(dhcp_t);

    dhcp->opcode = DHCP_BOOTREQUEST;
    dhcp->htype = DHCP_HARDWARE_TYPE_10_EHTHERNET;
    dhcp->hlen = 6;
    dhcp->flags = 0x0080;
    dhcp->xid = 0xBABACA00;
    dhcp->ciaddr = data.offer_data.ip;
    dhcp->yiaddr = data.offer_data.ip;
    memcpy(dhcp->chaddr, data.mac, ETHER_ADDR_LEN);
    dhcp->magic_cookie = htonl(DHCP_MAGIC_COOKIE);

    if (len & 1) len += 1;
    len += sizeof(struct udphdr);

    udp_header->uh_sport = htons(DHCP_CLIENT_PORT);
    udp_header->uh_dport = htons(DHCP_SERVER_PORT);
    udp_header->uh_ulen = htons(len);
    udp_header->uh_sum = 0;

    len += sizeof(struct ip);

    ip_header->ip_hl = 5;
    ip_header->ip_v = IPVERSION;
    ip_header->ip_tos = 0x00;
    ip_header->ip_len = htons(len);
    ip_header->ip_id = htons(0xffff);
    ip_header->ip_off = 0;
    ip_header->ip_ttl = 16;
    ip_header->ip_p = IPPROTO_UDP;
    ip_header->ip_sum = 0;
    ip_header->ip_src.s_addr = 0;
    ip_header->ip_dst.s_addr = 0xFFFFFFFF;

    ip_header->ip_sum = in_cksum((unsigned short *) ip_header, sizeof(struct ip));

    uint8_t mac_broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    return ether_output(packet, data.mac, mac_broadcast, len);
}

size_t packet_builder_create_decline(uint8_t *packet, size_t size, dhcp_client_decline_data_t data) {
    size_t len = 0;
    struct ip *ip_header = (struct ip *) (packet + sizeof(struct ether_header));
    struct udphdr *udp_header = (struct udphdr *) (((char *)ip_header) + sizeof(struct ip));
    dhcp_t *dhcp = (dhcp_t *) (((char *)udp_header) + sizeof(struct udphdr));
    memset(dhcp, 0, sizeof(dhcp_t));

    uint8_t option = DHCP_OPTION_DECLINE;

    // 53 - DHCP Message Type
    len += fill_dhcp_option(&dhcp->bp_options[len], MESSAGE_TYPE_DHCP_MESSAGE_TYPE, &option, sizeof(option));

    // 61 - Client Identifier (Mac address)
    uint8_t client_identifier[7];
    client_identifier[0] = 0x01;
    memcpy(&(client_identifier[1]), data.mac, LENGTH_MAC_ADDRESS_AS_BYTES);
    len += fill_dhcp_option(&dhcp->bp_options[len], MESSAGE_TYPE_CLIENT_IDENTIFIER, (uint8_t *) client_identifier, sizeof(client_identifier));

    // 50 - Requested IP address
    len += fill_dhcp_option(&dhcp->bp_options[len], MESSAGE_TYPE_REQ_IP, (uint8_t *) &(data.ack_data.ip), sizeof(data.ack_data.ip));

    // 54 - DHCP Server Identifier
    len += fill_dhcp_option(&dhcp->bp_options[len], MESSAGE_TYPE_DHCP_IP, (uint8_t *) &(data.ack_data.dhcp_server), sizeof(data.ack_data.dhcp_server));

    // 255- END
    option = 0;
    len += fill_dhcp_option(&dhcp->bp_options[len], MESSAGE_TYPE_END, &option, sizeof(option));

    len += sizeof(dhcp_t);

    dhcp->opcode = DHCP_BOOTREQUEST;
    dhcp->htype = DHCP_HARDWARE_TYPE_10_EHTHERNET;
    dhcp->hlen = 6;
    dhcp->flags = 0x0080;
    dhcp->xid = 0xBABACA00;

    dhcp->ciaddr = data.ack_data.ip;

    memcpy(dhcp->chaddr, data.mac, ETHER_ADDR_LEN);
    dhcp->magic_cookie = htonl(DHCP_MAGIC_COOKIE);

    if (len & 1) len += 1;
    len += sizeof(struct udphdr);

    udp_header->uh_sport = htons(DHCP_CLIENT_PORT);
    udp_header->uh_dport = htons(DHCP_SERVER_PORT);
    udp_header->uh_ulen = htons(len);
    udp_header->uh_sum = 0;

    len += sizeof(struct ip);

    ip_header->ip_hl = 5;
    ip_header->ip_v = IPVERSION;
    ip_header->ip_tos = 0x00;
    ip_header->ip_len = htons(len);
    ip_header->ip_id = htons(0xffff);
    ip_header->ip_off = 0;
    ip_header->ip_ttl = 16;
    ip_header->ip_p = IPPROTO_UDP;
    ip_header->ip_sum = 0;
    ip_header->ip_src.s_addr = 0;
    ip_header->ip_dst.s_addr = 0xFFFFFFFF;

    ip_header->ip_sum = in_cksum((unsigned short *) ip_header, sizeof(struct ip));

    uint8_t mac_broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    return ether_output(packet, data.mac, mac_broadcast, len);
}

/*
 * Ethernet output handler - Fills appropriate bytes in ethernet header
 */
static size_t ether_output(uint8_t *frame, const uint8_t *mac, const uint8_t *mac_dest, size_t len) {
    struct ether_header *eframe = (struct ether_header *) frame;

    memcpy(eframe->ether_shost, mac, ETHER_ADDR_LEN);
    memcpy(eframe->ether_dhost, mac_dest,  ETHER_ADDR_LEN);
    eframe->ether_type = htons(ETHERTYPE_IP);

    return len + sizeof(struct ether_header);
}

/*
 * Adds DHCP option to the bytestream
 */
static int fill_dhcp_option(uint8_t *packet, uint8_t code, uint8_t *data, uint8_t len) {
    packet[0] = code;
    packet[1] = len;
    memcpy(&packet[2], data, len);

    return len + (sizeof(uint8_t) * 2);
}

/*
 * Return checksum for the given data.
 * Copied from FreeBSD
 */
static uint16_t in_cksum(uint16_t *addr, size_t len) {
    register uint32_t sum = 0;
    uint16_t answer = 0;
    register uint16_t *w = addr;
    register uint32_t nleft = len;

    /*
     * Our algorithm is simple, using a 32 bit accumulator (sum), we add
     * sequential 16 bit words to it, and at the end, fold back all the
     * carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    /* mop up an odd byte, if necessary */
    if (nleft == 1) {
        *(u_char *)(&answer) = *(u_char *) w;
        sum += answer;
    }

    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
    sum += (sum >> 16);             /* add carry */
    answer = ~sum;              /* truncate to 16 bits */
    return (answer);
}