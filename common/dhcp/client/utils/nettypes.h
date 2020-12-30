#ifndef H_NETTYPES
#define H_NETTYPES

#include <stdint.h>
#include <winsock2.h>
#include <windows.h>

#include "network/network-types.h"

#define IPVERSION        4

#define	ETHERTYPE_IP	0x0800
#define ETHER_ADDR_LEN  6

#define DHCP_CHADDR_LEN 16
#define DHCP_SNAME_LEN  64
#define DHCP_FILE_LEN   128

#define DHCP_BOOTREQUEST                    1
#define DHCP_BOOTREPLY                      2

#define DHCP_HARDWARE_TYPE_10_EHTHERNET     1

#define MESSAGE_TYPE_PAD                    0
#define MESSAGE_TYPE_REQ_SUBNET_MASK        1
#define MESSAGE_TYPE_ROUTER                 3
#define MESSAGE_TYPE_DNS                    6
#define MESSAGE_TYPE_DOMAIN_NAME            15
#define MESSAGE_TYPE_REQ_IP                 50
#define MESSAGE_TYPE_LEASE_TIME_IN_SEC      51
#define MESSAGE_TYPE_DHCP_MESSAGE_TYPE      53
#define MESSAGE_TYPE_DHCP_IP                54
#define MESSAGE_TYPE_LEASE_TIME_IN_SEC      51
#define MESSAGE_TYPE_CLIENT_IDENTIFIER      61
#define MESSAGE_TYPE_PARAMETER_REQ_LIST     55
#define MESSAGE_TYPE_END                    255

#define DHCP_OPTION_DISCOVER                1
#define DHCP_OPTION_OFFER                   2
#define DHCP_OPTION_REQUEST                 3
#define DHCP_OPTION_DECLINE                 4
#define DHCP_OPTION_ACK                     5
#define DHCP_OPTION_NAK                     6

#define DHCP_SERVER_PORT    67
#define DHCP_CLIENT_PORT    68

#define DHCP_MAGIC_COOKIE   0x63825363

/*
 * http://www.tcpipguide.com/free/t_DHCPMessageFormat.htm
 */
typedef struct dhcp {
    uint8_t    opcode;
    uint8_t    htype;
    uint8_t    hlen;
    uint8_t    hops;
    uint32_t   xid;
    uint16_t   secs;
    uint16_t   flags;
    ip4_t      ciaddr;
    ip4_t      yiaddr;
    ip4_t      siaddr;
    ip4_t      giaddr;
    uint8_t    chaddr[DHCP_CHADDR_LEN];
    char       bp_sname[DHCP_SNAME_LEN];
    char       bp_file[DHCP_FILE_LEN];
    uint32_t   magic_cookie;
    uint8_t    bp_options[0];
} dhcp_t;

// https://unix.superglobalmegacorp.com/Net2/newsrc/netinet/if_ether.h.html
struct ether_header {
    uint8_t ether_dhost[ETHER_ADDR_LEN];
    uint8_t ether_shost[ETHER_ADDR_LEN];
    uint16_t ether_type;
};

struct ip {
    uint8_t ip_hl:4;		/* header length */
    uint8_t ip_v:4;		/* version */
    uint8_t ip_tos;			/* type of service */
    uint16_t ip_len;		/* total length */
    uint16_t ip_id;		/* identification */
    uint16_t ip_off;		/* fragment offset field */
#define	IP_RF 0x8000			/* reserved fragment flag */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
    uint8_t ip_ttl;			/* time to live */
    uint8_t ip_p;			/* protocol */
    uint16_t ip_sum;		/* checksum */
    struct in_addr ip_src, ip_dst;	/* source and dest address */
};

struct udphdr {
    uint16_t uh_sport;  /* source port */
    uint16_t uh_dport;  /* destination port */
    uint16_t uh_ulen;   /* udp length */
    uint16_t uh_sum;    /* udp checksum */
};

#endif