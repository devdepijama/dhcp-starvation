#include "dhcp/client/client.h"

#include <stdint.h>

#include "network/network.h"
#include "dhcp/client/utils/packet-builder.h"
#include "dhcp/client/utils/packet-unpacker.h"
#include "memory/memory.h"
#include "log/logger.h"
#include "settings/constants.h"

#define PACKET_BUFFER 4096
#define DESCRIPTION_INSTANCE "Instance of dhcp client"

struct dhcp_client_s {
    logger_t logger;
    network_t network;
    dhcp_client_callbacks_cfg_t callbacks;
    uint8_t packet[PACKET_BUFFER];
};

static void _dhcp_on_network_packet_received(network_t instance, const void *args, const uint8_t *frame, size_t length);
static void _build_network(dhcp_client_t instance, dhcp_client_args_t args);
static void _build_logger(dhcp_client_t instance, dhcp_client_args_t args);
static void _setup_callbacks(dhcp_client_t instance, dhcp_client_args_t args);

int dhcp_client_create(dhcp_client_t *instance, dhcp_client_args_t args) {
    *instance = memory_alloc(sizeof(struct dhcp_client_s), DESCRIPTION_INSTANCE);
    _build_logger(*instance, args);
    _build_network(*instance, args);
    _setup_callbacks(*instance, args);

    return DHCP_CLIENT_E_SUCCESSFUL;
}

int dhcp_client_init(dhcp_client_t instance) {
    logger_info(instance->logger, "Initializing...");
    network_init(instance->network);
    return DHCP_CLIENT_E_SUCCESSFUL;
}

int dhcp_client_discovery(dhcp_client_t instance, const uint8_t *mac) {
    size_t packet_size = 0;
    logger_info(instance->logger, "Performing discovery...");

    packet_size = packet_builder_create_discovery(instance->packet, sizeof(instance->packet), mac);
    network_send(instance->network, instance->packet, packet_size);

    return DHCP_CLIENT_E_SUCCESSFUL;
}

int dhcp_client_request(dhcp_client_t instance, dhcp_client_request_data_t data) {
    size_t packet_size = 0;
    logger_info(instance->logger, "Performing request...");

    packet_size = packet_builder_create_request(instance->packet, sizeof(instance->packet), data);
    network_send(instance->network, instance->packet, packet_size);

    return DHCP_CLIENT_E_SUCCESSFUL;
}

int dhcp_client_destroy(dhcp_client_t instance) {
    logger_info(instance->logger, "Destroying instance...");
    logger_destroy(instance->logger);
    network_destroy(instance->network);
    memory_free(instance, DESCRIPTION_INSTANCE);

    return DHCP_CLIENT_E_SUCCESSFUL;
}

static void _dhcp_on_network_packet_received(network_t network, const void *args, const uint8_t *frame, size_t length) {
    dhcp_t *dhcp;
    dhcp_client_t instance = (dhcp_client_t) args;
    logger_debug(instance->logger, "DHCP client received a packet candidate :D");

    if (is_dhcp_packet(frame, length, &dhcp) == FALSE) {
        logger_debug(instance->logger, "Candidate was not an DHCP packet...");
        return;
    }

    logger_info(instance->logger, "Received a DHCP packet");
    uint8_t dhcp_request_type = 0;
    read_dhcp_option(dhcp, MESSAGE_TYPE_DHCP_MESSAGE_TYPE, (uint8_t *) &dhcp_request_type, sizeof(dhcp_request_type));

    if (dhcp_request_type == DHCP_OPTION_OFFER) {
        logger_info(instance->logger, "It's an OFFER...");
        ip4_t dhcpserver;
        ip4_t gateway;
        ip4_t subnet;
        ip4_t dns;
        ip4_t ip;
        uint32_t lease_period;

        // Unpack information from DHCP packet
        read_dhcp_option(dhcp, MESSAGE_TYPE_DNS, (uint8_t *) &dns, sizeof(dns));
        read_dhcp_option(dhcp, MESSAGE_TYPE_REQ_SUBNET_MASK, (uint8_t *) &subnet, sizeof(subnet));
        read_dhcp_option(dhcp, MESSAGE_TYPE_ROUTER, (uint8_t *) &gateway, sizeof(gateway));
        read_dhcp_option(dhcp, MESSAGE_TYPE_LEASE_TIME_IN_SEC, (uint8_t *) &lease_period, sizeof(lease_period));
        read_dhcp_option(dhcp, MESSAGE_TYPE_DHCP_IP, (uint8_t *) &dhcpserver, sizeof(dhcpserver));
        ip.as_int = dhcp->yiaddr.as_int;

        dhcp_client_offer_data_t data = {
                .dhcp_server = dhcpserver,
                .gateway = gateway,
                .subnet = subnet,
                .dns = dns,
                .ip = ip,
                .lease_period_in_seconds = ntohl(lease_period)
        };
        void *args = instance->callbacks.on_offer_callback_cfg.args;
        instance->callbacks.on_offer_callback_cfg.callback(instance, args, data);
        return;
    }

    if (dhcp_request_type == DHCP_OPTION_ACK) {
        logger_info(instance->logger, "It's an ACK...");
        dhcp_client_ack_data_t data = {
                .anything = 11
        };
        void *args = instance->callbacks.on_ack_callback_cfg.args;
        instance->callbacks.on_ack_callback_cfg.callback(instance, args, data);
        return;
    }
}

static void _build_network(dhcp_client_t instance, dhcp_client_args_t args) {
    network_args_t network_args = {
        .interface_name = args.interface_name,
        .on_frame_received_callback = {
            .callback = (void (*)(network_t, const uint8_t *, const uint8_t *, size_t)) _dhcp_on_network_packet_received,
            .args = instance
        }
    };

    network_create(&(instance->network), network_args);
}

static void _build_logger(dhcp_client_t instance, dhcp_client_args_t args) {
    logger_create(&(instance->logger), "dhcp-client", CONSTANT_LOG_LEVEL);
}

static void _setup_callbacks(dhcp_client_t instance, dhcp_client_args_t args) {
    memcpy(&(instance->callbacks), &(args.callbacks), sizeof(instance->callbacks));
}