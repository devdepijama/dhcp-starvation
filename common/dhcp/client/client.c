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

typedef struct {
    dhcp_client_on_offer_callback_t *on_offer_callback;
    dhcp_client_on_ack_callback_t *on_ack_callback;
} dhcp_client_callbacks_t;

struct dhcp_client_s {
    logger_t logger;
    network_t network;
    dhcp_client_callbacks_t callbacks;
    uint8_t packet[PACKET_BUFFER];
};

static void _dhcp_on_network_packet_received(network_t instance, const void *args, const uint8_t *frame, size_t length);

int dhcp_client_create(dhcp_client_t *instance, dhcp_client_on_offer_callback_t on_offer_callback, dhcp_client_on_ack_callback_t on_ack_callback) {
    on_frame_received_cfg_t callback_cfg = {
        .callback = (void (*)(network_t, const uint8_t *, const uint8_t *, size_t)) _dhcp_on_network_packet_received,
        .args = NULL
    };

    *instance = memory_alloc(sizeof(struct dhcp_client_s), DESCRIPTION_INSTANCE);
    callback_cfg.args = *instance;

    logger_create(&((*instance)->logger), "dhcp-client", CONSTANT_LOG_LEVEL);
    network_create(&((*instance)->network), callback_cfg);
    (*instance)->callbacks.on_offer_callback = on_offer_callback;
    (*instance)->callbacks.on_ack_callback = on_ack_callback;

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

int dhcp_client_request(dhcp_client_t instance) {
    size_t packet_size = 0;
    logger_info(instance->logger, "Performing request...");

    packet_size = packet_builder_create_request(instance->packet, sizeof(instance->packet));
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
    if (dhcp->opcode == DHCP_OPTION_OFFER) {
        logger_info(instance->logger, "It's an OFFER...");
        return;
    }

    if (dhcp->opcode == DHCP_OPTION_PACK) {
        logger_info(instance->logger, "It's an ACK...");
        return;
    }
}