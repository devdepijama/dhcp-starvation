#include "dhcp/client/client.h"

#include <stdint.h>

#include "network/network.h"
#include "dhcp/client/utils/packet-builder.h"
#include "memory/memory.h"
#include "log/logger.h"
#include "settings/constants.h"

#define PACKET_BUFFER 1024
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

int dhcp_client_create(dhcp_client_t *instance, dhcp_client_on_offer_callback_t on_offer_callback, dhcp_client_on_ack_callback_t on_ack_callback) {
    *instance = memory_alloc(sizeof(struct dhcp_client_s), DESCRIPTION_INSTANCE);
    logger_create(&((*instance)->logger), "dhcp-client", CONSTANT_LOG_LEVEL);
    network_create(&((*instance)->network));
    (*instance)->callbacks.on_offer_callback = on_offer_callback;
    (*instance)->callbacks.on_ack_callback = on_ack_callback;

    return DHCP_CLIENT_E_SUCCESSFUL;
}

int dhcp_client_init(dhcp_client_t instance) {
    logger_info(instance->logger, "Initializing...");
    return DHCP_CLIENT_E_SUCCESSFUL;
}

int dhcp_client_discovery(dhcp_client_t instance) {
    size_t packet_size = 0;
    logger_info(instance->logger, "Performing discovery...");

    packet_size = packet_builder_create_discovery(instance->packet, sizeof(instance->packet));
    network_send(instance->network, instance->packet, packet_size);

    dhcp_client_offer_data_t data = {

    };
    instance->callbacks.on_offer_callback(instance, data);
    return DHCP_CLIENT_E_SUCCESSFUL;
}

int dhcp_client_request(dhcp_client_t instance) {
    size_t packet_size = 0;
    logger_info(instance->logger, "Performing request...");

    packet_size = packet_builder_create_request(instance->packet, sizeof(instance->packet));
    network_send(instance->network, instance->packet, packet_size);

    dhcp_client_ack_data_t data = {

    };

    instance->callbacks.on_ack_callback(instance, data);
    return DHCP_CLIENT_E_SUCCESSFUL;
}

int dhcp_client_destroy(dhcp_client_t instance) {
    logger_info(instance->logger, "Destroying instance...");
    logger_destroy(instance->logger);
    network_destroy(instance->network);
    memory_free(instance, DESCRIPTION_INSTANCE);

    return DHCP_CLIENT_E_SUCCESSFUL;
}