#include "dhcp/client.h"
#include "memory/memory.h"
#include "log/logger.h"
#include "settings/constants.h"

#define ALLOC_DESCRIPTION_INSTANCE "Instance of dhcp client"

typedef struct {
    dhcp_client_on_offer_callback_t *on_offer_callback;
    dhcp_client_on_ack_callback_t *on_ack_callback;
} dhcp_client_callbacks_t;

struct dhcp_client_s {
    logger_t logger;
    dhcp_client_callbacks_t callbacks;
};

int dhcp_client_create(dhcp_client_t *instance, dhcp_client_on_offer_callback_t on_offer_callback, dhcp_client_on_ack_callback_t on_ack_callback) {
    *instance = memory_alloc(sizeof(struct dhcp_client_s), ALLOC_DESCRIPTION_INSTANCE);
    logger_create(&((*instance)->logger), "dhcp-client", CONSTANT_LOG_LEVEL);
    (*instance)->callbacks.on_offer_callback = on_offer_callback;
    (*instance)->callbacks.on_ack_callback = on_ack_callback;

    return DHCP_CLIENT_E_SUCCESSFUL;
}

int dhcp_client_discovery(dhcp_client_t instance) {
    logger_info(instance->logger, "Performing discovery...");

    dhcp_client_offer_data_t data = {

    };
    instance->callbacks.on_offer_callback(instance, data);
    return DHCP_CLIENT_E_SUCCESSFUL;
}

int dhcp_client_request(dhcp_client_t instance) {
    logger_info(instance->logger, "Performing request...");
    dhcp_client_ack_data_t data = {

    };

    instance->callbacks.on_ack_callback(instance, data);
    return DHCP_CLIENT_E_SUCCESSFUL;
}

int dhcp_client_destroy(dhcp_client_t instance) {
    logger_info(instance->logger, "Destroying instance...");
    logger_destroy(instance->logger);
    memory_free(instance, ALLOC_DESCRIPTION_INSTANCE);
    
    return DHCP_CLIENT_E_SUCCESSFUL;
}