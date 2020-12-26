#include "network/network.h"

#include "memory/memory.h"
#include "log/logger.h"
#include "settings/constants.h"
#include "utils/utils.h"

#define DESCRIPTION_INSTANCE "network instance"

struct network_s {
    logger_t logger;
};

int network_create(network_t *instance) {
    *instance = memory_alloc(sizeof(struct network_s), DESCRIPTION_INSTANCE);
    logger_create(&((*instance)->logger), "network", CONSTANT_LOG_LEVEL);

    return NETWORK_E_SUCCESSFUL;
}

int network_init(network_t instance) {
    logger_info(instance->logger, "Initializing...");
    return NETWORK_E_SUCCESSFUL;
}

int network_send(network_t instance, uint8_t *packet, size_t size) {
    logger_info(instance->logger, "Sending a network packet...");
    log_bytes(instance->logger, logger_debug, packet, size);
    return NETWORK_E_SUCCESSFUL;
}

int network_destroy(network_t instance) {
    logger_info(instance->logger, "Destroying instance...");

    logger_destroy(instance->logger);
    memory_free(instance, DESCRIPTION_INSTANCE);
    return NETWORK_E_SUCCESSFUL;
}