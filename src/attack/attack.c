#include "attack/attack.h"
#include "memory/memory.h"
#include "log/logger.h"
#include "settings/constants.h"
#include "dhcp/client/client.h"
#include "utils/utils.h"

#include <string.h>

#define DESCRIPTION_INSTANCE "attack algorithm"

struct attack_s {
    logger_t logger;
    ip4_t malicious_dns;
    uint8_t mac[LENGTH_MAC_ADDRESS_AS_BYTES];
    char interface_name[LENGTH_INTERFACE_NAME];
    dhcp_client_t dhcp_client;
};

static void _build_dhcp_client(attack_t instance, attack_args_t args);
static void _build_logger(attack_t instance, attack_args_t args);
static void _extract_fields(attack_t instance, attack_args_t args);
static void _on_ack_callback(dhcp_client_t dhcp_client, void *args, dhcp_client_ack_data_t data);
static void _on_offer_callback(dhcp_client_t dhcp_client, void *args, dhcp_client_offer_data_t data);
static void _log_offer(attack_t instance, dhcp_client_offer_data_t offer);

int attack_create(attack_t *instance, attack_args_t args) {
    *instance = memory_alloc(sizeof(struct attack_s), DESCRIPTION_INSTANCE);
    _build_logger(*instance, args);
    _build_dhcp_client(*instance, args);
    _extract_fields(*instance, args);

    return ATTACK_E_SUCCESSFUL;
}


int attack_run(attack_t instance) {
    logger_info(instance->logger, "Running attack");
    dhcp_client_discovery(instance->dhcp_client, instance->mac);
    return ATTACK_E_SUCCESSFUL;
}

int attack_destroy(attack_t instance) {

}

static void _build_dhcp_client(attack_t instance, attack_args_t args) {
    dhcp_client_args_t dhcp_args = {
        .interface_name = args.interface_name,
        .callbacks = {
            .on_offer_callback_cfg = {
                .args = instance,
                .callback = _on_offer_callback
            },
            .on_ack_callback_cfg = {
                .args = instance,
                .callback = _on_ack_callback
            }
        }
    };
    dhcp_client_create(&(instance->dhcp_client), dhcp_args);
    dhcp_client_init(instance->dhcp_client);
}

static void _build_logger(attack_t instance, attack_args_t args) {
    logger_create(&(instance->logger), "attack-algorithm", CONSTANT_LOG_LEVEL);
}

static void _extract_fields(attack_t instance, attack_args_t args) {
    instance->malicious_dns = args.malicious_dns;
    strcpy(instance->interface_name, args.interface_name);
    memcpy(instance->mac, args.mac, sizeof(instance->mac));
}

static void _on_ack_callback(dhcp_client_t dhcp_client, void *args, dhcp_client_ack_data_t data) {
    attack_t instance = args;
    logger_info(instance->logger, "Just received a DHCP ACK");
}

static void _on_offer_callback(dhcp_client_t dhcp_client, void *args, dhcp_client_offer_data_t data) {
    attack_t instance = args;
    _log_offer(instance, data);
    dhcp_client_request(dhcp_client);
}

static void _log_offer(attack_t instance, dhcp_client_offer_data_t offer) {
    char ip[LENGTH_IP_ADDRESS_AS_STRING];
    char dns[LENGTH_IP_ADDRESS_AS_STRING];
    char gateway[LENGTH_IP_ADDRESS_AS_STRING];
    char subnet[LENGTH_IP_ADDRESS_AS_STRING];

    ip_to_string(ip, &(offer.ip));
    ip_to_string(dns, &(offer.dns));
    ip_to_string(gateway, &(offer.gateway));
    ip_to_string(subnet, &(offer.subnet));

    logger_info(instance->logger, "################ OFFER #################");
    logger_info(instance->logger, "Subnet: %s", subnet);
    logger_info(instance->logger, "Gateway: %s", gateway);
    logger_info(instance->logger, "IP: %s", ip);
    logger_info(instance->logger, "DNS: %s", dns);
    logger_info(instance->logger, "Lease time (seconds): %d", offer.lease_period_in_seconds);
    logger_info(instance->logger, "########################################");
}