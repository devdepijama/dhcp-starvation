#include "network/network.h"

#include "memory/memory.h"
#include "log/logger.h"
#include "settings/constants.h"
#include "utils/utils.h"

#include <pcap.h>
#include <stdio.h>
#include <tchar.h>

#define DESCRIPTION_INSTANCE        "network instance"
#define DESCRIPTION_PCAP_INTERFACES "pcap interface list"

#define PCAP_E_SUCCESSFUL               0
#define PCAP_E_COULD_NOT_LOAD_DLL       -1
#define PCAP_E_COULD_NOT_FIND_DEVICES   -2

struct network_s {
    logger_t logger;
    pcap_if_t **devices;
    size_t devices_length;
};

// Forward declaration of private methods
int _load_pcap_dlls(logger_t logger);

int _get_list_of_interfaces(logger_t logger, pcap_if_t ***devices, size_t *length);

int network_create(network_t *instance) {
    *instance = memory_alloc(sizeof(struct network_s), DESCRIPTION_INSTANCE);
    logger_create(&((*instance)->logger), "network", CONSTANT_LOG_LEVEL);
    (*instance)->devices_length = 0;

    return NETWORK_E_SUCCESSFUL;
}

int network_init(network_t instance) {
    logger_info(instance->logger, "Initializing...");
    logger_info(instance->logger, "Loading Npcap DLLs...");

    if (_load_pcap_dlls(instance->logger) != PCAP_E_SUCCESSFUL) {
        logger_error(instance->logger, "Couldn't load Npcap");
        return NETWORK_E_COULD_NOT_INIT;
    }

    logger_info(instance->logger, "Successfully loaded npcap...");

    logger_info(instance->logger, "Getting list of devices...");
    if (_get_list_of_interfaces(instance->logger, &(instance->devices), &(instance->devices_length)) !=
        PCAP_E_SUCCESSFUL) {
        logger_error(instance->logger, "Couldn't not find ");
        return NETWORK_E_COULD_NOT_INIT;
    }

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

    pcap_freealldevs(*(instance->devices));
    memory_free(instance->devices, DESCRIPTION_PCAP_INTERFACES);

    return NETWORK_E_SUCCESSFUL;
}

// Private methods
int _load_pcap_dlls(logger_t logger) {
    char npcap_dir[512];
    size_t len = GetSystemDirectory(npcap_dir, 480);
    if (len <= 0) {
        logger_error(logger, "Error in GetSystemDirectory: %x", GetLastError());
        return PCAP_E_COULD_NOT_LOAD_DLL;
    }

    _tcscat_s(npcap_dir, 512, _T("\\Npcap"));
    if (SetDllDirectory(npcap_dir) == 0) {
        logger_error(logger, "Error in SetDllDirectory: %x", GetLastError());
        return PCAP_E_COULD_NOT_LOAD_DLL;
    }

    return PCAP_E_SUCCESSFUL;
}

int _get_list_of_interfaces(logger_t logger, pcap_if_t ***devices, size_t *length) {
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int i = 0;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        logger_error(logger, "Couldn't find devices.. Details: %s", errbuf);
        return PCAP_E_COULD_NOT_FIND_DEVICES;
    }

    for (d = alldevs; d; d = d->next) {
        logger_info(logger, "-> %d. %s (%s)", ++i, d->name, ((d->description) ? d->description : "No description"));
    }

    if (i == 0) {
        logger_error(logger, "No interfaces found! Make sure Npcap is installed");
        return PCAP_E_COULD_NOT_FIND_DEVICES;
    }

    *devices = memory_alloc(i * sizeof(pcap_if_t *), DESCRIPTION_PCAP_INTERFACES);
    memset(*devices, 1, i * sizeof(pcap_if_t *));
    *length = i;

    i = 0;
    for (d = alldevs; d; d = d->next) {
        *(*devices + i++) = d;
    }

    return PCAP_E_SUCCESSFUL;
}