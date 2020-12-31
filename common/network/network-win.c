#include "network/network.h"

#include "memory/memory.h"
#include "log/logger.h"
#include "settings/constants.h"
#include "utils/utils.h"

#include <pcap.h>
#include <stdio.h>
#include <tchar.h>
#include <windows.h>

#define DESCRIPTION_INSTANCE        "network instance"
#define DESCRIPTION_PCAP_INTERFACES "pcap interface list"

#define PCAP_E_SUCCESSFUL               0
#define PCAP_E_COULD_NOT_LOAD_DLL       -1
#define PCAP_E_COULD_NOT_FIND_DEVICES   -2
#define PCAP_E_COULD_NOT_OPEN_DEVICE    -3
#define PCAP_E_COULD_NOT_SEND_PACKET    -4

struct network_s {
    char interface_name[LENGTH_INTERFACE_NAME];
    logger_t logger;
    pcap_if_t **devices;
    size_t devices_length;
    pcap_t *pcap_handler;
    on_frame_received_cfg_t on_frame_received_cfg;
    DWORD thread_id;
    HANDLE thread_handle;
};

// Forward declaration of private methods
static int _load_pcap_dlls(logger_t logger);
static int _get_list_of_interfaces(logger_t logger, pcap_if_t ***devices, size_t *length, uint8_t log_interfaces);
static int _open_pcap_capture(network_t instance);
static DWORD WINAPI _pcap_loop_thread_function(LPVOID param);
static void _pcap_loop_start(network_t instance);
static void _pcap_loop_callback(uint8_t *args, const struct pcap_pkthdr *header, const uint8_t *frame);
static void _build_logger(network_t instance, network_args_t args);
static void _extract_fields(network_t instance, network_args_t args);

int network_create(network_t *instance, network_args_t args) {
    *instance = memory_alloc(sizeof(struct network_s), DESCRIPTION_INSTANCE);
    _build_logger(*instance, args);
    _extract_fields(*instance, args);

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

    if (_get_list_of_interfaces(instance->logger, &(instance->devices), &(instance->devices_length), FALSE) != PCAP_E_SUCCESSFUL) {
        logger_error(instance->logger, "Couldn't not find ");
        return NETWORK_E_COULD_NOT_INIT;
    }

    if (_open_pcap_capture(instance) != PCAP_E_SUCCESSFUL) {
        logger_error(instance->logger, "Could not open device");
        return NETWORK_E_COULD_NOT_INIT;
    }
    logger_info(instance->logger, "Device opened successfully");

    _pcap_loop_start(instance);

    return NETWORK_E_SUCCESSFUL;
}

int network_list_interfaces(network_t instance) {
    _get_list_of_interfaces(instance->logger, &(instance->devices), &(instance->devices_length), TRUE);
    return NETWORK_E_SUCCESSFUL;
}

int network_send(network_t instance, uint8_t *packet, size_t size) {

    logger_debug(instance->logger, "Sending a network packet...");
    log_bytes(instance->logger, logger_debug, packet, size);

    if (pcap_inject(instance->pcap_handler, packet, size) <= 0) {
        logger_error(instance->logger, "Failed to send bytes to wire. Details: %s", pcap_geterr(instance->pcap_handler));
        return PCAP_E_COULD_NOT_SEND_PACKET;
    }

    return NETWORK_E_SUCCESSFUL;
}

int network_destroy(network_t instance) {
    logger_info(instance->logger, "Destroying instance...");

    logger_destroy(instance->logger);
    memory_free(instance, DESCRIPTION_INSTANCE);

    pcap_close(instance->pcap_handler);

    pcap_freealldevs(*(instance->devices));
    memory_free(instance->devices, DESCRIPTION_PCAP_INTERFACES);

    CloseHandle(instance->thread_handle);

    return NETWORK_E_SUCCESSFUL;
}

// Private methods
static int _load_pcap_dlls(logger_t logger) {
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

static int _get_list_of_interfaces(logger_t logger, pcap_if_t ***devices, size_t *length, uint8_t log_interfaces) {
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int i = 0;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        logger_error(logger, "Couldn't find devices.. Details: %s", errbuf);
        return PCAP_E_COULD_NOT_FIND_DEVICES;
    }

    if (log_interfaces) logger_info(logger, "Interface name and Description: ");
    for (d = alldevs; d; d = d->next, ++i) {
        if (log_interfaces) logger_info(logger, "%s: %s", d->name, ((d->description) ? d->description : "No description"));
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

static int _open_pcap_capture(network_t instance) {
    char errbuf[PCAP_ERRBUF_SIZE];

    logger_info(instance->logger, "Using device %s", instance->interface_name);
    instance->pcap_handler = pcap_open_live(instance->interface_name, BUFSIZ, 0, 10, errbuf);
    if (instance->pcap_handler == NULL) {
        logger_error(instance->logger, "Failed to open device. Details: %s", errbuf);
        return PCAP_E_COULD_NOT_OPEN_DEVICE;
    }

    return PCAP_E_SUCCESSFUL;
}

static void _pcap_loop_callback(uint8_t *args, const struct pcap_pkthdr *header, const uint8_t *frame) {
    network_t instance = (network_t) args;

    logger_debug(instance->logger, "Received a frame");
    on_frame_received_t *callback = instance->on_frame_received_cfg.callback;
    void *callback_args = instance->on_frame_received_cfg.args;

    callback(instance, callback_args, frame, header->len);
}

static DWORD WINAPI _pcap_loop_thread_function(LPVOID param) {
    network_t instance = (network_t) param;
    logger_info(instance->logger, "Starting capture loop");
    pcap_loop(instance->pcap_handler, -1, _pcap_loop_callback, (uint8_t *) instance);
}

static void _pcap_loop_start(network_t instance) {

    instance->thread_handle = CreateThread(
            NULL,
            0,
            _pcap_loop_thread_function,
            instance,
            0,
            &(instance->thread_id)
    );
    /* returns the thread identifier */
    if (instance->thread_handle != NULL) {
        logger_info(instance->logger, "Capture loop started in a different thread...");
    }
}

static void _build_logger(network_t instance, network_args_t args) {
    logger_create(&(instance->logger), "network", CONSTANT_LOG_LEVEL);
}

static void _extract_fields(network_t instance, network_args_t args) {
    instance->devices_length = 0;
    instance->on_frame_received_cfg = args.on_frame_received_callback;

    memset(instance->interface_name, '\0', sizeof(instance->interface_name));
    strcpy(instance->interface_name, args.interface_name);
}