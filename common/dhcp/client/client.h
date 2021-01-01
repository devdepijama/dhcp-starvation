#ifndef H_DHCP_CLIENT
#define H_DHCP_CLIENT

#include <stdint.h>
#include "dhcp/client/utils/nettypes.h"
#include "settings/constants.h"

#define DHCP_CLIENT_E_SUCCESSFUL 0

typedef struct dhcp_client_s* dhcp_client_t;

// On Offer callback
typedef struct {
    ip4_t dhcp_server;
    ip4_t gateway;
    ip4_t subnet;
    ip4_t dns;
    ip4_t ip;
    uint32_t lease_period_in_seconds;
    uint32_t xid;
    uint8_t client_mac[LENGTH_MAC_ADDRESS_AS_BYTES];
} dhcp_client_offer_data_t;
typedef void (dhcp_client_on_offer_callback_t(dhcp_client_t, void*, dhcp_client_offer_data_t));
typedef struct {
    dhcp_client_on_offer_callback_t *callback;
    void *args;
} on_offer_callback_cfg_t;

// On ack callback
typedef struct {
    ip4_t ip;
    ip4_t dhcp_server;
    uint8_t dhcp_server_mac[LENGTH_MAC_ADDRESS_AS_BYTES];
    uint32_t xid;
} dhcp_client_ack_data_t;
typedef void (dhcp_client_on_ack_callback_t(dhcp_client_t, void *, dhcp_client_ack_data_t));
typedef struct {
    dhcp_client_on_ack_callback_t *callback;
    void *args;
} on_ack_callback_cfg_t;

typedef struct {
    on_offer_callback_cfg_t on_offer_callback_cfg;
    on_ack_callback_cfg_t on_ack_callback_cfg;
} dhcp_client_callbacks_cfg_t;

typedef struct {
    uint8_t mac[LENGTH_MAC_ADDRESS_AS_BYTES];
    dhcp_client_offer_data_t offer_data;
} dhcp_client_request_data_t;

typedef struct {
    uint8_t mac[LENGTH_MAC_ADDRESS_AS_BYTES];
    dhcp_client_ack_data_t ack_data;
} dhcp_client_decline_data_t;

typedef struct {
    char *interface_name;
    dhcp_client_callbacks_cfg_t callbacks;
}dhcp_client_args_t;

int dhcp_client_create(dhcp_client_t *instance, dhcp_client_args_t args);

int dhcp_client_init(dhcp_client_t instance);

int dhcp_client_discovery(dhcp_client_t instance, const uint8_t *mac, ip4_t my_ip, uint32_t xid);
int dhcp_client_request(dhcp_client_t instance, dhcp_client_request_data_t data);
int dhcp_client_decline(dhcp_client_t instance, dhcp_client_decline_data_t data);

int dhcp_client_destroy(dhcp_client_t instance);

#endif