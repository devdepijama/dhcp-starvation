#ifndef H_DHCP_CLIENT
#define H_DHCP_CLIENT

#include <stdint.h>

#define DHCP_CLIENT_E_SUCCESSFUL 0

typedef struct dhcp_client_s* dhcp_client_t;
typedef struct {

} dhcp_client_offer_data_t;
typedef void (dhcp_client_on_offer_callback_t(dhcp_client_t, dhcp_client_offer_data_t));

typedef struct {

} dhcp_client_ack_data_t;
typedef void (dhcp_client_on_ack_callback_t(dhcp_client_t, dhcp_client_ack_data_t));

int dhcp_client_create(
    dhcp_client_t *instance,
    dhcp_client_on_offer_callback_t on_offer_callback,
    dhcp_client_on_ack_callback_t on_ack_callback
);

int dhcp_client_init(dhcp_client_t instance);

int dhcp_client_discovery(dhcp_client_t instance, const uint8_t *mac);
int dhcp_client_request(dhcp_client_t instance);

int dhcp_client_destroy(dhcp_client_t instance);

#endif