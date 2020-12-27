#ifndef H_NETWORK
#define H_NETWORK

#include <stdint.h>

#define NETWORK_E_SUCCESSFUL        0
#define NETWORK_E_COULD_NOT_INIT    -1

typedef struct network_s* network_t;
typedef void (on_frame_received_t(network_t instance, const uint8_t *args, const uint8_t *frame, size_t length));

typedef struct {
    on_frame_received_t *callback;
    void *args;
} on_frame_received_cfg_t;

int network_create(network_t *instance, on_frame_received_cfg_t on_frame_received_cfg);

int network_init(network_t instance);
int network_send(network_t instance, uint8_t *packet, size_t size);

int network_destroy(network_t instance);

#endif