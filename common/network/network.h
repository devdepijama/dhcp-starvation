#ifndef H_NETWORK
#define H_NETWORK

#include <stdint.h>

#define NETWORK_E_SUCCESSFUL        0
#define NETWORK_E_COULD_NOT_INIT    -1

typedef struct network_s* network_t;

int network_create(network_t *instance);

int network_init(network_t instance);
int network_send(network_t instance, uint8_t *packet, size_t size);

int network_destroy(network_t instance);

#endif