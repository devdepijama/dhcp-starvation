#ifndef H_ATTACK
#define H_ATTACK

#include "network/network-types.h"

#define ATTACK_E_SUCCESSFUL 0

typedef struct attack_s* attack_t;

typedef struct {
    ip4_t malicious_dns;
    uint8_t mac[6];
    char interface_name[128];
} attack_args_t;

int attack_create(attack_t *instance, attack_args_t args);

int attack_run(attack_t instance);

int attack_destroy(attack_t instance);

#endif