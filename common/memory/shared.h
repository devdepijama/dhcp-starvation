#ifndef H_SHAREDMEMORY
#define H_SHAREDMEMORY

#include "log/logger.h"

#define SHAREDMEMORY_E_SUCCESS                0
#define SHAREDMEMORY_E_COULD_NOT_CREATE       1
#define SHAREDMEMORY_E_BUFFER_NOT_BIG_ENOUGH  2

typedef struct shared_memory_s* shared_memory_t;

int shared_memory_instantiate(shared_memory_t *instance);

int shared_memory_create(shared_memory_t instance);
int shared_memory_write(shared_memory_t instance, void *content, unsigned int size);

int shared_memory_read(shared_memory_t instance, char *read_buffer, unsigned int *read_bytes);

int shared_memory_free(shared_memory_t instance);

#endif