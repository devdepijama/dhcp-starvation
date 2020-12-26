#include "memory/shared.h"
#include "memory/memory.h"
#include "settings/constants.h"

#include <string.h>
#include <windows.h>

#define SHARED_MEMORY_NAME        "MySharedMemory"
#define SHARED_MEMORY_BUFFER_SIZE 256
#define SHARED_MEMORY_SIZE        sizeof(shared_memory_content_t)

#define INSTANCE_CREATION_REASON  "shared memory instance"

// Shared memory Layout
typedef struct {
    unsigned int writer_index;
    unsigned int reader_index;
    char buffer[SHARED_MEMORY_BUFFER_SIZE];
}shared_memory_content_t;

// Structure that hold relevant information (instances)
struct shared_memory_s {
    logger_t logger;
    HANDLE handle_shared_memory;
    shared_memory_content_t *shared_content;
};

// Static logger to be shared by all instances
static logger_t logger_shared_memory = NULL;

// Forward declaration of private methods
static unsigned int read_shared_memory(shared_memory_content_t *content, char *buffer);
static logger_t get_or_instantiate_logger();

int shared_memory_instantiate(shared_memory_t *instance) {
    *instance = memory_alloc(sizeof(struct shared_memory_s), INSTANCE_CREATION_REASON);
    (*instance)->logger = get_or_instantiate_logger();

    return SHAREDMEMORY_E_SUCCESS;
}

int shared_memory_create(shared_memory_t instance) {
    instance->handle_shared_memory = CreateFileMapping(
            INVALID_HANDLE_VALUE,               // use paging file
            NULL,                               // default security
            PAGE_READWRITE,                     // read/write access
            0,                                  // maximum object size (high-order DWORD)
            sizeof(shared_memory_content_t),    // maximum object size (low-order DWORD)
            SHARED_MEMORY_NAME                  // name of mapping object
    );

    if (NULL == instance->handle_shared_memory) {
        logger_error(instance->logger, "Could not create file mapping object (%lX).\n", GetLastError());
        return SHAREDMEMORY_E_COULD_NOT_CREATE;
    }

    instance->shared_content = MapViewOfFile(
        instance->handle_shared_memory,  // handle to map object
        FILE_MAP_ALL_ACCESS,   // read/write permission
        0,
        0,
        sizeof(shared_memory_content_t)
    );

    if (NULL == instance->shared_content) {
        logger_error(instance->logger,"Could not map view of file (%lX).\n", GetLastError());
        CloseHandle(instance->handle_shared_memory);
        return SHAREDMEMORY_E_COULD_NOT_CREATE;
    }

    return SHAREDMEMORY_E_SUCCESS;
}

int shared_memory_write(shared_memory_t instance, void *content, unsigned int size) {
    unsigned int writer = instance->shared_content->writer_index;
    unsigned int new_writer_index = writer + size;
    unsigned int free_slots;

    if (size > SHARED_MEMORY_BUFFER_SIZE) return SHAREDMEMORY_E_BUFFER_NOT_BIG_ENOUGH;

    // To write stuff, we don't need to roll the buffer
    if (new_writer_index < SHARED_MEMORY_BUFFER_SIZE) {
        memcpy(instance->shared_content->buffer + writer, content, size);
        instance->shared_content->writer_index = new_writer_index;
    } else {
        free_slots = SHARED_MEMORY_BUFFER_SIZE - writer;

        // Write first portion (to fill the buffer til the end)
        memcpy(instance->shared_content->buffer + writer, content, free_slots);

        // Write second portion (start from beginning)
        memcpy(instance->shared_content->buffer, content + free_slots, size - free_slots);
        instance->shared_content->writer_index = size - free_slots;
    }

    return SHAREDMEMORY_E_SUCCESS;
}

int shared_memory_read(shared_memory_t instance, char *read_buffer, unsigned int *read_bytes) {
    *read_bytes = read_shared_memory(instance->shared_content, read_buffer);
    if (*read_bytes > 0) {
        read_buffer[*read_bytes] = '\0';
    }

    return SHAREDMEMORY_E_SUCCESS;
}

int shared_memory_free(shared_memory_t instance) {
    UnmapViewOfFile(instance->shared_content);
    CloseHandle(instance->handle_shared_memory);
    free(instance);
    return SHAREDMEMORY_E_SUCCESS;
}

// Private methods
static unsigned int read_shared_memory(shared_memory_content_t *content, char *buffer) {
    unsigned int reader = content->reader_index;
    unsigned int writer = content->writer_index;
    unsigned int remaining, bytes_to_read;

    // Nothing new
    if (reader == writer) return 0;

    // Writer is in the front of reader
    if (writer > reader) {
        bytes_to_read = writer - reader;
        memcpy(buffer, content->buffer + reader, bytes_to_read);
        content->reader_index = writer;
        return bytes_to_read;
    }

    // Writer is behind
    remaining = SHARED_MEMORY_BUFFER_SIZE - reader;
    memcpy(buffer, content->buffer + reader, remaining);
    memcpy(buffer + remaining, content->buffer, writer);
    content->reader_index = writer;

    return (remaining + writer);
}

static logger_t get_or_instantiate_logger() {
    if (NULL == logger_shared_memory) {
        logger_create(&logger_shared_memory, "shared-memory", CONSTANT_LOG_LEVEL);
    }

    return logger_shared_memory;
}