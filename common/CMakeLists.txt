add_library (
    common
    SHARED

    log/logger.c
    memory/memory.c
    dhcp/client.c
)

target_include_directories(common PRIVATE .)