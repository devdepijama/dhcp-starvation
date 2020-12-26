add_library (
    common
    SHARED

    log/logger.c
    memory/memory.c
    dhcp/client/client.c
    dhcp/client/utils/packet-builder.c
    utils/utils.c

    network/network-win.c
)

target_include_directories(common PRIVATE .)