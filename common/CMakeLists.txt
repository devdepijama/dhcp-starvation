add_library (
    common
    SHARED

    log/logger.c
    memory/memory.c
    dhcp/client/client.c
    dhcp/client/utils/packet-builder.c
    dhcp/client/utils/packet-unpacker.c
    utils/utils.c

    network/network-win.c
)

target_include_directories(common PUBLIC
    .
    ../dependencies/npcap-sdk-1.06/Include
)

target_link_directories(common PUBLIC
    ../dependencies/npcap-sdk-1.06/Lib/x64
)

target_link_libraries(common PUBLIC wpcap ws2_32)