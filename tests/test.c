#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "log/logger.h"
#include "utils/utils.h"
#include "dhcp/client/utils/packet-unpacker.h"
#include "assertions/assertions.h"

void test_log_of_hex_bytes() {
    logger_t logger;
    logger_create(&logger, "hex-logger", LOGGER_LEVEL_INFO);
    char *sampleMessage = "hi my name is hugo and this is just a vulgar string";

    log_bytes(logger, logger_info, (uint8_t *) sampleMessage, strlen(sampleMessage));
}

void test_read_of_dhcp_options() {
    dhcp_t *mocked_dhcp_packet;
    uint8_t value[256];

    uint8_t tlv[] = {
            0x35, 0x01, 0x02, 0x36, 0x04, 0xc0, 0xa8, 0x01, 0x01, 0x33, 0x04, 0x00, 0x00, 0x00, 0x3c, 0x01,
            0x04, 0xff, 0xff, 0xff, 0x00, 0x03, 0x04, 0xc0, 0xa8, 0x01, 0x01, 0x06, 0x04, 0xc0, 0xa8, 0x01,
            0x01, 0x0f, 0x03, 0x6c, 0x61, 0x6e, 0xff
    };

    mocked_dhcp_packet = malloc(sizeof(dhcp_t) + sizeof(tlv) - 1);
    memcpy(&(mocked_dhcp_packet->bp_options), tlv, sizeof(tlv));

    assert_true(read_dhcp_option(mocked_dhcp_packet, MESSAGE_TYPE_DNS, (uint8_t *) &value, sizeof(value)), "Did not find DNS");
    char dns[32];
    ip_to_string(dns, (ip4_t *) value);

    assert_true(!strcmp(dns, "192.168.1.1"), "DNS is different than expected!");
}

void test_random() {
    printf("Random values: \n");
    for(int i = 0; i < 10; i++) {
        printf("%d \n", random());
    }
}

int main() {

    test_log_of_hex_bytes();
    test_read_of_dhcp_options();
    test_random();
    return 0;
}
