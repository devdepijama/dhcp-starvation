#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "log/logger.h"
#include "utils/utils.h"

void test_log_of_hex_bytes() {
    logger_t logger;
    logger_create(&logger, "hex-logger", LOGGER_LEVEL_INFO);
    char *sampleMessage = "hi my name is hugo and this is just a vulgar string";

    log_bytes(logger, logger_info, (uint8_t *) sampleMessage, strlen(sampleMessage));
}

int main() {

    test_log_of_hex_bytes();
    return 0;
}
