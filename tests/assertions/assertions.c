#include "assertions/assertions.h"

#include <stdio.h>
#include <stdlib.h>

static void wrapped_exit(char *message) {
    printf(message);
    exit(-1);
}

void assert_equals(int expected, int actual, char *message) {
    if (expected != actual) wrapped_exit(message);
}

void assert_true(int value, char *message) {
    if (!value) wrapped_exit(message);
}

void assert_false(int value, char *message) {
    if (value) wrapped_exit(message);
}