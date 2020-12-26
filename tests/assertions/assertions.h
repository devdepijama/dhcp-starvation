#ifndef H_ASSERTIONS
#define H_ASSERTIONS

void assert_equals(int expected, int actual, char *message);
void assert_true(int value, char *message);
void assert_false(int value, char *message);
#endif