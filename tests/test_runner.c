#include <stdio.h>
#include "test_helpers.h"

int tests_passed = 0;
int tests_failed = 0;

int test_protocol_parse(void);
int test_handshake_state(void);
int test_session_table(void);
int test_handshake_flow(void);

int main(void)
{
    RUN_TEST(test_protocol_parse);
    RUN_TEST(test_handshake_state);
    RUN_TEST(test_session_table);
    RUN_TEST(test_handshake_flow);

    TEST_SUMMARY();
    return tests_failed;
}
