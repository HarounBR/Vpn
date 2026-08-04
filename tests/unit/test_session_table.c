#include <assert.h>
#include <stdio.h>
#include "vpn/session.h"

static void test_session_table_init(void)
{
    struct vpn_session_table table;
    vpn_session_table_init(&table);
    assert(table.session_count == 0);
}

int main(void)
{
    test_session_table_init();
    printf("test_session_table.c skeleton passed\n");
    return 0;
}
