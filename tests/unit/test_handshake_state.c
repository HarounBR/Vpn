#include <assert.h>
#include <stdio.h>
#include "vpn/handshake.h"

static void test_handshake_context_initial_state(void)
{
    struct vpn_handshake_context ctx;
    vpn_handshake_context_init(&ctx, 0);
    assert(ctx.client_state == VPN_CLIENT_HANDSHAKE_STATE_IDLE);
    assert(ctx.server_state == VPN_SERVER_HANDSHAKE_STATE_NO_SESSION);
}

int main(void)
{
    test_handshake_context_initial_state();
    printf("test_handshake_state.c skeleton passed\n");
    return 0;
}
