#include <assert.h>
#include <stdio.h>
#include "vpn/handshake.h"

int test_handshake_flow(void)
{
    struct vpn_handshake_context client_ctx;
    struct vpn_handshake_context server_ctx;
    struct vpn_protocol_envelope envelope;

    vpn_handshake_context_init(&client_ctx, 1u);
    vpn_handshake_context_init(&server_ctx, 1u);

    envelope.magic = VPN_PROTOCOL_MAGIC;
    envelope.version = VPN_PROTOCOL_VERSION;
    envelope.type = VPN_MSG_CLIENT_HELLO;
    envelope.flags = 0;
    envelope.message_id = 10u;
    envelope.session_id = 0u;
    envelope.payload_length = 0u;

    assert(vpn_handshake_process_envelope(&envelope, &client_ctx) == 0);
    assert(client_ctx.client_state == VPN_CLIENT_HANDSHAKE_STATE_HELLO_SENT);

    assert(vpn_handshake_process_envelope(&envelope, &server_ctx) == 0);
    assert(server_ctx.server_state == VPN_SERVER_HANDSHAKE_STATE_HELLO_RECEIVED);

    envelope.type = VPN_MSG_SERVER_HELLO;
    envelope.session_id = 1u;
    assert(vpn_handshake_process_envelope(&envelope, &client_ctx) == 0);
    assert(client_ctx.client_state == VPN_CLIENT_HANDSHAKE_STATE_FINISH_SENT);

    assert(vpn_handshake_process_envelope(&envelope, &server_ctx) == 0);
    assert(server_ctx.server_state == VPN_SERVER_HANDSHAKE_STATE_SERVER_HELLO_SENT);

    envelope.type = VPN_MSG_CLIENT_FINISH;
    envelope.session_id = 1u;
    assert(vpn_handshake_process_envelope(&envelope, &client_ctx) == 0);
    assert(client_ctx.client_state == VPN_CLIENT_HANDSHAKE_STATE_ESTABLISHED);

    assert(vpn_handshake_process_envelope(&envelope, &server_ctx) == 0);
    assert(server_ctx.server_state == VPN_SERVER_HANDSHAKE_STATE_ESTABLISHED);

    printf("test_handshake_flow.c passed\n");
    return 0;
}
