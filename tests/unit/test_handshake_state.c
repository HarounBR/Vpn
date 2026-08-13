#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "vpn/handshake.h"

static void test_handshake_context_initial_state(void)
{
    struct vpn_handshake_context ctx;
    vpn_handshake_context_init(&ctx, 0);
    assert(ctx.client_state == VPN_CLIENT_HANDSHAKE_STATE_IDLE);
    assert(ctx.server_state == VPN_SERVER_HANDSHAKE_STATE_NO_SESSION);
    assert(ctx.client_nonce == 0);
    assert(ctx.server_nonce == 0);
    assert(ctx.key_exchange_context_length == 0);
    assert(ctx.handshake_timeout_ms == 10000u);
    assert(ctx.keepalive_interval_ms == 15000u);
    assert(ctx.session_idle_timeout_ms == 45000u);
}

static void test_handshake_processes_valid_envelope_transitions(void)
{
    struct vpn_handshake_context ctx;
    struct vpn_protocol_envelope envelope;

    vpn_handshake_context_init(&ctx, 7);

    envelope.magic = VPN_PROTOCOL_MAGIC;
    envelope.version = VPN_PROTOCOL_VERSION;
    envelope.type = VPN_MSG_CLIENT_HELLO;
    envelope.flags = 0;
    envelope.message_id = 1;
    envelope.session_id = 0;
    envelope.payload_length = 0;

    assert(vpn_handshake_process_envelope(&envelope, &ctx) == 0);
    assert(ctx.last_message_id == 1u);
    assert(ctx.client_state == VPN_CLIENT_HANDSHAKE_STATE_HELLO_SENT);
    assert(ctx.server_state == VPN_SERVER_HANDSHAKE_STATE_HELLO_RECEIVED);

    envelope.type = VPN_MSG_SERVER_HELLO;
    envelope.session_id = 7u;
    assert(vpn_handshake_process_envelope(&envelope, &ctx) == 0);
    assert(ctx.client_state == VPN_CLIENT_HANDSHAKE_STATE_FINISH_SENT);
    assert(ctx.server_state == VPN_SERVER_HANDSHAKE_STATE_SERVER_HELLO_SENT);
    envelope.type = VPN_MSG_CLIENT_FINISH;
    envelope.session_id = 7u;
    assert(vpn_handshake_process_envelope(&envelope, &ctx) == 0);
    assert(ctx.client_state == VPN_CLIENT_HANDSHAKE_STATE_ESTABLISHED);
    assert(ctx.server_state == VPN_SERVER_HANDSHAKE_STATE_ESTABLISHED);
}

static void test_handshake_rejects_invalid_message(void)
{
    struct vpn_handshake_context ctx;
    struct vpn_protocol_envelope envelope;

    vpn_handshake_context_init(&ctx, 9);
    memset(&envelope, 0, sizeof(envelope));
    envelope.magic = VPN_PROTOCOL_MAGIC;
    envelope.version = VPN_PROTOCOL_VERSION;
    envelope.type = 42;
    envelope.flags = 0;
    envelope.message_id = 3;
    envelope.session_id = 0;
    envelope.payload_length = 0;

    assert(vpn_handshake_process_envelope(&envelope, &ctx) == -1);
}

static void test_handshake_rejects_invalid_state_order(void)
{
    struct vpn_handshake_context ctx;
    struct vpn_protocol_envelope envelope;

    vpn_handshake_context_init(&ctx, 7);

    memset(&envelope, 0, sizeof(envelope));
    envelope.magic = VPN_PROTOCOL_MAGIC;
    envelope.version = VPN_PROTOCOL_VERSION;
    envelope.type = VPN_MSG_SERVER_FINISH;
    envelope.flags = 0;
    envelope.message_id = 5;
    envelope.session_id = 0;
    envelope.payload_length = 0;

    assert(vpn_handshake_process_envelope(&envelope, &ctx) == -1);

    envelope.type = VPN_MSG_CLIENT_HELLO;
    envelope.session_id = 9;
    assert(vpn_handshake_process_envelope(&envelope, &ctx) == -1);
}

int test_handshake_state(void)
{
    test_handshake_context_initial_state();
    test_handshake_processes_valid_envelope_transitions();
    test_handshake_rejects_invalid_message();
    test_handshake_rejects_invalid_state_order();
    printf("test_handshake_state.c passed\n");
    return 0;
}
