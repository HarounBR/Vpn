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
    envelope.message_id = 2;
    assert(vpn_handshake_process_envelope(&envelope, &ctx) == 0);
    assert(ctx.client_state == VPN_CLIENT_HANDSHAKE_STATE_FINISH_SENT);
    assert(ctx.server_state == VPN_SERVER_HANDSHAKE_STATE_SERVER_HELLO_SENT);
    
    envelope.type = VPN_MSG_CLIENT_FINISH;
    envelope.session_id = 7u;
    envelope.message_id = 3;
    assert(vpn_handshake_process_envelope(&envelope, &ctx) == 0);
    /* Client stays in FINISH_SENT, server moves to ESTABLISHED */
    assert(ctx.client_state == VPN_CLIENT_HANDSHAKE_STATE_FINISH_SENT);
    assert(ctx.server_state == VPN_SERVER_HANDSHAKE_STATE_ESTABLISHED);
    
    envelope.type = VPN_MSG_SERVER_FINISH;
    envelope.session_id = 7u;
    envelope.message_id = 4;
    assert(vpn_handshake_process_envelope(&envelope, &ctx) == 0);
    /* Now client moves to ESTABLISHED */
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

/* T017: Client state path tests - IDLE -> HELLO_SENT -> FINISH_SENT -> ESTABLISHED */

static void test_client_state_idle_sends_hello(void)
{
    struct vpn_handshake_context ctx;
    struct vpn_protocol_envelope envelope;
    
    vpn_handshake_context_init(&ctx, 1);
    assert(ctx.client_state == VPN_CLIENT_HANDSHAKE_STATE_IDLE);
    
    /* Client sends CLIENT_HELLO */
    envelope.magic = VPN_PROTOCOL_MAGIC;
    envelope.version = VPN_PROTOCOL_VERSION;
    envelope.type = VPN_MSG_CLIENT_HELLO;
    envelope.flags = 0;
    envelope.message_id = 1;
    envelope.session_id = 0;  /* Initial hello has zero session */
    envelope.payload_length = 0;
    
    assert(vpn_handshake_process_envelope(&envelope, &ctx) == 0);
    assert(ctx.client_state == VPN_CLIENT_HANDSHAKE_STATE_HELLO_SENT);
}

static void test_client_state_hello_sent_receives_server_hello(void)
{
    struct vpn_handshake_context ctx;
    struct vpn_protocol_envelope envelope;
    
    vpn_handshake_context_init(&ctx, 7);
    
    /* Move to HELLO_SENT */
    envelope.magic = VPN_PROTOCOL_MAGIC;
    envelope.version = VPN_PROTOCOL_VERSION;
    envelope.type = VPN_MSG_CLIENT_HELLO;
    envelope.flags = 0;
    envelope.message_id = 1;
    envelope.session_id = 0;
    envelope.payload_length = 0;
    assert(vpn_handshake_process_envelope(&envelope, &ctx) == 0);
    assert(ctx.client_state == VPN_CLIENT_HANDSHAKE_STATE_HELLO_SENT);
    
    /* Receive SERVER_HELLO with assigned session */
    envelope.type = VPN_MSG_SERVER_HELLO;
    envelope.session_id = 7u;
    envelope.message_id = 2;
    assert(vpn_handshake_process_envelope(&envelope, &ctx) == 0);
    assert(ctx.client_state == VPN_CLIENT_HANDSHAKE_STATE_FINISH_SENT);
}

static void test_client_state_finish_sent_receives_server_finish(void)
{
    struct vpn_handshake_context ctx;
    struct vpn_protocol_envelope envelope;
    
    vpn_handshake_context_init(&ctx, 7);
    
    /* Move to HELLO_SENT then FINISH_SENT */
    envelope.magic = VPN_PROTOCOL_MAGIC;
    envelope.version = VPN_PROTOCOL_VERSION;
    envelope.type = VPN_MSG_CLIENT_HELLO;
    envelope.flags = 0;
    envelope.message_id = 1;
    envelope.session_id = 0;
    envelope.payload_length = 0;
    assert(vpn_handshake_process_envelope(&envelope, &ctx) == 0);
    
    envelope.type = VPN_MSG_SERVER_HELLO;
    envelope.session_id = 7u;
    envelope.message_id = 2;
    assert(vpn_handshake_process_envelope(&envelope, &ctx) == 0);
    assert(ctx.client_state == VPN_CLIENT_HANDSHAKE_STATE_FINISH_SENT);
    
    /* Receive CLIENT_FINISH - server moves to ESTABLISHED, client stays in FINISH_SENT */
    envelope.type = VPN_MSG_CLIENT_FINISH;
    envelope.session_id = 7u;
    envelope.message_id = 3;
    assert(vpn_handshake_process_envelope(&envelope, &ctx) == 0);
    assert(ctx.client_state == VPN_CLIENT_HANDSHAKE_STATE_FINISH_SENT);
    
    /* Receive SERVER_FINISH to complete client establishment */
    envelope.type = VPN_MSG_SERVER_FINISH;
    envelope.session_id = 7u;
    envelope.message_id = 4;
    assert(vpn_handshake_process_envelope(&envelope, &ctx) == 0);
    assert(ctx.client_state == VPN_CLIENT_HANDSHAKE_STATE_ESTABLISHED);
}

static void test_client_rejects_out_of_order_messages(void)
{
    struct vpn_handshake_context ctx;
    struct vpn_protocol_envelope envelope;
    
    vpn_handshake_context_init(&ctx, 7);
    
    /* Try to receive SERVER_HELLO before sending CLIENT_HELLO */
    envelope.magic = VPN_PROTOCOL_MAGIC;
    envelope.version = VPN_PROTOCOL_VERSION;
    envelope.type = VPN_MSG_SERVER_HELLO;
    envelope.flags = 0;
    envelope.message_id = 1;
    envelope.session_id = 7u;
    envelope.payload_length = 0;
    
    assert(vpn_handshake_process_envelope(&envelope, &ctx) == -1);
    assert(ctx.client_state == VPN_CLIENT_HANDSHAKE_STATE_IDLE);
}

/* T018: Server state path tests - NO_SESSION -> HELLO_RECEIVED -> SERVER_HELLO_SENT -> ESTABLISHED */

static void test_server_state_no_session_receives_hello(void)
{
    struct vpn_handshake_context ctx;
    struct vpn_protocol_envelope envelope;
    
    vpn_handshake_context_init(&ctx, 0);  /* Initial no session */
    assert(ctx.server_state == VPN_SERVER_HANDSHAKE_STATE_NO_SESSION);
    
    /* Server receives CLIENT_HELLO */
    envelope.magic = VPN_PROTOCOL_MAGIC;
    envelope.version = VPN_PROTOCOL_VERSION;
    envelope.type = VPN_MSG_CLIENT_HELLO;
    envelope.flags = 0;
    envelope.message_id = 1;
    envelope.session_id = 0;
    envelope.payload_length = 0;
    
    assert(vpn_handshake_process_envelope(&envelope, &ctx) == 0);
    assert(ctx.server_state == VPN_SERVER_HANDSHAKE_STATE_HELLO_RECEIVED);
}

static void test_server_state_hello_received_sends_server_hello(void)
{
    struct vpn_handshake_context ctx;
    struct vpn_protocol_envelope envelope;
    
    vpn_handshake_context_init(&ctx, 42);  /* Server will assign this session */
    
    /* Server receives CLIENT_HELLO */
    envelope.magic = VPN_PROTOCOL_MAGIC;
    envelope.version = VPN_PROTOCOL_VERSION;
    envelope.type = VPN_MSG_CLIENT_HELLO;
    envelope.flags = 0;
    envelope.message_id = 1;
    envelope.session_id = 0;
    envelope.payload_length = 0;
    
    assert(vpn_handshake_process_envelope(&envelope, &ctx) == 0);
    assert(ctx.server_state == VPN_SERVER_HANDSHAKE_STATE_HELLO_RECEIVED);
    
    /* Server sends SERVER_HELLO with assigned session */
    envelope.type = VPN_MSG_SERVER_HELLO;
    envelope.session_id = 42u;
    envelope.message_id = 2;
    assert(vpn_handshake_process_envelope(&envelope, &ctx) == 0);
    assert(ctx.server_state == VPN_SERVER_HANDSHAKE_STATE_SERVER_HELLO_SENT);
}

static void test_server_state_server_hello_sent_receives_client_finish(void)
{
    struct vpn_handshake_context ctx;
    struct vpn_protocol_envelope envelope;
    
    vpn_handshake_context_init(&ctx, 42);
    
    /* Move to SERVER_HELLO_SENT */
    envelope.magic = VPN_PROTOCOL_MAGIC;
    envelope.version = VPN_PROTOCOL_VERSION;
    envelope.type = VPN_MSG_CLIENT_HELLO;
    envelope.flags = 0;
    envelope.message_id = 1;
    envelope.session_id = 0;
    envelope.payload_length = 0;
    assert(vpn_handshake_process_envelope(&envelope, &ctx) == 0);
    
    envelope.type = VPN_MSG_SERVER_HELLO;
    envelope.session_id = 42u;
    envelope.message_id = 2;
    assert(vpn_handshake_process_envelope(&envelope, &ctx) == 0);
    assert(ctx.server_state == VPN_SERVER_HANDSHAKE_STATE_SERVER_HELLO_SENT);
    
    /* Receive CLIENT_FINISH to complete server establishment */
    envelope.type = VPN_MSG_CLIENT_FINISH;
    envelope.session_id = 42u;
    envelope.message_id = 3;
    assert(vpn_handshake_process_envelope(&envelope, &ctx) == 0);
    assert(ctx.server_state == VPN_SERVER_HANDSHAKE_STATE_ESTABLISHED);
}

static void test_server_rejects_invalid_session_id(void)
{
    struct vpn_handshake_context ctx;
    struct vpn_protocol_envelope envelope;
    
    vpn_handshake_context_init(&ctx, 42);
    
    /* Server receives CLIENT_HELLO */
    envelope.magic = VPN_PROTOCOL_MAGIC;
    envelope.version = VPN_PROTOCOL_VERSION;
    envelope.type = VPN_MSG_CLIENT_HELLO;
    envelope.flags = 0;
    envelope.message_id = 1;
    envelope.session_id = 0;
    envelope.payload_length = 0;
    assert(vpn_handshake_process_envelope(&envelope, &ctx) == 0);
    
    /* Send SERVER_HELLO with correct session */
    envelope.type = VPN_MSG_SERVER_HELLO;
    envelope.session_id = 42u;
    envelope.message_id = 2;
    assert(vpn_handshake_process_envelope(&envelope, &ctx) == 0);
    
    /* Try to receive CLIENT_FINISH for wrong session */
    envelope.type = VPN_MSG_CLIENT_FINISH;
    envelope.session_id = 99u;  /* Wrong session ID */
    envelope.message_id = 3;
    assert(vpn_handshake_process_envelope(&envelope, &ctx) == -1);
}

int test_handshake_state(void)
{
    test_handshake_context_initial_state();
    test_handshake_processes_valid_envelope_transitions();
    test_handshake_rejects_invalid_message();
    test_handshake_rejects_invalid_state_order();
    test_client_state_idle_sends_hello();
    test_client_state_hello_sent_receives_server_hello();
    test_client_state_finish_sent_receives_server_finish();
    test_client_rejects_out_of_order_messages();
    test_server_state_no_session_receives_hello();
    test_server_state_hello_received_sends_server_hello();
    test_server_state_server_hello_sent_receives_client_finish();
    test_server_rejects_invalid_session_id();
    printf("test_handshake_state.c passed\n");
    return 0;
}
