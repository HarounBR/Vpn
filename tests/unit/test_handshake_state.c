#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "vpn/handshake.h"
#include "vpn/session.h"

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

/* T040: Retry schedule tests - 0s, 1s, 3s, 7s */
static void test_handshake_retry_schedule(void)
{
    struct vpn_handshake_context ctx;
    struct vpn_session_table table;
    vpn_session_table_init(&table);
    vpn_handshake_context_init(&ctx, 1);

    /* Verify default retry policy values */
    assert(ctx.retry_policy.initial_retry_ms == 1000u);
    assert(ctx.retry_policy.max_retry_ms == 4000u);
    assert(ctx.retry_policy.max_attempts == 4u);
    assert(ctx.attempt_count == 0u);

    /* Test should_retry at each stage */
    assert(vpn_handshake_should_retry(&ctx) == 1);  /* attempt 1 (initial) */

    ctx.attempt_count = 1;
    assert(vpn_handshake_should_retry(&ctx) == 1);  /* attempt 2 (1s retry) */

    ctx.attempt_count = 2;
    assert(vpn_handshake_should_retry(&ctx) == 1);  /* attempt 3 (3s cumulative) */

    ctx.attempt_count = 3;
    assert(vpn_handshake_should_retry(&ctx) == 1);  /* attempt 4 (7s cumulative) */

    ctx.attempt_count = 4;
    assert(vpn_handshake_should_retry(&ctx) == 0);  /* exhausted after 4 attempts */

    /* Test advance_retry with simulated time - use fresh context */
    struct vpn_handshake_context ctx2;
    vpn_handshake_context_init(&ctx2, 2);
    uint64_t current_time = 1000u;
    assert(vpn_handshake_on_handshake_start(&ctx2, current_time) == 0);
    assert(ctx2.attempt_count == 1);
    assert(ctx2.handshake_started_at_ms == 1000u);
    assert(ctx2.handshake_deadline_ms == 1000u + 10000u); /* 10s handshake timeout */

    /* First retry at 1s */
    assert(vpn_handshake_advance_retry(&ctx2, 2000u, &table) == 0);
    assert(ctx2.attempt_count == 2);
    assert(ctx2.next_retry_at_ms == 4000u); /* retry 2 at start + 3s */

    /* Second retry at 3s (cumulative) */
    assert(vpn_handshake_advance_retry(&ctx2, 4000u, &table) == 0);
    assert(ctx2.attempt_count == 3);
    assert(ctx2.next_retry_at_ms == 8000u); /* retry 3 at start + 7s */

    /* Third retry at 7s (cumulative) */
    assert(vpn_handshake_advance_retry(&ctx2, 8000u, &table) == 0);
    assert(ctx2.attempt_count == 4);
    assert(ctx2.next_retry_at_ms == 0u); /* no retry after the fourth transmission */

    /* Fourth attempt - exhausted */
    assert(vpn_handshake_advance_retry(&ctx2, 15000u, &table) == -1);
    assert(ctx2.client_state == VPN_CLIENT_HANDSHAKE_STATE_FAILED);
    assert(ctx2.server_state == VPN_SERVER_HANDSHAKE_STATE_FAILED);
}

/* T041: Incomplete handshake expiration after 10 seconds */
static void test_handshake_incomplete_expiration(void)
{
    struct vpn_handshake_context ctx;
    struct vpn_session_table table;
    struct vpn_session *session;
    uint64_t session_id;
    const uint32_t virtual_ip = 0x0A000030u;
    const uint32_t peer_address = 0xC0A80001u;
    vpn_session_table_init(&table);
    assert(vpn_session_table_create(&table, &session_id, (const uint8_t *)"timeout", 7u, 0u) == 0);
    assert(vpn_session_table_assign_virtual_ip(&table, session_id, virtual_ip) == 0);
    assert(vpn_session_table_capture_client_hello_peer(&table, session_id, peer_address, 1194u) == 0);
    vpn_handshake_context_init(&ctx, session_id);

    /* Verify default handshake timeout is 10 seconds */
    assert(ctx.handshake_timeout_ms == 10000u);
    assert(ctx.handshake_deadline_ms == 0u);

    /* Start handshake */
    uint64_t start_time = 1000u;
    assert(vpn_handshake_on_handshake_start(&ctx, start_time) == 0);
    assert(ctx.handshake_started_at_ms == 1000u);
    assert(ctx.handshake_deadline_ms == 11000u); /* start + 10s */

    /* Before timeout - should not be expired */
    assert(vpn_handshake_check_timeout(&ctx, 10000u, &table) == 0);
    assert(ctx.client_state != VPN_CLIENT_HANDSHAKE_STATE_FAILED);
    assert(vpn_session_table_find_by_id(&table, session_id) != NULL);

    /* At timeout (10s from start = 11000u epoch) - hard deadline exceeded, should fail immediately
     * The hard 10s deadline wins over retry scheduling. At 11000u (10s from start),
     * the hard deadline is reached and handshake fails immediately. */
    assert(vpn_handshake_check_timeout(&ctx, 11000u, &table) == -1);
    assert(ctx.client_state == VPN_CLIENT_HANDSHAKE_STATE_FAILED);
    assert(ctx.server_state == VPN_SERVER_HANDSHAKE_STATE_FAILED);

    session = vpn_session_table_find_by_id(&table, ctx.session_id);
    assert(session == NULL);
    assert(vpn_session_table_find_by_virtual_ip(&table, virtual_ip) == NULL);

    assert(vpn_session_table_create(&table, &session_id, (const uint8_t *)"replacement", 11u, 0u) == 0);
    assert(vpn_session_table_assign_virtual_ip(&table, session_id, virtual_ip) == 0);
}

/* T043: Duplicate, stale, and out-of-order control message handling */
static void test_handshake_duplicate_message_handling(void)
{
    struct vpn_handshake_context ctx;
    struct vpn_protocol_envelope envelope;

    vpn_handshake_context_init(&ctx, 1);

    envelope.magic = VPN_PROTOCOL_MAGIC;
    envelope.version = VPN_PROTOCOL_VERSION;
    envelope.flags = 0;
    envelope.payload_length = 0;

    /* First CLIENT_HELLO - should succeed */
    envelope.type = VPN_MSG_CLIENT_HELLO;
    envelope.message_id = 1;
    envelope.session_id = 0;
    assert(vpn_handshake_process_envelope(&envelope, &ctx) == 0);
    assert(ctx.client_state == VPN_CLIENT_HANDSHAKE_STATE_HELLO_SENT);
    assert(ctx.last_message_id == 1u);

    /* Duplicate CLIENT_HELLO with same message_id is silently ignored. */
    assert(vpn_handshake_process_envelope(&envelope, &ctx) == 0);
    assert(ctx.client_state == VPN_CLIENT_HANDSHAKE_STATE_HELLO_SENT);
}

static void test_handshake_stale_message_handling(void)
{
    struct vpn_handshake_context ctx;
    struct vpn_protocol_envelope envelope;

    vpn_handshake_context_init(&ctx, 7);

    envelope.magic = VPN_PROTOCOL_MAGIC;
    envelope.version = VPN_PROTOCOL_VERSION;
    envelope.flags = 0;
    envelope.payload_length = 0;

    /* Complete normal handshake to ESTABLISHED */
    envelope.type = VPN_MSG_CLIENT_HELLO;
    envelope.message_id = 1;
    envelope.session_id = 0;
    assert(vpn_handshake_process_envelope(&envelope, &ctx) == 0);

    envelope.type = VPN_MSG_SERVER_HELLO;
    envelope.session_id = 7u;
    envelope.message_id = 2;
    assert(vpn_handshake_process_envelope(&envelope, &ctx) == 0);

    envelope.type = VPN_MSG_CLIENT_FINISH;
    envelope.session_id = 7u;
    envelope.message_id = 3;
    assert(vpn_handshake_process_envelope(&envelope, &ctx) == 0);

    envelope.type = VPN_MSG_SERVER_FINISH;
    envelope.session_id = 7u;
    envelope.message_id = 4;
    assert(vpn_handshake_process_envelope(&envelope, &ctx) == 0);

    assert(ctx.client_state == VPN_CLIENT_HANDSHAKE_STATE_ESTABLISHED);
    assert(ctx.server_state == VPN_SERVER_HANDSHAKE_STATE_ESTABLISHED);

    /* Now try to replay CLIENT_HELLO - stale messages are silently ignored. */
    envelope.type = VPN_MSG_CLIENT_HELLO;
    envelope.session_id = 0;
    envelope.message_id = 5;
    assert(vpn_handshake_process_envelope(&envelope, &ctx) == 0);
    assert(ctx.client_state == VPN_CLIENT_HANDSHAKE_STATE_ESTABLISHED);
}

static void test_handshake_out_of_order_message_handling(void)
{
    struct vpn_handshake_context ctx;
    struct vpn_protocol_envelope envelope;

    vpn_handshake_context_init(&ctx, 1);

    envelope.magic = VPN_PROTOCOL_MAGIC;
    envelope.version = VPN_PROTOCOL_VERSION;
    envelope.flags = 0;
    envelope.payload_length = 0;

    /* Try CLIENT_FINISH before SERVER_HELLO - out of order */
    envelope.type = VPN_MSG_CLIENT_FINISH;
    envelope.session_id = 1u;
    envelope.message_id = 1;
    assert(vpn_handshake_process_envelope(&envelope, &ctx) == -1);
    assert(ctx.client_state == VPN_CLIENT_HANDSHAKE_STATE_IDLE);
    assert(ctx.server_state == VPN_SERVER_HANDSHAKE_STATE_NO_SESSION);

    /* Try SERVER_FINISH before CLIENT_FINISH - out of order */
    envelope.type = VPN_MSG_SERVER_FINISH;
    envelope.session_id = 1u;
    envelope.message_id = 2;
    assert(vpn_handshake_process_envelope(&envelope, &ctx) == -1);
    assert(ctx.client_state == VPN_CLIENT_HANDSHAKE_STATE_IDLE);
    assert(ctx.server_state == VPN_SERVER_HANDSHAKE_STATE_NO_SESSION);

    /* Valid CLIENT_HELLO then SERVER_HELLO then try SERVER_HELLO again */
    envelope.type = VPN_MSG_CLIENT_HELLO;
    envelope.session_id = 0;
    envelope.message_id = 1;
    assert(vpn_handshake_process_envelope(&envelope, &ctx) == 0);

    envelope.type = VPN_MSG_SERVER_HELLO;
    envelope.session_id = 1u;
    envelope.message_id = 2;
    assert(vpn_handshake_process_envelope(&envelope, &ctx) == 0);

    /* Stale SERVER_HELLO should be silently ignored. */
    envelope.message_id = 3;
    assert(vpn_handshake_process_envelope(&envelope, &ctx) == 0);
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
    /* T040: Retry schedule tests */
    test_handshake_retry_schedule();
    /* T041: Handshake timeout tests */
    test_handshake_incomplete_expiration();
    /* T043: Duplicate, stale, out-of-order message tests */
    test_handshake_duplicate_message_handling();
    test_handshake_stale_message_handling();
    test_handshake_out_of_order_message_handling();
    printf("test_handshake_state.c passed\n");
    return 0;
}
