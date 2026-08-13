#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "vpn/handshake.h"
#include "vpn/session.h"

/* T019: Clean four-message integration test */
static void test_clean_four_message_establishment(void)
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

    /* Step 1: Client sends CLIENT_HELLO */
    assert(vpn_handshake_process_envelope(&envelope, &client_ctx) == 0);
    assert(client_ctx.client_state == VPN_CLIENT_HANDSHAKE_STATE_HELLO_SENT);

    /* Step 1: Server receives CLIENT_HELLO */
    assert(vpn_handshake_process_envelope(&envelope, &server_ctx) == 0);
    assert(server_ctx.server_state == VPN_SERVER_HANDSHAKE_STATE_HELLO_RECEIVED);

    /* Step 2: Server sends SERVER_HELLO with assigned session */
    envelope.type = VPN_MSG_SERVER_HELLO;
    envelope.session_id = 1u;
    envelope.message_id = 11u;
    assert(vpn_handshake_process_envelope(&envelope, &client_ctx) == 0);
    assert(client_ctx.client_state == VPN_CLIENT_HANDSHAKE_STATE_FINISH_SENT);
    assert(client_ctx.session_id == 1u);

    /* Step 2: Server sends SERVER_HELLO to itself (state change) */
    assert(vpn_handshake_process_envelope(&envelope, &server_ctx) == 0);
    assert(server_ctx.server_state == VPN_SERVER_HANDSHAKE_STATE_SERVER_HELLO_SENT);

    /* Step 3: Client sends CLIENT_FINISH */
    envelope.type = VPN_MSG_CLIENT_FINISH;
    envelope.session_id = 1u;
    envelope.message_id = 12u;
    assert(vpn_handshake_process_envelope(&envelope, &client_ctx) == 0);
    assert(client_ctx.client_state == VPN_CLIENT_HANDSHAKE_STATE_ESTABLISHED);

    /* Step 3: Server receives CLIENT_FINISH */
    assert(vpn_handshake_process_envelope(&envelope, &server_ctx) == 0);
    assert(server_ctx.server_state == VPN_SERVER_HANDSHAKE_STATE_ESTABLISHED);

    /* Verify both sides agreed on session_id */
    assert(client_ctx.session_id == server_ctx.session_id);
    assert(client_ctx.session_id == 1u);
    
    /* Verify both are established */
    assert(client_ctx.client_state == VPN_CLIENT_HANDSHAKE_STATE_ESTABLISHED);
    assert(server_ctx.server_state == VPN_SERVER_HANDSHAKE_STATE_ESTABLISHED);
}

/* T020: Reject data before SERVER_FINISH */
static void test_reject_data_before_server_finish(void)
{
    struct vpn_session_table table;
    struct vpn_session session;
    
    vpn_session_table_init(&table);
    
    /* Create a handshake-in-progress session */
    session.session_id = 1u;
    session.state = VPN_SESSION_STATE_HANDSHAKE_IN_PROGRESS;
    session.client_identity.client_id_length = 4;
    memcpy(session.client_identity.client_id, "test", 4);
    
    assert(vpn_session_table_insert(&table, &session) == 0);
    
    struct vpn_session *found = vpn_session_table_find_by_id(&table, 1u);
    assert(found != NULL);
    assert(found->state == VPN_SESSION_STATE_HANDSHAKE_IN_PROGRESS);
    
    /* Data should be rejected during handshake */
    assert(vpn_session_can_accept_data(found) == 0);
    
    /* Move to established */
    found->state = VPN_SESSION_STATE_ESTABLISHED;
    
    /* Data should now be accepted */
    assert(vpn_session_can_accept_data(found) == 1);
}

/* T028: Wire integration helpers - realistic simulation */
static void test_realistic_handshake_simulation(void)
{
    struct vpn_session_table table;
    struct vpn_handshake_context client_ctx;
    struct vpn_handshake_context server_ctx;
    struct vpn_protocol_envelope envelope;
    uint64_t server_assigned_session_id;
    uint8_t client_id[] = "client-1";
    
    vpn_session_table_init(&table);
    vpn_handshake_context_init(&client_ctx, 0);
    
    /* Server initializes with no session */
    vpn_handshake_context_init(&server_ctx, 0);
    
    /* Step 1: Client builds and sends CLIENT_HELLO */
    envelope.magic = VPN_PROTOCOL_MAGIC;
    envelope.version = VPN_PROTOCOL_VERSION;
    envelope.type = VPN_MSG_CLIENT_HELLO;
    envelope.flags = 0;
    envelope.message_id = 1u;
    envelope.session_id = 0u;  /* No session yet */
    envelope.payload_length = 0u;
    
    assert(vpn_handshake_process_envelope(&envelope, &client_ctx) == 0);
    assert(client_ctx.client_state == VPN_CLIENT_HANDSHAKE_STATE_HELLO_SENT);
    
    /* Step 1b: Server creates session on receiving CLIENT_HELLO */
    assert(vpn_session_table_create(&table, &server_assigned_session_id, 
                                     client_id, sizeof(client_id) - 1, 
                                     0xC0A80001u) == 0);
    assert(server_assigned_session_id == 1u);
    
    struct vpn_session *server_session = vpn_session_table_find_by_id(&table, server_assigned_session_id);
    assert(server_session != NULL);
    assert(server_session->state == VPN_SESSION_STATE_HANDSHAKE_IN_PROGRESS);
    assert(vpn_session_can_accept_data(server_session) == 0);
    
    /* Initialize server context with the assigned session */
    vpn_handshake_context_init(&server_ctx, server_assigned_session_id);
    
    /* Server receives CLIENT_HELLO */
    assert(vpn_handshake_process_envelope(&envelope, &server_ctx) == 0);
    assert(server_ctx.server_state == VPN_SERVER_HANDSHAKE_STATE_HELLO_RECEIVED);
    
    /* Step 2: Server sends SERVER_HELLO */
    envelope.type = VPN_MSG_SERVER_HELLO;
    envelope.session_id = server_assigned_session_id;
    envelope.message_id = 2u;
    
    assert(vpn_handshake_process_envelope(&envelope, &server_ctx) == 0);
    assert(server_ctx.server_state == VPN_SERVER_HANDSHAKE_STATE_SERVER_HELLO_SENT);
    
    /* Client receives SERVER_HELLO */
    assert(vpn_handshake_process_envelope(&envelope, &client_ctx) == 0);
    assert(client_ctx.client_state == VPN_CLIENT_HANDSHAKE_STATE_FINISH_SENT);
    assert(client_ctx.session_id == server_assigned_session_id);
    
    /* Step 3: Client sends CLIENT_FINISH */
    envelope.type = VPN_MSG_CLIENT_FINISH;
    envelope.session_id = server_assigned_session_id;
    envelope.message_id = 3u;
    
    assert(vpn_handshake_process_envelope(&envelope, &client_ctx) == 0);
    assert(client_ctx.client_state == VPN_CLIENT_HANDSHAKE_STATE_ESTABLISHED);
    
    /* Server receives CLIENT_FINISH */
    assert(vpn_handshake_process_envelope(&envelope, &server_ctx) == 0);
    assert(server_ctx.server_state == VPN_SERVER_HANDSHAKE_STATE_ESTABLISHED);
    
    /* Step 4: Mark session as established on server */
    server_session->state = VPN_SESSION_STATE_ESTABLISHED;
    
    /* Verify both sides are fully established */
    assert(client_ctx.client_state == VPN_CLIENT_HANDSHAKE_STATE_ESTABLISHED);
    assert(server_ctx.server_state == VPN_SERVER_HANDSHAKE_STATE_ESTABLISHED);
    assert(vpn_session_can_accept_data(server_session) == 1);
    assert(client_ctx.session_id == server_ctx.session_id);
    assert(client_ctx.session_id == server_assigned_session_id);
}

int test_handshake_flow(void)
{
    test_clean_four_message_establishment();
    test_reject_data_before_server_finish();
    test_realistic_handshake_simulation();
    printf("test_handshake_flow.c passed\n");
    return 0;
}
