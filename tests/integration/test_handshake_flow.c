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
    /* Client still in FINISH_SENT, waiting for SERVER_FINISH */
    assert(client_ctx.client_state == VPN_CLIENT_HANDSHAKE_STATE_FINISH_SENT);

    /* Step 3: Server receives CLIENT_FINISH and moves to ESTABLISHED */
    assert(vpn_handshake_process_envelope(&envelope, &server_ctx) == 0);
    assert(server_ctx.server_state == VPN_SERVER_HANDSHAKE_STATE_ESTABLISHED);

    /* Step 4: Server sends SERVER_FINISH */
    envelope.type = VPN_MSG_SERVER_FINISH;
    envelope.session_id = 1u;
    envelope.message_id = 13u;
    
    /* Server doesn't receive its own SERVER_FINISH; client receives it */
    assert(vpn_handshake_process_envelope(&envelope, &client_ctx) == 0);
    /* Now client moves to ESTABLISHED */
    assert(client_ctx.client_state == VPN_CLIENT_HANDSHAKE_STATE_ESTABLISHED);
    
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

static uint64_t establish_simulated_client(struct vpn_session_table *table,
                                          const char *client_id,
                                          uint32_t virtual_ip)
{
    struct vpn_handshake_context client_ctx;
    struct vpn_handshake_context server_ctx;
    struct vpn_protocol_envelope envelope;
    uint64_t session_id = 0u;
    struct vpn_session *server_session;

    assert(table != NULL);
    assert(client_id != NULL);

    vpn_handshake_context_init(&client_ctx, 0u);
    vpn_handshake_context_init(&server_ctx, 0u);

    envelope.magic = VPN_PROTOCOL_MAGIC;
    envelope.version = VPN_PROTOCOL_VERSION;
    envelope.type = VPN_MSG_CLIENT_HELLO;
    envelope.flags = 0u;
    envelope.message_id = 1u;
    envelope.session_id = 0u;
    envelope.payload_length = 0u;

    assert(vpn_handshake_process_envelope(&envelope, &client_ctx) == 0);
    assert(client_ctx.client_state == VPN_CLIENT_HANDSHAKE_STATE_HELLO_SENT);

    assert(vpn_session_table_create(table, &session_id,
                                   (const uint8_t *)client_id,
                                   (uint8_t)strlen(client_id),
                                   0u) == 0);
    assert(session_id != 0u);

    server_session = vpn_session_table_find_by_id(table, session_id);
    assert(server_session != NULL);
    assert(server_session->state == VPN_SESSION_STATE_HANDSHAKE_IN_PROGRESS);
    assert(server_session->assigned_virtual_ip == 0u);

    assert(vpn_handshake_reserve_virtual_ip(table, session_id, virtual_ip) == 0);
    assert(server_session->assigned_virtual_ip == virtual_ip);

    vpn_handshake_context_init(&server_ctx, session_id);
    assert(vpn_handshake_process_envelope(&envelope, &server_ctx) == 0);
    assert(server_ctx.server_state == VPN_SERVER_HANDSHAKE_STATE_HELLO_RECEIVED);

    envelope.type = VPN_MSG_SERVER_HELLO;
    envelope.session_id = session_id;
    envelope.message_id = 2u;
    assert(vpn_handshake_process_envelope(&envelope, &server_ctx) == 0);
    assert(server_ctx.server_state == VPN_SERVER_HANDSHAKE_STATE_SERVER_HELLO_SENT);
    assert(vpn_handshake_process_envelope(&envelope, &client_ctx) == 0);
    assert(client_ctx.client_state == VPN_CLIENT_HANDSHAKE_STATE_FINISH_SENT);
    assert(client_ctx.session_id == session_id);

    envelope.type = VPN_MSG_CLIENT_FINISH;
    envelope.session_id = session_id;
    envelope.message_id = 3u;
    assert(vpn_handshake_process_envelope(&envelope, &server_ctx) == 0);
    assert(server_ctx.server_state == VPN_SERVER_HANDSHAKE_STATE_ESTABLISHED);
    assert(vpn_handshake_process_envelope(&envelope, &client_ctx) == 0);
    assert(client_ctx.client_state == VPN_CLIENT_HANDSHAKE_STATE_FINISH_SENT);

    envelope.type = VPN_MSG_SERVER_FINISH;
    envelope.session_id = session_id;
    envelope.message_id = 4u;
    assert(vpn_handshake_process_envelope(&envelope, &client_ctx) == 0);
    assert(client_ctx.client_state == VPN_CLIENT_HANDSHAKE_STATE_ESTABLISHED);

    server_session->state = VPN_SESSION_STATE_ESTABLISHED;
    assert(vpn_session_can_accept_data(server_session) == 1);
    return session_id;
}

static void test_three_simultaneous_clients_virtual_ip_lookup(void)
{
    struct vpn_session_table table;
    uint64_t session_a_id;
    uint64_t session_b_id;
    uint64_t session_c_id;
    struct vpn_session *found;
    const uint32_t vip_a = 0x0A00000Au;
    const uint32_t vip_b = 0x0A00000Bu;
    const uint32_t vip_c = 0x0A00000Cu;

    vpn_session_table_init(&table);

    session_a_id = establish_simulated_client(&table, "client-a", vip_a);
    session_b_id = establish_simulated_client(&table, "client-b", vip_b);
    session_c_id = establish_simulated_client(&table, "client-c", vip_c);

    assert(session_a_id != session_b_id);
    assert(session_b_id != session_c_id);
    assert(session_a_id != session_c_id);
    assert(vpn_session_table_find_by_virtual_ip(&table, vip_a)->session_id == session_a_id);
    assert(vpn_session_table_find_by_virtual_ip(&table, vip_b)->session_id == session_b_id);
    assert(vpn_session_table_find_by_virtual_ip(&table, vip_c)->session_id == session_c_id);

    found = vpn_session_table_find_by_virtual_ip(&table, vip_b);
    assert(found != NULL);
    assert(found->session_id == session_b_id);

    found = vpn_session_table_find_by_virtual_ip(&table, 0x0A0000FFu);
    assert(found == NULL);
}

static void test_virtual_ip_conflict_rejection(void)
{
    struct vpn_session_table table;
    uint64_t session_a_id;
    uint64_t session_b_id;
    struct vpn_session *session_b;
    struct vpn_session *owner;

    vpn_session_table_init(&table);

    session_a_id = establish_simulated_client(&table, "client-a", 0x0A00000Au);
    assert(session_a_id == 1u);

    session_b_id = vpn_session_table_next_session_id(&table);
    assert(session_b_id == 2u);
    assert(vpn_session_table_create(&table, &session_b_id, (const uint8_t *)"client-b", 8u, 0u) == 0);

    session_b = vpn_session_table_find_by_id(&table, session_b_id);
    assert(session_b != NULL);
    assert(session_b->assigned_virtual_ip == 0u);
    assert(vpn_handshake_reserve_virtual_ip(&table, session_b_id, 0x0A00000Au) != 0);
    assert(session_b->assigned_virtual_ip == 0u);

    owner = vpn_session_table_find_by_virtual_ip(&table, 0x0A00000Au);
    assert(owner != NULL);
    assert(owner->session_id == session_a_id);
    assert(table.session_count == 2u);
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
    uint32_t requested_vip = 0xC0A80001u;  /* 192.168.0.1 */
    
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
                                     0u) == 0);
    assert(server_assigned_session_id == 1u);
    
    struct vpn_session *server_session = vpn_session_table_find_by_id(&table, server_assigned_session_id);
    assert(server_session != NULL);
    assert(server_session->state == VPN_SESSION_STATE_HANDSHAKE_IN_PROGRESS);
    assert(server_session->assigned_virtual_ip == 0u);
    assert(vpn_handshake_reserve_virtual_ip(&table, server_assigned_session_id, requested_vip) == 0);
    assert(server_session->assigned_virtual_ip == requested_vip);
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
    /* Client stays in FINISH_SENT, waiting for SERVER_FINISH */
    assert(client_ctx.client_state == VPN_CLIENT_HANDSHAKE_STATE_FINISH_SENT);
    
    /* Server receives CLIENT_FINISH */
    assert(vpn_handshake_process_envelope(&envelope, &server_ctx) == 0);
    assert(server_ctx.server_state == VPN_SERVER_HANDSHAKE_STATE_ESTABLISHED);
    
    /* Step 4: Server sends SERVER_FINISH */
    envelope.type = VPN_MSG_SERVER_FINISH;
    envelope.session_id = server_assigned_session_id;
    envelope.message_id = 4u;
    
    /* Client receives SERVER_FINISH and moves to ESTABLISHED */
    assert(vpn_handshake_process_envelope(&envelope, &client_ctx) == 0);
    assert(client_ctx.client_state == VPN_CLIENT_HANDSHAKE_STATE_ESTABLISHED);
    
    /* Step 5: Mark session as established on server */
    server_session->state = VPN_SESSION_STATE_ESTABLISHED;
    
    /* Verify all expectations */
    assert(client_ctx.client_state == VPN_CLIENT_HANDSHAKE_STATE_ESTABLISHED);
    assert(server_ctx.server_state == VPN_SERVER_HANDSHAKE_STATE_ESTABLISHED);
    assert(client_ctx.session_id == server_ctx.session_id);
    assert(client_ctx.session_id == server_assigned_session_id);
    assert(vpn_session_can_accept_data(server_session) == 1);
    assert(server_session->assigned_virtual_ip == requested_vip);
}

int test_handshake_flow(void)
{
    test_clean_four_message_establishment();
    test_reject_data_before_server_finish();
    test_three_simultaneous_clients_virtual_ip_lookup();
    test_virtual_ip_conflict_rejection();
    test_realistic_handshake_simulation();
    printf("test_handshake_flow.c passed\n");
    return 0;
}
