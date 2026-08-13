#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "vpn/session.h"

static void test_session_table_init(void)
{
    struct vpn_session_table table;
    vpn_session_table_init(&table);
    assert(table.session_count == 0);
}

static void test_session_table_conflicts_and_peer_address(void)
{
    struct vpn_session_table table;
    struct vpn_session first_session;
    struct vpn_session duplicate_identity_session;
    struct vpn_session conflicting_virtual_ip_session;

    memset(&table, 0, sizeof(table));
    vpn_session_table_init(&table);

    memset(&first_session, 0, sizeof(first_session));
    first_session.session_id = 1;
    first_session.state = VPN_SESSION_STATE_HANDSHAKE_IN_PROGRESS;
    first_session.assigned_virtual_ip = 0x0A000001u;
    first_session.client_identity.client_id_length = 5;
    memcpy(first_session.client_identity.client_id, "alpha", 5);
    first_session.client_nonce = 0x11111111u;
    first_session.server_nonce = 0x22222222u;
    first_session.key_exchange_context_length = 3;
    memcpy(first_session.key_exchange_context, "xyz", 3);
    first_session.last_message_id = 42u;
    first_session.retry_count = 1u;

    assert(vpn_session_table_insert(&table, &first_session) == 0);
    assert(table.sessions[0].client_nonce == 0x11111111u);
    assert(table.sessions[0].server_nonce == 0x22222222u);
    assert(table.sessions[0].key_exchange_context_length == 3u);
    assert(memcmp(table.sessions[0].key_exchange_context, "xyz", 3) == 0);
    assert(table.sessions[0].last_message_id == 42u);
    assert(table.sessions[0].retry_count == 1u);
    assert(table.session_count == 1);

    memset(&duplicate_identity_session, 0, sizeof(duplicate_identity_session));
    duplicate_identity_session.session_id = 2;
    duplicate_identity_session.state = VPN_SESSION_STATE_HANDSHAKE_IN_PROGRESS;
    duplicate_identity_session.assigned_virtual_ip = 0x0A000002u;
    duplicate_identity_session.client_identity.client_id_length = 5;
    memcpy(duplicate_identity_session.client_identity.client_id, "alpha", 5);

    assert(vpn_session_table_insert(&table, &duplicate_identity_session) != 0);

    memset(&conflicting_virtual_ip_session, 0, sizeof(conflicting_virtual_ip_session));
    conflicting_virtual_ip_session.session_id = 3;
    conflicting_virtual_ip_session.state = VPN_SESSION_STATE_HANDSHAKE_IN_PROGRESS;
    conflicting_virtual_ip_session.assigned_virtual_ip = 0x0A000001u;
    conflicting_virtual_ip_session.client_identity.client_id_length = 6;
    memcpy(conflicting_virtual_ip_session.client_identity.client_id, "beta", 4);

    assert(vpn_session_table_insert(&table, &conflicting_virtual_ip_session) != 0);

    first_session.state = VPN_SESSION_STATE_ESTABLISHED;
    assert(vpn_session_table_record_peer_address(&table, first_session.session_id, 0xC0A8000Au, 1194) == 0);
    assert(table.sessions[0].peer_address.address == 0xC0A8000Au);
    assert(table.sessions[0].peer_address.port == 1194);
}

static void test_session_table_rejects_invalid_identity_and_zero_virtual_ip(void)
{
    struct vpn_session_table table;
    struct vpn_session invalid_identity_session;
    struct vpn_session invalid_virtual_ip_session;

    memset(&table, 0, sizeof(table));
    vpn_session_table_init(&table);

    memset(&invalid_identity_session, 0, sizeof(invalid_identity_session));
    invalid_identity_session.session_id = 10u;
    invalid_identity_session.state = VPN_SESSION_STATE_HANDSHAKE_IN_PROGRESS;
    invalid_identity_session.assigned_virtual_ip = 0x0A00000Au;
    invalid_identity_session.client_identity.client_id_length = 0u;
    assert(vpn_session_table_insert(&table, &invalid_identity_session) != 0);

    memset(&invalid_virtual_ip_session, 0, sizeof(invalid_virtual_ip_session));
    invalid_virtual_ip_session.session_id = 11u;
    invalid_virtual_ip_session.state = VPN_SESSION_STATE_HANDSHAKE_IN_PROGRESS;
    invalid_virtual_ip_session.assigned_virtual_ip = 0u;
    invalid_virtual_ip_session.client_identity.client_id_length = 4u;
    memcpy(invalid_virtual_ip_session.client_identity.client_id, "beta", 4);
    assert(vpn_session_table_insert(&table, &invalid_virtual_ip_session) == 0);
}

int test_session_table(void)
{
    test_session_table_init();
    test_session_table_conflicts_and_peer_address();
    test_session_table_rejects_invalid_identity_and_zero_virtual_ip();
    printf("test_session_table.c passed\n");
    return 0;
}
