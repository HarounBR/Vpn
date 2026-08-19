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

    assert(vpn_session_table_insert(&table, &first_session) == 0);
    assert(table.sessions[0].client_nonce == 0x11111111u);
    assert(table.sessions[0].server_nonce == 0x22222222u);
    assert(table.sessions[0].key_exchange_context_length == 3u);
    assert(memcmp(table.sessions[0].key_exchange_context, "xyz", 3) == 0);
    assert(table.sessions[0].last_message_id == 42u);
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

    table.sessions[0].state = VPN_SESSION_STATE_ESTABLISHED;
    assert(vpn_session_table_process_keepalive(&table, first_session.session_id,
                                               1000u, 43u,
                                               0xC0A8000Au, 1194,
                                               VPN_AUTH_OK) == VPN_SESSION_OK);
    assert(table.sessions[0].peer_address.address == 0xC0A8000Au);
    assert(table.sessions[0].peer_address.port == 1194);
}

static void test_session_table_virtual_ip_uniqueness(void)
{
    struct vpn_session_table table;
    struct vpn_session session_a;
    struct vpn_session session_b;
    struct vpn_session session_c;
    struct vpn_session *owner;
    const uint32_t vip_a = 0x0A000001u;
    const uint32_t vip_b = 0x0A000002u;

    memset(&table, 0, sizeof(table));
    vpn_session_table_init(&table);

    memset(&session_a, 0, sizeof(session_a));
    session_a.session_id = 20u;
    session_a.state = VPN_SESSION_STATE_HANDSHAKE_IN_PROGRESS;
    session_a.assigned_virtual_ip = vip_a;
    session_a.client_identity.client_id_length = 5u;
    memcpy(session_a.client_identity.client_id, "alpha", 5u);
    assert(vpn_session_table_insert(&table, &session_a) == 0);

    memset(&session_b, 0, sizeof(session_b));
    session_b.session_id = 21u;
    session_b.state = VPN_SESSION_STATE_HANDSHAKE_IN_PROGRESS;
    session_b.assigned_virtual_ip = vip_b;
    session_b.client_identity.client_id_length = 5u;
    memcpy(session_b.client_identity.client_id, "bravo", 5u);
    assert(vpn_session_table_insert(&table, &session_b) == 0);

    memset(&session_c, 0, sizeof(session_c));
    session_c.session_id = 22u;
    session_c.state = VPN_SESSION_STATE_HANDSHAKE_IN_PROGRESS;
    session_c.assigned_virtual_ip = vip_a;
    session_c.client_identity.client_id_length = 5u;
    memcpy(session_c.client_identity.client_id, "gamma", 5u);
    assert(vpn_session_table_insert(&table, &session_c) != 0);

    owner = vpn_session_table_find_by_virtual_ip(&table, vip_a);
    assert(owner != NULL);
    assert(owner->session_id == session_a.session_id);
    assert(table.session_count == 2u);
}

static void test_session_table_virtual_ip_lookup(void)
{
    struct vpn_session_table table;
    struct vpn_session session_a;
    struct vpn_session session_b;
    struct vpn_session session_c;
    struct vpn_session *found;
    const uint32_t vip_a = 0x0A000011u;
    const uint32_t vip_b = 0x0A000012u;
    const uint32_t vip_c = 0x0A000013u;

    memset(&table, 0, sizeof(table));
    vpn_session_table_init(&table);

    memset(&session_a, 0, sizeof(session_a));
    session_a.session_id = 30u;
    session_a.state = VPN_SESSION_STATE_ESTABLISHED;
    session_a.assigned_virtual_ip = vip_a;
    session_a.client_identity.client_id_length = 5u;
    memcpy(session_a.client_identity.client_id, "alpha", 5u);
    assert(vpn_session_table_insert(&table, &session_a) == 0);

    memset(&session_b, 0, sizeof(session_b));
    session_b.session_id = 31u;
    session_b.state = VPN_SESSION_STATE_ESTABLISHED;
    session_b.assigned_virtual_ip = vip_b;
    session_b.client_identity.client_id_length = 5u;
    memcpy(session_b.client_identity.client_id, "bravo", 5u);
    assert(vpn_session_table_insert(&table, &session_b) == 0);

    memset(&session_c, 0, sizeof(session_c));
    session_c.session_id = 32u;
    session_c.state = VPN_SESSION_STATE_ESTABLISHED;
    session_c.assigned_virtual_ip = vip_c;
    session_c.client_identity.client_id_length = 5u;
    memcpy(session_c.client_identity.client_id, "charl", 5u);
    assert(vpn_session_table_insert(&table, &session_c) == 0);

    found = vpn_session_table_find_by_virtual_ip(&table, vip_b);
    assert(found != NULL);
    assert(found->session_id == session_b.session_id);

    found = vpn_session_table_find_by_virtual_ip(&table, 0x0A0000FFu);
    assert(found == NULL);
}

static void test_session_table_records_peer_address_from_client_hello(void)
{
    struct vpn_session_table table;
    struct vpn_session session;

    memset(&table, 0, sizeof(table));
    vpn_session_table_init(&table);

    memset(&session, 0, sizeof(session));
    session.session_id = 40u;
    session.state = VPN_SESSION_STATE_HANDSHAKE_IN_PROGRESS;
    session.assigned_virtual_ip = 0x0A000021u;
    session.client_identity.client_id_length = 4u;
    memcpy(session.client_identity.client_id, "test", 4u);
    assert(vpn_session_table_insert(&table, &session) == 0);

    assert(vpn_session_table_capture_client_hello_peer(&table, session.session_id, 0xC0A8000Au, 1194u) == 0);
    assert(table.sessions[0].peer_address.address == 0xC0A8000Au);
    assert(table.sessions[0].peer_address.port == 1194u);

    assert(vpn_session_table_capture_client_hello_peer(&table, session.session_id, 0xC0A8000Bu, 1195u) != 0);
    assert(table.sessions[0].peer_address.address == 0xC0A8000Au);
    assert(table.sessions[0].peer_address.port == 1194u);
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

/* T042: Session expiration tests */
static void test_session_table_established_expiration(void)
{
    struct vpn_session_table table;
    struct vpn_session session;
    const uint32_t vip = 0x0A000001u;

    memset(&table, 0, sizeof(table));
    vpn_session_table_init(&table);

    memset(&session, 0, sizeof(session));
    session.session_id = 1u;
    session.state = VPN_SESSION_STATE_ESTABLISHED;
    session.assigned_virtual_ip = vip;
    session.client_identity.client_id_length = 5u;
    memcpy(session.client_identity.client_id, "alpha", 5u);
    session.last_seen_at_ms = 1000u;

    assert(vpn_session_table_insert(&table, &session) == 0);

    /* Verify session is initially active */
    struct vpn_session *found = vpn_session_table_find_by_id(&table, 1u);
    assert(found != NULL);
    assert(found->state == VPN_SESSION_STATE_ESTABLISHED);
    assert(found->assigned_virtual_ip == vip);

    /* Before 45s - not expired */
    assert(vpn_session_table_check_expiration(&table, 1000u + 44999u) == 0);
    assert(vpn_session_table_cleanup_expired(&table, 1000u + 44999u) == 0);
    found = vpn_session_table_find_by_id(&table, 1u);
    assert(found != NULL);
    assert(found->state == VPN_SESSION_STATE_ESTABLISHED);

    /* At exactly 45s - expired */
    assert(vpn_session_table_check_expiration(&table, 1000u + 45000u) == 1);
    assert(vpn_session_table_cleanup_expired(&table, 1000u + 45000u) == 1);
    found = vpn_session_table_find_by_id(&table, 1u);
    assert(found == NULL || found->state == VPN_SESSION_STATE_EXPIRED);

    /* Virtual IP should be released */
    found = vpn_session_table_find_by_virtual_ip(&table, vip);
    assert(found == NULL);
}

static void test_session_table_handshake_cleanup(void)
{
    struct vpn_session_table table;
    struct vpn_session session;
    const uint32_t vip = 0x0A000002u;

    memset(&table, 0, sizeof(table));
    vpn_session_table_init(&table);

    memset(&session, 0, sizeof(session));
    session.session_id = 2u;
    session.state = VPN_SESSION_STATE_HANDSHAKE_IN_PROGRESS;
    session.assigned_virtual_ip = vip;
    session.client_identity.client_id_length = 5u;
    memcpy(session.client_identity.client_id, "beta", 5u);
    session.handshake_deadline_ms = 1000u + VPN_HANDSHAKE_TIMEOUT_MS;

    assert(vpn_session_table_insert(&table, &session) == 0);

    struct vpn_session *found = vpn_session_table_find_by_id(&table, 2u);
    assert(found != NULL);
    assert(found->state == VPN_SESSION_STATE_HANDSHAKE_IN_PROGRESS);
    assert(found->assigned_virtual_ip == vip);
    assert(found->handshake_deadline_ms == 11000u);

    /* Before 10s - not expired */
    assert(vpn_session_table_check_expiration(&table, 10000u) == 0);
    assert(vpn_session_table_cleanup_expired(&table, 10000u) == 0);
    found = vpn_session_table_find_by_id(&table, 2u);
    assert(found != NULL);
    assert(found->state == VPN_SESSION_STATE_HANDSHAKE_IN_PROGRESS);

    /* At exactly 10s - expired */
    assert(vpn_session_table_check_expiration(&table, 11000u) == 1);
    assert(vpn_session_table_cleanup_expired(&table, 11000u) == 1);
    found = vpn_session_table_find_by_id(&table, 2u);
    assert(found == NULL || found->state == VPN_SESSION_STATE_EXPIRED);

    /* Virtual IP should be released */
    found = vpn_session_table_find_by_virtual_ip(&table, vip);
    assert(found == NULL);
}

static void test_session_table_release_virtual_ip_on_expiration(void)
{
    struct vpn_session_table table;
    struct vpn_session session;
    const uint32_t vip = 0x0A000003u;

    memset(&table, 0, sizeof(table));
    vpn_session_table_init(&table);

    memset(&session, 0, sizeof(session));
    session.session_id = 3u;
    session.state = VPN_SESSION_STATE_ESTABLISHED;
    session.assigned_virtual_ip = vip;
    session.client_identity.client_id_length = 5u;
    memcpy(session.client_identity.client_id, "gamma", 5u);

    assert(vpn_session_table_insert(&table, &session) == 0);

    /* Verify virtual IP is assigned */
    struct vpn_session *found = vpn_session_table_find_by_virtual_ip(&table, vip);
    assert(found != NULL);
    assert(found->session_id == 3u);

    /* Release virtual IP on expiration */
    assert(vpn_session_table_release_virtual_ip(&table, 3u, vip) == VPN_SESSION_OK);
    assert(found->assigned_virtual_ip == 0u);

    /* Virtual IP should no longer be found */
    found = vpn_session_table_find_by_virtual_ip(&table, vip);
    assert(found == NULL);
}

static void test_session_table_peer_address_rebinding(void)
{
    struct vpn_session_table table;
    struct vpn_session session;
    const uint32_t vip = 0x0A000004u;

    memset(&table, 0, sizeof(table));
    vpn_session_table_init(&table);

    memset(&session, 0, sizeof(session));
    session.session_id = 4u;
    session.state = VPN_SESSION_STATE_ESTABLISHED;
    session.assigned_virtual_ip = vip;
    session.client_identity.client_id_length = 5u;
    memcpy(session.client_identity.client_id, "delta", 5u);
    session.peer_address.address = 0xC0A80001u;  /* 192.168.0.1 */
    session.peer_address.port = 1194u;

    assert(vpn_session_table_insert(&table, &session) == 0);

    struct vpn_session *found = vpn_session_table_find_by_id(&table, 4u);
    assert(found != NULL);
    assert(found->peer_address.address == 0xC0A80001u);
    assert(found->peer_address.port == 1194u);

    /* Update peer address with authenticated keepalive from new address */
    assert(vpn_session_table_process_keepalive(&table, 4u, 10000u, 1u,
                                               0xC0A80002u, 1195u, VPN_AUTH_OK) == VPN_SESSION_OK);
    assert(found->peer_address.address == 0xC0A80002u);
    assert(found->peer_address.port == 1195u);

    /* Verify unauthenticated update from different address is rejected */
    assert(vpn_session_table_process_keepalive(&table, 4u, 10001u, 2u,
                                               0xC0A80003u, 1196u, VPN_AUTH_FAILED) != VPN_SESSION_OK);
    assert(found->peer_address.address == 0xC0A80002u);  /* Should remain unchanged */
}

int test_session_table(void)
{
    test_session_table_init();
    test_session_table_conflicts_and_peer_address();
    test_session_table_virtual_ip_uniqueness();
    test_session_table_virtual_ip_lookup();
    test_session_table_records_peer_address_from_client_hello();
    test_session_table_rejects_invalid_identity_and_zero_virtual_ip();
    /* T042: Session expiration tests */
    test_session_table_established_expiration();
    test_session_table_handshake_cleanup();
    test_session_table_release_virtual_ip_on_expiration();
    test_session_table_peer_address_rebinding();
    printf("test_session_table.c passed\n");
    return 0;
}
