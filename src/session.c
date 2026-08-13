#include "vpn/session.h"
#include <string.h>

static int session_is_active(const struct vpn_session *session)
{
    if (!session) {
        return 0;
    }

    switch (session->state) {
    case VPN_SESSION_STATE_HANDSHAKE_IN_PROGRESS:
    case VPN_SESSION_STATE_ESTABLISHED:
    case VPN_SESSION_STATE_CLOSING:
        return 1;
    default:
        return 0;
    }
}

static int has_duplicate_identity(const struct vpn_session_table *table, const struct vpn_session *session)
{
    if (!table || !session) {
        return 0;
    }

    for (size_t i = 0; i < table->session_count; ++i) {
        const struct vpn_session *candidate = &table->sessions[i];
        if (!session_is_active(candidate)) {
            continue;
        }

        if (candidate->client_identity.client_id_length != session->client_identity.client_id_length) {
            continue;
        }

        if (memcmp(candidate->client_identity.client_id,
                   session->client_identity.client_id,
                   session->client_identity.client_id_length) == 0) {
            return 1;
        }
    }

    return 0;
}

static int has_conflicting_virtual_ip(const struct vpn_session_table *table, const struct vpn_session *session)
{
    if (!table || !session) {
        return 0;
    }

    if (session->assigned_virtual_ip == 0u) {
        return 0;
    }

    for (size_t i = 0; i < table->session_count; ++i) {
        const struct vpn_session *candidate = &table->sessions[i];
        if (session_is_active(candidate) && candidate->assigned_virtual_ip == session->assigned_virtual_ip) {
            return 1;
        }
    }

    return 0;
}

static int has_valid_client_identity(const struct vpn_session *session)
{
    if (!session) {
        return 0;
    }

    if (session->client_identity.client_id_length == 0u ||
        session->client_identity.client_id_length > VPN_PROTOCOL_MAX_CLIENT_ID) {
        return 0;
    }

    return 1;
}

void vpn_session_table_init(struct vpn_session_table *table)
{
    if (!table) {
        return;
    }

    table->session_count = 0;
    memset(table->sessions, 0, sizeof(table->sessions));
}

struct vpn_session *vpn_session_table_find_by_id(struct vpn_session_table *table, uint64_t session_id)
{
    if (!table) {
        return NULL;
    }

    for (size_t i = 0; i < table->session_count; ++i) {
        if (table->sessions[i].session_id == session_id) {
            return &table->sessions[i];
        }
    }

    return NULL;
}

int vpn_session_table_insert(struct vpn_session_table *table, const struct vpn_session *session)
{
    if (!table || !session || table->session_count >= VPN_SESSION_TABLE_MAX_SESSIONS) {
        return -1;
    }

    if (!has_valid_client_identity(session)) {
        return -1;
    }

    if (has_duplicate_identity(table, session) || has_conflicting_virtual_ip(table, session)) {
        return -1;
    }

    table->sessions[table->session_count++] = *session;
    return 0;
}

int vpn_session_table_remove(struct vpn_session_table *table, uint64_t session_id)
{
    if (!table) {
        return -1;
    }

    for (size_t i = 0; i < table->session_count; ++i) {
        if (table->sessions[i].session_id == session_id) {
            if (i + 1 < table->session_count) {
                memmove(&table->sessions[i], &table->sessions[i + 1],
                        (table->session_count - i - 1) * sizeof(table->sessions[0]));
            }
            --table->session_count;
            return 0;
        }
    }

    return -1;
}

struct vpn_session *vpn_session_table_find_by_virtual_ip(struct vpn_session_table *table, uint32_t virtual_ip)
{
    if (!table) {
        return NULL;
    }

    for (size_t i = 0; i < table->session_count; ++i) {
        if (table->sessions[i].assigned_virtual_ip == virtual_ip) {
            return &table->sessions[i];
        }
    }

    return NULL;
}

int vpn_session_table_record_peer_address(struct vpn_session_table *table, uint64_t session_id, uint32_t address, uint16_t port)
{
    struct vpn_session *session;

    if (!table) {
        return -1;
    }

    session = vpn_session_table_find_by_id(table, session_id);
    if (!session) {
        return -1;
    }

    if (session->state != VPN_SESSION_STATE_ESTABLISHED &&
        (session->peer_address.address != 0u || session->peer_address.port != 0u)) {
        return -1;
    }

    if (session->state == VPN_SESSION_STATE_ESTABLISHED ||
        (session->peer_address.address == 0u && session->peer_address.port == 0u)) {
        session->peer_address.address = address;
        session->peer_address.port = port;
        return 0;
    }

    return -1;
}
