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

int vpn_session_table_has_virtual_ip_conflict(const struct vpn_session_table *table,
                                              uint32_t virtual_ip,
                                              uint64_t allowed_session_id)
{
    if (!table || virtual_ip == 0u) {
        return 0;
    }

    for (size_t i = 0; i < table->session_count; ++i) {
        const struct vpn_session *candidate = &table->sessions[i];
        if (session_is_active(candidate) &&
            candidate->assigned_virtual_ip == virtual_ip &&
            candidate->session_id != allowed_session_id) {
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
        return VPN_SESSION_ERR_INVALID_INPUT;
    }

    if (!has_valid_client_identity(session)) {
        return VPN_SESSION_ERR_INVALID_INPUT;
    }

    if (has_duplicate_identity(table, session)) {
        return VPN_SESSION_ERR_DUPLICATE_IDENTITY;
    }

    if (vpn_session_table_has_virtual_ip_conflict(table, session->assigned_virtual_ip, session->session_id)) {
        return VPN_SESSION_ERR_VIRTUAL_IP_CONFLICT;
    }

    table->sessions[table->session_count++] = *session;
    return VPN_SESSION_OK;
}

int vpn_session_table_remove(struct vpn_session_table *table, uint64_t session_id)
{
    if (!table) {
        return VPN_SESSION_ERR_INVALID_INPUT;
    }

    for (size_t i = 0; i < table->session_count; ++i) {
        if (table->sessions[i].session_id == session_id) {
            if (i + 1 < table->session_count) {
                memmove(&table->sessions[i], &table->sessions[i + 1],
                        (table->session_count - i - 1) * sizeof(table->sessions[0]));
            }
            --table->session_count;
            return VPN_SESSION_OK;
        }
    }

    return VPN_SESSION_ERR_NOT_FOUND;
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

/* Phase 4 boundary: vpn_session_table_capture_client_hello_peer() is the
 * handshake-time peer capture helper. This function is for established-session
 * updates and must not be used for unauthenticated CLIENT_HELLO capture. */
int vpn_session_table_record_peer_address(struct vpn_session_table *table, uint64_t session_id, uint32_t address, uint16_t port)
{
    struct vpn_session *session;

    if (!table) {
        return VPN_SESSION_ERR_INVALID_INPUT;
    }

    session = vpn_session_table_find_by_id(table, session_id);
    if (!session) {
        return VPN_SESSION_ERR_NOT_FOUND;
    }

    if (session->state != VPN_SESSION_STATE_ESTABLISHED &&
        (session->peer_address.address != 0u || session->peer_address.port != 0u)) {
        return VPN_SESSION_ERR_INVALID_STATE;
    }

    if (session->state == VPN_SESSION_STATE_ESTABLISHED ||
        (session->peer_address.address == 0u && session->peer_address.port == 0u)) {
        session->peer_address.address = address;
        session->peer_address.port = port;
        return VPN_SESSION_OK;
    }

    return VPN_SESSION_ERR_INVALID_STATE;
}

/* T027: Pre-establishment data rejection helper */
int vpn_session_can_accept_data(const struct vpn_session *session)
{
    if (!session) {
        return 0;
    }

    return session->state == VPN_SESSION_STATE_ESTABLISHED;
}

/* T026: Session creation and session ID allocation */
uint64_t vpn_session_table_next_session_id(struct vpn_session_table *table)
{
    if (!table) {
        return 1;
    }

    uint64_t max_id = 0;
    for (size_t i = 0; i < table->session_count; ++i) {
        if (table->sessions[i].session_id > max_id) {
            max_id = table->sessions[i].session_id;
        }
    }

    return max_id + 1;
}

int vpn_session_table_create(struct vpn_session_table *table, uint64_t *out_session_id,
                             const uint8_t *client_id, uint8_t client_id_length,
                             uint32_t requested_virtual_ip)
{
    struct vpn_session session;
    uint64_t new_session_id;

    (void)requested_virtual_ip;

    if (!table || !out_session_id || !client_id) {
        return VPN_SESSION_ERR_INVALID_INPUT;
    }

    if (client_id_length == 0 || client_id_length > VPN_PROTOCOL_MAX_CLIENT_ID) {
        return VPN_SESSION_ERR_INVALID_INPUT;
    }

    new_session_id = vpn_session_table_next_session_id(table);
    if (new_session_id == 0) {
        return VPN_SESSION_ERR_INVALID_INPUT;
    }

    memset(&session, 0, sizeof(session));
    session.session_id = new_session_id;
    session.state = VPN_SESSION_STATE_HANDSHAKE_IN_PROGRESS;
    session.client_identity.client_id_length = client_id_length;
    memcpy(session.client_identity.client_id, client_id, client_id_length);
    session.assigned_virtual_ip = 0u;

    if (vpn_session_table_insert(table, &session) != VPN_SESSION_OK) {
        return VPN_SESSION_ERR_DUPLICATE_IDENTITY;
    }

    *out_session_id = new_session_id;
    return VPN_SESSION_OK;
}

/* T034: Virtual IP assignment and release */
int vpn_session_table_assign_virtual_ip(struct vpn_session_table *table,
                                        uint64_t session_id,
                                        uint32_t virtual_ip)
{
    struct vpn_session *session;

    if (!table) {
        return VPN_SESSION_ERR_INVALID_INPUT;
    }

    session = vpn_session_table_find_by_id(table, session_id);
    if (!session) {
        return VPN_SESSION_ERR_NOT_FOUND;
    }

    if (vpn_session_table_has_virtual_ip_conflict(table, virtual_ip, session_id)) {
        return VPN_SESSION_ERR_VIRTUAL_IP_CONFLICT;
    }

    session->assigned_virtual_ip = virtual_ip;
    return VPN_SESSION_OK;
}

int vpn_session_table_release_virtual_ip(struct vpn_session_table *table,
                                         uint64_t session_id,
                                         uint32_t virtual_ip)
{
    struct vpn_session *session;

    if (!table || virtual_ip == 0u) {
        return VPN_SESSION_ERR_INVALID_INPUT;
    }

    session = vpn_session_table_find_by_id(table, session_id);
    if (!session) {
        return VPN_SESSION_ERR_NOT_FOUND;
    }

    if (session->assigned_virtual_ip != virtual_ip) {
        return VPN_SESSION_ERR_INVALID_STATE;
    }

    session->assigned_virtual_ip = 0u;
    return VPN_SESSION_OK;
}

/* T036: Peer address capture from CLIENT_HELLO */
int vpn_session_table_capture_client_hello_peer(struct vpn_session_table *table,
                                                uint64_t session_id,
                                                uint32_t address,
                                                uint16_t port)
{
    struct vpn_session *session;

    if (!table) {
        return -1;
    }

    session = vpn_session_table_find_by_id(table, session_id);
    if (!session) {
        return -1;
    }

    if (session->state != VPN_SESSION_STATE_HANDSHAKE_IN_PROGRESS) {
        return -1;
    }

    if (session->peer_address.address != 0u || session->peer_address.port != 0u) {
        return -1;
    }

    session->peer_address.address = address;
    session->peer_address.port = port;
    return 0;
}

/* T037: Outbound virtual IP lookup for data-plane routing */
struct vpn_session *vpn_session_table_lookup_outbound(struct vpn_session_table *table,
                                                      uint32_t destination_virtual_ip)
{
    struct vpn_session *session;

    if (!table || destination_virtual_ip == 0u) {
        return NULL;
    }

    session = vpn_session_table_find_by_virtual_ip(table, destination_virtual_ip);
    if (!session || session->state != VPN_SESSION_STATE_ESTABLISHED) {
        return NULL;
    }

    return session;
}
