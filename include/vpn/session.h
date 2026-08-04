#ifndef VPN_SESSION_H
#define VPN_SESSION_H

#include <stdint.h>
#include <stddef.h>
#include "vpn/protocol.h"
#include "vpn/handshake.h"

#ifdef __cplusplus
extern "C" {
#endif

struct vpn_client_identity {
    uint8_t client_id[VPN_PROTOCOL_MAX_CLIENT_ID];
    uint8_t client_id_length;
};

struct vpn_peer_address {
    uint32_t address;
    uint16_t port;
};

struct vpn_virtual_ip_assignment {
    uint32_t virtual_ip;
    uint64_t session_id;
    uint8_t active;
};

enum vpn_session_state {
    VPN_SESSION_STATE_NONE,
    VPN_SESSION_STATE_HANDSHAKE_IN_PROGRESS,
    VPN_SESSION_STATE_ESTABLISHED,
    VPN_SESSION_STATE_CLOSING,
    VPN_SESSION_STATE_CLOSED,
    VPN_SESSION_STATE_EXPIRED
};

struct vpn_session {
    uint64_t session_id;
    struct vpn_client_identity client_identity;
    enum vpn_session_state state;
    uint32_t assigned_virtual_ip;
    struct vpn_peer_address peer_address;
    uint64_t last_seen_at_ms;
    uint64_t expires_at_ms;
};

#define VPN_SESSION_TABLE_MAX_SESSIONS 64u

struct vpn_session_table {
    struct vpn_session sessions[VPN_SESSION_TABLE_MAX_SESSIONS];
    size_t session_count;
};

void vpn_session_table_init(struct vpn_session_table *table);
struct vpn_session *vpn_session_table_find_by_id(struct vpn_session_table *table, uint64_t session_id);
int vpn_session_table_insert(struct vpn_session_table *table, const struct vpn_session *session);
int vpn_session_table_remove(struct vpn_session_table *table, uint64_t session_id);
struct vpn_session *vpn_session_table_find_by_virtual_ip(struct vpn_session_table *table, uint32_t virtual_ip);

#ifdef __cplusplus
}
#endif

#endif /* VPN_SESSION_H */
