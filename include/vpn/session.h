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

/* Reserved for future explicit assignment table implementation. */

enum vpn_session_state {
    VPN_SESSION_STATE_NONE,
    VPN_SESSION_STATE_HANDSHAKE_IN_PROGRESS,
    VPN_SESSION_STATE_ESTABLISHED,
    VPN_SESSION_STATE_CLOSING,
    VPN_SESSION_STATE_CLOSED,
    VPN_SESSION_STATE_EXPIRED
};

enum vpn_session_result {
    VPN_SESSION_OK = 0,
    VPN_SESSION_ERR_NOT_FOUND = -1,
    VPN_SESSION_ERR_INVALID_INPUT = -2,
    VPN_SESSION_ERR_TABLE_FULL = -3,
    VPN_SESSION_ERR_DUPLICATE_IDENTITY = -4,
    VPN_SESSION_ERR_VIRTUAL_IP_CONFLICT = -5,
    VPN_SESSION_ERR_VIRTUAL_IP_NOT_FOUND = -6,
    VPN_SESSION_ERR_INVALID_STATE = -7,
    VPN_SESSION_ERR_AUTHENTICATION_FAILED = -8
};

enum vpn_auth_result {
    VPN_AUTH_OK = 0,
    VPN_AUTH_FAILED = -1,
    VPN_AUTH_STALE = -2,
    VPN_AUTH_REPLAY = -3
};

#define VPN_SESSION_IDLE_TIMEOUT_MS 45000u
#define VPN_HANDSHAKE_TIMEOUT_MS 10000u

struct vpn_session {
    uint64_t session_id;
    struct vpn_client_identity client_identity;
    enum vpn_session_state state;
    uint32_t assigned_virtual_ip;
    struct vpn_peer_address peer_address;
    uint32_t client_nonce;
    uint32_t server_nonce;
    uint8_t key_exchange_context[32];
    uint8_t key_exchange_context_length;
    uint64_t last_message_id;
    uint64_t last_seen_at_ms;
    uint64_t handshake_deadline_ms;
    uint64_t pending_keepalive_message_id;
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

/* T034: Virtual IP assignment, lookup, and release */
int vpn_session_table_assign_virtual_ip(struct vpn_session_table *table,
                                        uint64_t session_id,
                                        uint32_t virtual_ip);
int vpn_session_table_release_virtual_ip(struct vpn_session_table *table,
                                         uint64_t session_id,
                                         uint32_t virtual_ip);

/* T035: Active virtual IP conflict detection */
int vpn_session_table_has_virtual_ip_conflict(const struct vpn_session_table *table,
                                              uint32_t virtual_ip,
                                              uint64_t allowed_session_id);

/* T036: Peer address capture from CLIENT_HELLO */
int vpn_session_table_capture_client_hello_peer(struct vpn_session_table *table,
                                                uint64_t session_id,
                                                uint32_t address,
                                                uint16_t port);

/* T037: Outbound virtual IP lookup for data-plane routing */
struct vpn_session *vpn_session_table_lookup_outbound(struct vpn_session_table *table,
                                                      uint32_t destination_virtual_ip);

/* T026: Session creation and session ID allocation */
uint64_t vpn_session_table_next_session_id(struct vpn_session_table *table);
int vpn_session_table_create(struct vpn_session_table *table, uint64_t *out_session_id, 
                             const uint8_t *client_id, uint8_t client_id_length,
                             uint32_t requested_virtual_ip);

/* T027: Pre-establishment data rejection helper */
int vpn_session_can_accept_data(const struct vpn_session *session);

/* T048: Session expiration and cleanup */
int vpn_session_table_check_expiration(struct vpn_session_table *table, uint64_t current_time_ms);
int vpn_session_table_cleanup_expired(struct vpn_session_table *table, uint64_t current_time_ms);
int vpn_session_table_cleanup_session(struct vpn_session_table *table, uint64_t session_id);

/* T051: Authenticated peer address rebinding and keepalive processing */
int vpn_session_table_process_keepalive(struct vpn_session_table *table, uint64_t session_id,
                                        uint64_t current_time_ms, uint64_t message_id,
                                        uint32_t peer_address, uint16_t peer_port,
                                        enum vpn_auth_result auth_result);
int vpn_session_table_process_keepalive_ack(struct vpn_session_table *table, uint64_t session_id,
                                            uint64_t current_time_ms, uint64_t original_message_id,
                                            enum vpn_auth_result auth_result);
int vpn_session_table_process_close(struct vpn_session_table *table, uint64_t session_id,
                                    uint64_t current_time_ms, enum vpn_auth_result auth_result);
int vpn_session_table_process_reject(struct vpn_session_table *table, uint64_t session_id,
                                     uint64_t failed_message_id, enum vpn_auth_result auth_result);

/* T048: Session establishment with timestamp */
int vpn_session_table_establish(struct vpn_session_table *table, uint64_t session_id,
                                uint64_t current_time_ms);

#ifdef __cplusplus
}
#endif

#endif /* VPN_SESSION_H */
