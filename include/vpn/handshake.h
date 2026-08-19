#ifndef VPN_HANDSHAKE_H
#define VPN_HANDSHAKE_H

#include <stdint.h>
#include <stddef.h>
#include "vpn/protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

struct vpn_session_table;

#define VPN_HANDSHAKE_TIMEOUT_MS 10000u
#define VPN_KEEPALIVE_INTERVAL_MS 15000u
#define VPN_SESSION_IDLE_TIMEOUT_MS 45000u
#define VPN_RETRY_ONE_MS 1000u
#define VPN_RETRY_TWO_AT_MS 3000u
#define VPN_RETRY_THREE_AT_MS 7000u
#define VPN_RETRY_MAX_MS 4000u
#define VPN_MAX_HANDSHAKE_ATTEMPTS 4u

enum vpn_client_handshake_state {
    VPN_CLIENT_HANDSHAKE_STATE_IDLE,
    VPN_CLIENT_HANDSHAKE_STATE_HELLO_SENT,
    VPN_CLIENT_HANDSHAKE_STATE_FINISH_SENT,
    VPN_CLIENT_HANDSHAKE_STATE_ESTABLISHED,
    VPN_CLIENT_HANDSHAKE_STATE_CLOSING,
    VPN_CLIENT_HANDSHAKE_STATE_CLOSED,
    VPN_CLIENT_HANDSHAKE_STATE_FAILED
};

enum vpn_server_handshake_state {
    VPN_SERVER_HANDSHAKE_STATE_NO_SESSION,
    VPN_SERVER_HANDSHAKE_STATE_HELLO_RECEIVED,
    VPN_SERVER_HANDSHAKE_STATE_SERVER_HELLO_SENT,
    VPN_SERVER_HANDSHAKE_STATE_ESTABLISHED,
    VPN_SERVER_HANDSHAKE_STATE_CLOSING,
    VPN_SERVER_HANDSHAKE_STATE_CLOSED,
    VPN_SERVER_HANDSHAKE_STATE_FAILED
};

struct vpn_retry_policy {
    uint32_t initial_retry_ms;
    uint32_t max_retry_ms;
    uint32_t max_attempts;
};

struct vpn_handshake_context {
    uint64_t session_id;
    enum vpn_client_handshake_state client_state;
    enum vpn_server_handshake_state server_state;
    struct vpn_retry_policy retry_policy;
    uint32_t attempt_count;        /* Total transmission attempts (initial + retries) */
    uint64_t last_message_id;
    uint64_t last_accepted_message_id;  /* For duplicate detection */
    uint64_t handshake_deadline_ms;     /* Hard 10s handshake deadline (fixed at start) */
    uint64_t handshake_started_at_ms;   /* When handshake began */
    uint64_t next_retry_at_ms;          /* Next retry deadline */
    uint32_t client_nonce;
    uint32_t server_nonce;
    uint8_t key_exchange_context[32];
    uint8_t key_exchange_context_length;
    uint32_t handshake_timeout_ms;
    uint32_t keepalive_interval_ms;
    uint32_t session_idle_timeout_ms;
};

void vpn_handshake_context_init(struct vpn_handshake_context *ctx, uint64_t session_id);
int vpn_handshake_should_retry(const struct vpn_handshake_context *ctx);
int vpn_handshake_process_envelope(const struct vpn_protocol_envelope *envelope,
                                  struct vpn_handshake_context *ctx);

/* T046: Retry policy and timeout handling */
int vpn_handshake_advance_retry(struct vpn_handshake_context *ctx, uint64_t current_time_ms,
                                struct vpn_session_table *table);
int vpn_handshake_check_timeout(struct vpn_handshake_context *ctx, uint64_t current_time_ms,
                                struct vpn_session_table *table);
int vpn_handshake_on_handshake_start(struct vpn_handshake_context *ctx, uint64_t current_time_ms);

/* Duplicate/stale message handling */
int vpn_handshake_check_duplicate(const struct vpn_handshake_context *ctx, uint64_t message_id);
int vpn_handshake_accept_message(struct vpn_handshake_context *ctx, uint64_t message_id);

/* T038: Server-side virtual IP reservation helper */
int vpn_handshake_reserve_virtual_ip(struct vpn_session_table *table,
                                     uint64_t session_id,
                                     uint32_t virtual_ip);

#ifdef __cplusplus
}
#endif

#endif /* VPN_HANDSHAKE_H */
