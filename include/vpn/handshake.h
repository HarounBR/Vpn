#ifndef VPN_HANDSHAKE_H
#define VPN_HANDSHAKE_H

#include <stdint.h>
#include <stddef.h>
#include "vpn/protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

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
    uint32_t retry_count;
    uint64_t last_message_id;
    uint64_t expires_at_ms;
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

#ifdef __cplusplus
}
#endif

#endif /* VPN_HANDSHAKE_H */
