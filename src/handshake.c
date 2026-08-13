#include "vpn/handshake.h"
#include <string.h>

static int apply_state_transition(struct vpn_handshake_context *ctx,
                                  enum vpn_client_handshake_state client_state,
                                  enum vpn_server_handshake_state server_state)
{
    if (!ctx) {
        return -1;
    }

    ctx->client_state = client_state;
    ctx->server_state = server_state;
    return 0;
}

void vpn_handshake_context_init(struct vpn_handshake_context *ctx, uint64_t session_id)
{
    if (!ctx) {
        return;
    }

    ctx->session_id = session_id;
    ctx->client_state = VPN_CLIENT_HANDSHAKE_STATE_IDLE;
    ctx->server_state = VPN_SERVER_HANDSHAKE_STATE_NO_SESSION;
    ctx->retry_policy.initial_retry_ms = 1000;
    ctx->retry_policy.max_retry_ms = 4000;
    ctx->retry_policy.max_attempts = 4;
    ctx->retry_count = 0;
    ctx->last_message_id = 0;
    ctx->expires_at_ms = 0;
    ctx->client_nonce = 0;
    ctx->server_nonce = 0;
    ctx->key_exchange_context_length = 0;
    memset(ctx->key_exchange_context, 0, sizeof(ctx->key_exchange_context));
    ctx->handshake_timeout_ms = 10000u;
    ctx->keepalive_interval_ms = 15000u;
    ctx->session_idle_timeout_ms = 45000u;
}

int vpn_handshake_should_retry(const struct vpn_handshake_context *ctx)
{
    if (!ctx) {
        return 0;
    }

    return ctx->retry_count < ctx->retry_policy.max_attempts;
}

int vpn_handshake_process_envelope(const struct vpn_protocol_envelope *envelope,
                                  struct vpn_handshake_context *ctx)
{
    if (!envelope || !ctx) {
        return -1;
    }

    if (vpn_protocol_validate_envelope(envelope) != VPN_PROTOCOL_OK) {
        return -1;
    }

    ctx->last_message_id = envelope->message_id;

    switch (envelope->type) {
    case VPN_MSG_CLIENT_HELLO:
        if (envelope->session_id != 0u) {
            return -1;
        }
        if (ctx->client_state != VPN_CLIENT_HANDSHAKE_STATE_IDLE ||
            ctx->server_state != VPN_SERVER_HANDSHAKE_STATE_NO_SESSION) {
            return -1;
        }
        return apply_state_transition(ctx,
                                      VPN_CLIENT_HANDSHAKE_STATE_HELLO_SENT,
                                      VPN_SERVER_HANDSHAKE_STATE_HELLO_RECEIVED);
    case VPN_MSG_SERVER_HELLO:
        if (envelope->session_id == 0u) {
            return -1;
        }
        if (ctx->session_id != 0u && envelope->session_id != ctx->session_id) {
            return -1;
        }
        if (ctx->client_state != VPN_CLIENT_HANDSHAKE_STATE_HELLO_SENT ||
            ctx->server_state != VPN_SERVER_HANDSHAKE_STATE_HELLO_RECEIVED) {
            return -1;
        }
        ctx->session_id = envelope->session_id;
        return apply_state_transition(ctx,
                                      VPN_CLIENT_HANDSHAKE_STATE_FINISH_SENT,
                                      VPN_SERVER_HANDSHAKE_STATE_SERVER_HELLO_SENT);
    case VPN_MSG_CLIENT_FINISH:
        if (envelope->session_id != 0u && envelope->session_id != ctx->session_id) {
            return -1;
        }
        if (ctx->client_state != VPN_CLIENT_HANDSHAKE_STATE_FINISH_SENT ||
            ctx->server_state != VPN_SERVER_HANDSHAKE_STATE_SERVER_HELLO_SENT) {
            return -1;
        }
        return apply_state_transition(ctx,
                                      VPN_CLIENT_HANDSHAKE_STATE_ESTABLISHED,
                                      VPN_SERVER_HANDSHAKE_STATE_ESTABLISHED);
    case VPN_MSG_SERVER_FINISH:
        if (envelope->session_id != 0u && envelope->session_id != ctx->session_id) {
            return -1;
        }
        if (ctx->client_state != VPN_CLIENT_HANDSHAKE_STATE_FINISH_SENT ||
            ctx->server_state != VPN_SERVER_HANDSHAKE_STATE_SERVER_HELLO_SENT) {
            return -1;
        }
        return apply_state_transition(ctx,
                                      VPN_CLIENT_HANDSHAKE_STATE_ESTABLISHED,
                                      VPN_SERVER_HANDSHAKE_STATE_ESTABLISHED);
    case VPN_MSG_KEEPALIVE:
    case VPN_MSG_KEEPALIVE_ACK:
    case VPN_MSG_CLOSE:
    case VPN_MSG_REJECT:
        if (envelope->session_id != 0u && envelope->session_id != ctx->session_id) {
            return -1;
        }
        return 0;
    default:
        return -1;
    }
}
