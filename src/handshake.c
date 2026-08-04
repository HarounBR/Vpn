#include "vpn/handshake.h"

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
    (void)envelope;
    (void)ctx;
    return 0;
}
