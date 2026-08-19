#include "vpn/handshake.h"
#include "vpn/session.h"
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
    ctx->retry_policy.initial_retry_ms = VPN_RETRY_ONE_MS;
    ctx->retry_policy.max_retry_ms = VPN_RETRY_MAX_MS;
    ctx->retry_policy.max_attempts = VPN_MAX_HANDSHAKE_ATTEMPTS;
    ctx->attempt_count = 0;
    ctx->last_message_id = 0;
    ctx->last_accepted_message_id = 0;
    ctx->handshake_deadline_ms = 0;
    ctx->handshake_started_at_ms = 0;
    ctx->next_retry_at_ms = 0;
    ctx->client_nonce = 0;
    ctx->server_nonce = 0;
    ctx->key_exchange_context_length = 0;
    memset(ctx->key_exchange_context, 0, sizeof(ctx->key_exchange_context));
    ctx->handshake_timeout_ms = VPN_HANDSHAKE_TIMEOUT_MS;
    ctx->keepalive_interval_ms = VPN_KEEPALIVE_INTERVAL_MS;
    ctx->session_idle_timeout_ms = VPN_SESSION_IDLE_TIMEOUT_MS;
}

int vpn_handshake_should_retry(const struct vpn_handshake_context *ctx)
{
    if (!ctx) {
        return 0;
    }

    return ctx->attempt_count < ctx->retry_policy.max_attempts;
}

int vpn_handshake_on_handshake_start(struct vpn_handshake_context *ctx, uint64_t current_time_ms)
{
    if (!ctx) {
        return -1;
    }

    if (ctx->attempt_count == 0) {
        ctx->handshake_started_at_ms = current_time_ms;
        ctx->handshake_deadline_ms = current_time_ms + ctx->handshake_timeout_ms;
        ctx->attempt_count = 1;
        ctx->next_retry_at_ms = current_time_ms + ctx->retry_policy.initial_retry_ms;
    }
    return 0;
}

int vpn_handshake_check_duplicate(const struct vpn_handshake_context *ctx, uint64_t message_id)
{
    if (!ctx) {
        return -1;
    }

    if (message_id == 0) {
        return 0;
    }

    if (message_id <= ctx->last_accepted_message_id) {
        return 1;
    }

    return 0;
}

int vpn_handshake_accept_message(struct vpn_handshake_context *ctx, uint64_t message_id)
{
    if (!ctx) {
        return -1;
    }

    if (message_id == 0) {
        return -1;
    }

    ctx->last_accepted_message_id = message_id;
    ctx->last_message_id = message_id;
    return 0;
}

static int cleanup_failed_handshake(struct vpn_handshake_context *ctx,
                                    struct vpn_session_table *table)
{
    if (!ctx || !table) {
        return -1;
    }

    ctx->client_state = VPN_CLIENT_HANDSHAKE_STATE_FAILED;
    ctx->server_state = VPN_SERVER_HANDSHAKE_STATE_FAILED;
    ctx->next_retry_at_ms = 0u;
    ctx->handshake_deadline_ms = 0u;

    if (vpn_session_table_cleanup_session(table, ctx->session_id) == VPN_SESSION_ERR_NOT_FOUND) {
        return VPN_SESSION_OK;
    }

    return VPN_SESSION_OK;
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

    if (vpn_handshake_check_duplicate(ctx, envelope->message_id)) {
        return 0;
    }

    if (envelope->session_id != 0u && ctx->session_id != 0u && envelope->session_id != ctx->session_id) {
        return -1;
    }

    switch (envelope->type) {
    case VPN_MSG_CLIENT_HELLO:
        if (envelope->session_id != 0u) {
            return -1;
        }
        if (ctx->client_state != VPN_CLIENT_HANDSHAKE_STATE_IDLE ||
            ctx->server_state != VPN_SERVER_HANDSHAKE_STATE_NO_SESSION) {
            return ctx->client_state == VPN_CLIENT_HANDSHAKE_STATE_HELLO_SENT ||
                   ctx->client_state == VPN_CLIENT_HANDSHAKE_STATE_FINISH_SENT ||
                   ctx->client_state == VPN_CLIENT_HANDSHAKE_STATE_ESTABLISHED ? 0 : -1;
        }
        if (vpn_handshake_accept_message(ctx, envelope->message_id) != 0) {
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
            return ctx->client_state == VPN_CLIENT_HANDSHAKE_STATE_FINISH_SENT ||
                   ctx->client_state == VPN_CLIENT_HANDSHAKE_STATE_ESTABLISHED ? 0 : -1;
        }
        ctx->session_id = envelope->session_id;
        if (vpn_handshake_accept_message(ctx, envelope->message_id) != 0) {
            return -1;
        }
        return apply_state_transition(ctx,
                                      VPN_CLIENT_HANDSHAKE_STATE_FINISH_SENT,
                                      VPN_SERVER_HANDSHAKE_STATE_SERVER_HELLO_SENT);
    case VPN_MSG_CLIENT_FINISH:
        if (envelope->session_id == 0u || envelope->session_id != ctx->session_id) {
            return -1;
        }
        if (ctx->server_state != VPN_SERVER_HANDSHAKE_STATE_SERVER_HELLO_SENT) {
            return ctx->server_state == VPN_SERVER_HANDSHAKE_STATE_ESTABLISHED ? 0 : -1;
        }
        if (vpn_handshake_accept_message(ctx, envelope->message_id) != 0) {
            return -1;
        }
        ctx->server_state = VPN_SERVER_HANDSHAKE_STATE_ESTABLISHED;
        return 0;
    case VPN_MSG_SERVER_FINISH:
        if (envelope->session_id == 0u || envelope->session_id != ctx->session_id) {
            return -1;
        }
        if (ctx->client_state != VPN_CLIENT_HANDSHAKE_STATE_FINISH_SENT) {
            return ctx->client_state == VPN_CLIENT_HANDSHAKE_STATE_ESTABLISHED ? 0 : -1;
        }
        if (vpn_handshake_accept_message(ctx, envelope->message_id) != 0) {
            return -1;
        }
        ctx->client_state = VPN_CLIENT_HANDSHAKE_STATE_ESTABLISHED;
        return 0;
    case VPN_MSG_KEEPALIVE:
    case VPN_MSG_KEEPALIVE_ACK:
    case VPN_MSG_CLOSE:
    case VPN_MSG_REJECT:
        if (envelope->session_id != 0u && envelope->session_id != ctx->session_id) {
            return -1;
        }
        if (vpn_handshake_accept_message(ctx, envelope->message_id) != 0) {
            return -1;
        }
        return 0;
    default:
        return -1;
    }
}

int vpn_handshake_check_timeout(struct vpn_handshake_context *ctx, uint64_t current_time_ms,
                                struct vpn_session_table *table)
{
    if (!ctx || !table) {
        return -1;
    }

    if (ctx->handshake_deadline_ms != 0u && current_time_ms >= ctx->handshake_deadline_ms) {
        cleanup_failed_handshake(ctx, table);
        return -1;
    }

    return 0;
}

int vpn_handshake_advance_retry(struct vpn_handshake_context *ctx, uint64_t current_time_ms,
                                struct vpn_session_table *table)
{
    if (!ctx || !table) {
        return -1;
    }

    if (ctx->handshake_deadline_ms != 0u && current_time_ms >= ctx->handshake_deadline_ms) {
        cleanup_failed_handshake(ctx, table);
        return -1;
    }

    if (ctx->next_retry_at_ms != 0u && current_time_ms < ctx->next_retry_at_ms) {
        return 0;
    }

    if (ctx->attempt_count >= ctx->retry_policy.max_attempts) {
        cleanup_failed_handshake(ctx, table);
        return -1;
    }

    ctx->attempt_count++;

    if (ctx->attempt_count == ctx->retry_policy.max_attempts) {
        ctx->next_retry_at_ms = 0u;
        return 0;
    }

    uint64_t next_retry_at_ms = ctx->handshake_started_at_ms +
                                (ctx->attempt_count == 2u ? VPN_RETRY_TWO_AT_MS : VPN_RETRY_THREE_AT_MS);
    if (ctx->handshake_deadline_ms != 0u && next_retry_at_ms >= ctx->handshake_deadline_ms) {
        cleanup_failed_handshake(ctx, table);
        return -1;
    }

    ctx->next_retry_at_ms = next_retry_at_ms;

    return 0;
}

int vpn_handshake_reserve_virtual_ip(struct vpn_session_table *table,
                                     uint64_t session_id,
                                     uint32_t virtual_ip)
{
    return vpn_session_table_assign_virtual_ip(table, session_id, virtual_ip);
}
