#include "vpn/protocol.h"
#include <string.h>
#include <arpa/inet.h>

size_t vpn_protocol_envelope_size(void)
{
    return VPN_PROTOCOL_ENVELOPE_SIZE;
}

static uint32_t vpn_protocol_read_u32(const uint8_t *data)
{
    uint32_t value;
    memcpy(&value, data, sizeof(value));
    return ntohl(value);
}

static uint64_t vpn_protocol_read_u64(const uint8_t *data)
{
    uint32_t high, low;
    memcpy(&high, data, sizeof(high));
    memcpy(&low, data + 4, sizeof(low));
    return ((uint64_t)ntohl(high) << 32) | ntohl(low);
}

static void vpn_protocol_write_u32(uint8_t *data, uint32_t value)
{
    uint32_t network_value = htonl(value);
    memcpy(data, &network_value, sizeof(network_value));
}

static void vpn_protocol_write_u64(uint8_t *data, uint64_t value)
{
    uint32_t high = htonl((uint32_t)(value >> 32));
    uint32_t low = htonl((uint32_t)value);
    memcpy(data, &high, sizeof(high));
    memcpy(data + 4, &low, sizeof(low));
}

int vpn_protocol_parse_envelope(const uint8_t *data, size_t length, struct vpn_protocol_envelope *out)
{
    if (!data || !out) {
        return VPN_PROTOCOL_ERR_MALFORMED;
    }

    size_t header_size = vpn_protocol_envelope_size();
    if (length < header_size) {
        return VPN_PROTOCOL_ERR_INSUFFICIENT_LENGTH;
    }

    uint16_t raw_flags;
    uint16_t raw_payload_length;

    out->magic = vpn_protocol_read_u32(data);
    out->version = data[4];
    out->type = data[5];
    memcpy(&raw_flags, data + 6, sizeof(raw_flags));
    out->flags = ntohs(raw_flags);
    out->message_id = vpn_protocol_read_u32(data + 8);
    out->session_id = vpn_protocol_read_u64(data + 12);
    memcpy(&raw_payload_length, data + 20, sizeof(raw_payload_length));
    out->payload_length = ntohs(raw_payload_length);

    if (length != header_size + out->payload_length) {
        return VPN_PROTOCOL_ERR_MALFORMED;
    }

    return vpn_protocol_validate_envelope(out);
}

int vpn_protocol_validate_envelope(const struct vpn_protocol_envelope *envelope)
{
    if (!envelope) {
        return VPN_PROTOCOL_ERR_MALFORMED;
    }

    if (envelope->magic != VPN_PROTOCOL_MAGIC) {
        return VPN_PROTOCOL_ERR_MALFORMED;
    }

    if (envelope->version != VPN_PROTOCOL_VERSION) {
        return VPN_PROTOCOL_ERR_UNSUPPORTED_VERSION;
    }

    if (envelope->flags != 0) {
        return VPN_PROTOCOL_ERR_UNSUPPORTED_FLAGS;
    }

    switch (envelope->type) {
    case VPN_MSG_CLIENT_HELLO:
    case VPN_MSG_SERVER_HELLO:
    case VPN_MSG_CLIENT_FINISH:
    case VPN_MSG_SERVER_FINISH:
    case VPN_MSG_KEEPALIVE:
    case VPN_MSG_KEEPALIVE_ACK:
    case VPN_MSG_CLOSE:
    case VPN_MSG_REJECT:
        break;
    default:
        return VPN_PROTOCOL_ERR_INVALID_TYPE;
    }

    (void)envelope;
    return VPN_PROTOCOL_OK;
}

/* T021: Envelope encode/decode */
int vpn_protocol_encode_envelope(uint8_t *data, size_t length, const struct vpn_protocol_envelope *envelope)
{
    if (!data || !envelope) {
        return VPN_PROTOCOL_ERR_MALFORMED;
    }

    size_t header_size = vpn_protocol_envelope_size();
    if (length < header_size + envelope->payload_length) {
        return VPN_PROTOCOL_ERR_INSUFFICIENT_LENGTH;
    }

    if (vpn_protocol_validate_envelope(envelope) != VPN_PROTOCOL_OK) {
        return VPN_PROTOCOL_ERR_MALFORMED;
    }

    vpn_protocol_write_u32(data, envelope->magic);
    data[4] = envelope->version;
    data[5] = envelope->type;

    uint16_t raw_flags = htons(envelope->flags);
    memcpy(data + 6, &raw_flags, sizeof(raw_flags));

    vpn_protocol_write_u32(data + 8, envelope->message_id);
    vpn_protocol_write_u64(data + 12, envelope->session_id);

    uint16_t raw_payload_length = htons(envelope->payload_length);
    memcpy(data + 20, &raw_payload_length, sizeof(raw_payload_length));

    return (int)(header_size + envelope->payload_length);
}

/* T022: CLIENT_HELLO payload encode/decode */
int vpn_protocol_encode_client_hello(uint8_t *data, size_t length, const struct vpn_protocol_client_hello *hello)
{
    if (!data || !hello) {
        return VPN_PROTOCOL_ERR_MALFORMED;
    }

    if (hello->client_id_length == 0 || hello->client_id_length > VPN_PROTOCOL_MAX_CLIENT_ID) {
        return VPN_PROTOCOL_ERR_MALFORMED;
    }

    if (hello->key_exchange_length > sizeof(hello->key_exchange_bytes)) {
        return VPN_PROTOCOL_ERR_MALFORMED;
    }

    size_t required_length = 1 + hello->client_id_length + 4 + 4 + 2 + hello->key_exchange_length;
    if (length < required_length) {
        return VPN_PROTOCOL_ERR_INSUFFICIENT_LENGTH;
    }

    size_t offset = 0;
    data[offset++] = hello->client_id_length;
    memcpy(data + offset, hello->client_id, hello->client_id_length);
    offset += hello->client_id_length;

    vpn_protocol_write_u32(data + offset, hello->requested_virtual_ip);
    offset += 4;

    vpn_protocol_write_u32(data + offset, hello->client_nonce);
    offset += 4;

    uint16_t raw_kex_len = htons(hello->key_exchange_length);
    memcpy(data + offset, &raw_kex_len, sizeof(raw_kex_len));
    offset += 2;

    memcpy(data + offset, hello->key_exchange_bytes, hello->key_exchange_length);
    offset += hello->key_exchange_length;

    return (int)offset;
}

int vpn_protocol_parse_client_hello(const uint8_t *data, size_t length, struct vpn_protocol_client_hello *out)
{
    if (!data || !out || length < 1) {
        return VPN_PROTOCOL_ERR_MALFORMED;
    }

    size_t offset = 0;
    out->client_id_length = data[offset++];

    if (out->client_id_length == 0 || out->client_id_length > VPN_PROTOCOL_MAX_CLIENT_ID) {
        return VPN_PROTOCOL_ERR_MALFORMED;
    }

    if (length < offset + out->client_id_length + 4 + 4 + 2) {
        return VPN_PROTOCOL_ERR_INSUFFICIENT_LENGTH;
    }

    memcpy(out->client_id, data + offset, out->client_id_length);
    offset += out->client_id_length;

    out->requested_virtual_ip = vpn_protocol_read_u32(data + offset);
    offset += 4;

    out->client_nonce = vpn_protocol_read_u32(data + offset);
    offset += 4;

    uint16_t raw_kex_len;
    memcpy(&raw_kex_len, data + offset, sizeof(raw_kex_len));
    out->key_exchange_length = ntohs(raw_kex_len);
    offset += 2;

    if (length < offset + out->key_exchange_length) {
        return VPN_PROTOCOL_ERR_INSUFFICIENT_LENGTH;
    }

    if (out->key_exchange_length > sizeof(out->key_exchange_bytes)) {
        return VPN_PROTOCOL_ERR_MALFORMED;
    }

    memcpy(out->key_exchange_bytes, data + offset, out->key_exchange_length);
    offset += out->key_exchange_length;

    return (int)offset;
}

/* SERVER_HELLO payload encode/decode */
int vpn_protocol_encode_server_hello(uint8_t *data, size_t length, const struct vpn_protocol_server_hello *hello)
{
    if (!data || !hello) {
        return VPN_PROTOCOL_ERR_MALFORMED;
    }

    if (hello->session_id == 0) {
        return VPN_PROTOCOL_ERR_MALFORMED;
    }

    if (hello->key_exchange_length > sizeof(hello->key_exchange_bytes)) {
        return VPN_PROTOCOL_ERR_MALFORMED;
    }

    size_t required_length = 8 + 4 + 4 + 1 + 4 + 2 + hello->key_exchange_length;
    if (length < required_length) {
        return VPN_PROTOCOL_ERR_INSUFFICIENT_LENGTH;
    }

    size_t offset = 0;
    vpn_protocol_write_u64(data + offset, hello->session_id);
    offset += 8;

    vpn_protocol_write_u32(data + offset, hello->assigned_virtual_ip);
    offset += 4;

    vpn_protocol_write_u32(data + offset, hello->server_nonce);
    offset += 4;

    data[offset++] = hello->retry_policy_id;

    vpn_protocol_write_u32(data + offset, hello->lifetime_hint_ms);
    offset += 4;

    uint16_t raw_kex_len = htons(hello->key_exchange_length);
    memcpy(data + offset, &raw_kex_len, sizeof(raw_kex_len));
    offset += 2;

    memcpy(data + offset, hello->key_exchange_bytes, hello->key_exchange_length);
    offset += hello->key_exchange_length;

    return (int)offset;
}

int vpn_protocol_parse_server_hello(const uint8_t *data, size_t length, struct vpn_protocol_server_hello *out)
{
    if (!data || !out || length < 8 + 4 + 4 + 1 + 4 + 2) {
        return VPN_PROTOCOL_ERR_INSUFFICIENT_LENGTH;
    }

    size_t offset = 0;
    out->session_id = vpn_protocol_read_u64(data + offset);
    offset += 8;

    if (out->session_id == 0) {
        return VPN_PROTOCOL_ERR_MALFORMED;
    }

    out->assigned_virtual_ip = vpn_protocol_read_u32(data + offset);
    offset += 4;

    out->server_nonce = vpn_protocol_read_u32(data + offset);
    offset += 4;

    out->retry_policy_id = data[offset++];

    out->lifetime_hint_ms = vpn_protocol_read_u32(data + offset);
    offset += 4;

    uint16_t raw_kex_len;
    memcpy(&raw_kex_len, data + offset, sizeof(raw_kex_len));
    out->key_exchange_length = ntohs(raw_kex_len);
    offset += 2;

    if (length < offset + out->key_exchange_length) {
        return VPN_PROTOCOL_ERR_INSUFFICIENT_LENGTH;
    }

    if (out->key_exchange_length > sizeof(out->key_exchange_bytes)) {
        return VPN_PROTOCOL_ERR_MALFORMED;
    }

    memcpy(out->key_exchange_bytes, data + offset, out->key_exchange_length);
    offset += out->key_exchange_length;

    return (int)offset;
}

/* T023: CLIENT_FINISH and SERVER_FINISH payload encode/decode */
int vpn_protocol_encode_client_finish(uint8_t *data, size_t length, const struct vpn_protocol_client_finish *finish)
{
    if (!data || !finish) {
        return VPN_PROTOCOL_ERR_MALFORMED;
    }

    if (finish->session_id == 0) {
        return VPN_PROTOCOL_ERR_MALFORMED;
    }

    if (finish->key_exchange_length > sizeof(finish->key_exchange_bytes)) {
        return VPN_PROTOCOL_ERR_MALFORMED;
    }

    size_t required_length = 8 + 2 + finish->key_exchange_length;
    if (length < required_length) {
        return VPN_PROTOCOL_ERR_INSUFFICIENT_LENGTH;
    }

    size_t offset = 0;
    vpn_protocol_write_u64(data + offset, finish->session_id);
    offset += 8;

    uint16_t raw_kex_len = htons(finish->key_exchange_length);
    memcpy(data + offset, &raw_kex_len, sizeof(raw_kex_len));
    offset += 2;

    memcpy(data + offset, finish->key_exchange_bytes, finish->key_exchange_length);
    offset += finish->key_exchange_length;

    return (int)offset;
}

int vpn_protocol_parse_client_finish(const uint8_t *data, size_t length, struct vpn_protocol_client_finish *out)
{
    if (!data || !out || length < 8 + 2) {
        return VPN_PROTOCOL_ERR_INSUFFICIENT_LENGTH;
    }

    size_t offset = 0;
    out->session_id = vpn_protocol_read_u64(data + offset);
    offset += 8;

    uint16_t raw_kex_len;
    memcpy(&raw_kex_len, data + offset, sizeof(raw_kex_len));
    out->key_exchange_length = ntohs(raw_kex_len);
    offset += 2;

    if (length < offset + out->key_exchange_length) {
        return VPN_PROTOCOL_ERR_INSUFFICIENT_LENGTH;
    }

    if (out->key_exchange_length > sizeof(out->key_exchange_bytes)) {
        return VPN_PROTOCOL_ERR_MALFORMED;
    }

    memcpy(out->key_exchange_bytes, data + offset, out->key_exchange_length);
    offset += out->key_exchange_length;

    return (int)offset;
}

int vpn_protocol_encode_server_finish(uint8_t *data, size_t length, const struct vpn_protocol_server_finish *finish)
{
    if (!data || !finish) {
        return VPN_PROTOCOL_ERR_MALFORMED;
    }

    if (finish->session_id == 0) {
        return VPN_PROTOCOL_ERR_MALFORMED;
    }

    if (finish->key_exchange_length > sizeof(finish->key_exchange_bytes)) {
        return VPN_PROTOCOL_ERR_MALFORMED;
    }

    size_t required_length = 8 + 2 + finish->key_exchange_length;
    if (length < required_length) {
        return VPN_PROTOCOL_ERR_INSUFFICIENT_LENGTH;
    }

    size_t offset = 0;
    vpn_protocol_write_u64(data + offset, finish->session_id);
    offset += 8;

    uint16_t raw_kex_len = htons(finish->key_exchange_length);
    memcpy(data + offset, &raw_kex_len, sizeof(raw_kex_len));
    offset += 2;

    memcpy(data + offset, finish->key_exchange_bytes, finish->key_exchange_length);
    offset += finish->key_exchange_length;

    return (int)offset;
}

int vpn_protocol_parse_server_finish(const uint8_t *data, size_t length, struct vpn_protocol_server_finish *out)
{
    if (!data || !out || length < 8 + 2) {
        return VPN_PROTOCOL_ERR_INSUFFICIENT_LENGTH;
    }

    size_t offset = 0;
    out->session_id = vpn_protocol_read_u64(data + offset);
    offset += 8;

    uint16_t raw_kex_len;
    memcpy(&raw_kex_len, data + offset, sizeof(raw_kex_len));
    out->key_exchange_length = ntohs(raw_kex_len);
    offset += 2;

    if (length < offset + out->key_exchange_length) {
        return VPN_PROTOCOL_ERR_INSUFFICIENT_LENGTH;
    }

    if (out->key_exchange_length > sizeof(out->key_exchange_bytes)) {
        return VPN_PROTOCOL_ERR_MALFORMED;
    }

    memcpy(out->key_exchange_bytes, data + offset, out->key_exchange_length);
    offset += out->key_exchange_length;

    return (int)offset;
}
/* T049: KEEPALIVE encode/decode */
int vpn_protocol_encode_keepalive(uint8_t *data, size_t length, const struct vpn_protocol_keepalive *keepalive)
{
    if (!data || !keepalive) {
        return VPN_PROTOCOL_ERR_MALFORMED;
    }

    if (keepalive->session_id == 0u) {
        return VPN_PROTOCOL_ERR_MALFORMED;
    }

    size_t required_length = 8 + 8 + 1 + keepalive->authenticator_length;  /* session_id + timestamp_ms + auth_len + authenticator */
    if (length < required_length) {
        return VPN_PROTOCOL_ERR_INSUFFICIENT_LENGTH;
    }

    if (keepalive->authenticator_length > sizeof(keepalive->authenticator)) {
        return VPN_PROTOCOL_ERR_MALFORMED;
    }

    size_t offset = 0;
    vpn_protocol_write_u64(data + offset, keepalive->session_id);
    offset += 8;

    vpn_protocol_write_u64(data + offset, keepalive->timestamp_ms);
    offset += 8;

    data[offset++] = keepalive->authenticator_length;
    if (keepalive->authenticator_length > 0) {
        memcpy(data + offset, keepalive->authenticator, keepalive->authenticator_length);
        offset += keepalive->authenticator_length;
    }

    return (int)offset;
}

int vpn_protocol_parse_keepalive(const uint8_t *data, size_t length, struct vpn_protocol_keepalive *out)
{
    if (!data || !out || length < 8 + 8 + 1) {
        return VPN_PROTOCOL_ERR_INSUFFICIENT_LENGTH;
    }

    size_t offset = 0;
    out->session_id = vpn_protocol_read_u64(data + offset);
    offset += 8;

    out->timestamp_ms = vpn_protocol_read_u64(data + offset);
    offset += 8;

    out->authenticator_length = data[offset++];
    if (out->authenticator_length > sizeof(out->authenticator)) {
        return VPN_PROTOCOL_ERR_MALFORMED;
    }

    if (length < offset + out->authenticator_length) {
        return VPN_PROTOCOL_ERR_INSUFFICIENT_LENGTH;
    }

    if (out->authenticator_length > 0) {
        memcpy(out->authenticator, data + offset, out->authenticator_length);
        offset += out->authenticator_length;
    } else {
        memset(out->authenticator, 0, sizeof(out->authenticator));
    }

    return (int)offset;
}

/* KEEPALIVE_ACK encode/decode */
int vpn_protocol_encode_keepalive_ack(uint8_t *data, size_t length, const struct vpn_protocol_keepalive_ack *ack)
{
    if (!data || !ack) {
        return VPN_PROTOCOL_ERR_MALFORMED;
    }

    if (ack->session_id == 0u) {
        return VPN_PROTOCOL_ERR_MALFORMED;
    }

    size_t required_length = 8 + 8 + 1 + ack->authenticator_length;  /* session_id + original_timestamp_ms + auth_len + authenticator */
    if (length < required_length) {
        return VPN_PROTOCOL_ERR_INSUFFICIENT_LENGTH;
    }

    if (ack->authenticator_length > sizeof(ack->authenticator)) {
        return VPN_PROTOCOL_ERR_MALFORMED;
    }

    size_t offset = 0;
    vpn_protocol_write_u64(data + offset, ack->session_id);
    offset += 8;

    vpn_protocol_write_u64(data + offset, ack->original_timestamp_ms);
    offset += 8;

    data[offset++] = ack->authenticator_length;
    if (ack->authenticator_length > 0) {
        memcpy(data + offset, ack->authenticator, ack->authenticator_length);
        offset += ack->authenticator_length;
    }

    return (int)offset;
}

int vpn_protocol_parse_keepalive_ack(const uint8_t *data, size_t length, struct vpn_protocol_keepalive_ack *out)
{
    if (!data || !out || length < 8 + 8 + 1) {
        return VPN_PROTOCOL_ERR_INSUFFICIENT_LENGTH;
    }

    size_t offset = 0;
    out->session_id = vpn_protocol_read_u64(data + offset);
    offset += 8;

    out->original_timestamp_ms = vpn_protocol_read_u64(data + offset);
    offset += 8;

    out->authenticator_length = data[offset++];
    if (out->authenticator_length > sizeof(out->authenticator)) {
        return VPN_PROTOCOL_ERR_MALFORMED;
    }

    if (length < offset + out->authenticator_length) {
        return VPN_PROTOCOL_ERR_INSUFFICIENT_LENGTH;
    }

    if (out->authenticator_length > 0) {
        memcpy(out->authenticator, data + offset, out->authenticator_length);
        offset += out->authenticator_length;
    } else {
        memset(out->authenticator, 0, sizeof(out->authenticator));
    }

    return (int)offset;
}

/* CLOSE encode/decode */
int vpn_protocol_encode_close(uint8_t *data, size_t length, const struct vpn_protocol_close *close)
{
    if (!data || !close) {
        return VPN_PROTOCOL_ERR_MALFORMED;
    }

    if (close->session_id == 0u) {
        return VPN_PROTOCOL_ERR_MALFORMED;
    }

    size_t required_length = 8 + 1 + 1 + close->authenticator_length;  /* session_id + reason + auth_len + authenticator */
    if (length < required_length) {
        return VPN_PROTOCOL_ERR_INSUFFICIENT_LENGTH;
    }

    if (close->authenticator_length > sizeof(close->authenticator)) {
        return VPN_PROTOCOL_ERR_MALFORMED;
    }

    size_t offset = 0;
    vpn_protocol_write_u64(data + offset, close->session_id);
    offset += 8;

    data[offset++] = close->reason;

    data[offset++] = close->authenticator_length;
    if (close->authenticator_length > 0) {
        memcpy(data + offset, close->authenticator, close->authenticator_length);
        offset += close->authenticator_length;
    }

    return (int)offset;
}

int vpn_protocol_parse_close(const uint8_t *data, size_t length, struct vpn_protocol_close *out)
{
    if (!data || !out || length < 8 + 1 + 1) {
        return VPN_PROTOCOL_ERR_INSUFFICIENT_LENGTH;
    }

    size_t offset = 0;
    out->session_id = vpn_protocol_read_u64(data + offset);
    offset += 8;

    out->reason = data[offset++];

    out->authenticator_length = data[offset++];
    if (out->authenticator_length > sizeof(out->authenticator)) {
        return VPN_PROTOCOL_ERR_MALFORMED;
    }

    if (length < offset + out->authenticator_length) {
        return VPN_PROTOCOL_ERR_INSUFFICIENT_LENGTH;
    }

    if (out->authenticator_length > 0) {
        memcpy(out->authenticator, data + offset, out->authenticator_length);
        offset += out->authenticator_length;
    } else {
        memset(out->authenticator, 0, sizeof(out->authenticator));
    }

    return (int)offset;
}

/* REJECT encode/decode */
int vpn_protocol_encode_reject(uint8_t *data, size_t length, const struct vpn_protocol_reject *reject)
{
    if (!data || !reject) {
        return VPN_PROTOCOL_ERR_MALFORMED;
    }

    size_t required_length = 8 + 1 + 8;  /* session_id + rejection_code + failed_message_id */
    if (length < required_length) {
        return VPN_PROTOCOL_ERR_INSUFFICIENT_LENGTH;
    }

    size_t offset = 0;
    vpn_protocol_write_u64(data + offset, reject->session_id);
    offset += 8;

    data[offset++] = reject->rejection_code;

    vpn_protocol_write_u64(data + offset, reject->failed_message_id);
    offset += 8;

    return (int)offset;
}

int vpn_protocol_parse_reject(const uint8_t *data, size_t length, struct vpn_protocol_reject *out)
{
    if (!data || !out || length < 8 + 1 + 8) {
        return VPN_PROTOCOL_ERR_INSUFFICIENT_LENGTH;
    }

    size_t offset = 0;
    out->session_id = vpn_protocol_read_u64(data + offset);
    offset += 8;

    out->rejection_code = data[offset++];

    out->failed_message_id = vpn_protocol_read_u64(data + offset);
    offset += 8;

    return (int)offset;
}
