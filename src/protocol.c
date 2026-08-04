#include "vpn/protocol.h"
#include <string.h>
#include <arpa/inet.h>

size_t vpn_protocol_envelope_size(void)
{
    return sizeof(struct vpn_protocol_envelope);
}

static uint32_t vpn_protocol_read_u32(const uint8_t *data)
{
    uint32_t value;
    memcpy(&value, data, sizeof(value));
    return ntohl(value);
}

static uint64_t vpn_protocol_read_u64(const uint8_t *data)
{
    uint64_t value;
    memcpy(&value, data, sizeof(value));
    return ((uint64_t)ntohl((uint32_t)(value >> 32)) << 32) | ntohl((uint32_t)value);
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
