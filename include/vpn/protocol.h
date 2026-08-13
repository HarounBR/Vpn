#ifndef VPN_PROTOCOL_H
#define VPN_PROTOCOL_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VPN_PROTOCOL_MAGIC 0x56504E20u /* "VPN " */
#define VPN_PROTOCOL_VERSION 1u
#define VPN_PROTOCOL_MAX_CLIENT_ID 64u
#define VPN_PROTOCOL_MAX_PAYLOAD_LENGTH 65535u
#define VPN_PROTOCOL_ENVELOPE_SIZE 22u

enum vpn_message_type {
    VPN_MSG_CLIENT_HELLO = 1,
    VPN_MSG_SERVER_HELLO = 2,
    VPN_MSG_CLIENT_FINISH = 3,
    VPN_MSG_SERVER_FINISH = 4,
    VPN_MSG_KEEPALIVE = 5,
    VPN_MSG_KEEPALIVE_ACK = 6,
    VPN_MSG_CLOSE = 7,
    VPN_MSG_REJECT = 255
};

enum vpn_rejection_code {
    VPN_REJECT_MALFORMED_MESSAGE = 1,
    VPN_REJECT_UNSUPPORTED_VERSION = 2,
    VPN_REJECT_INVALID_STATE = 3,
    VPN_REJECT_VIRTUAL_IP_CONFLICT = 4,
    VPN_REJECT_IDENTITY_CONFLICT = 5,
    VPN_REJECT_AUTHENTICATION_FAILED = 6,
    VPN_REJECT_REPLAY_OR_STALE_MESSAGE = 7,
    VPN_REJECT_TIMEOUT = 8
};

struct vpn_protocol_envelope {
    uint32_t magic;
    uint8_t version;
    uint8_t type;
    uint16_t flags;
    uint32_t message_id;
    uint64_t session_id;
    uint16_t payload_length;
};

/* The wire format uses a fixed 22-byte header in network byte order.
 * Do not use sizeof(struct vpn_protocol_envelope) for the on-wire header size.
 */

enum vpn_protocol_result {
    VPN_PROTOCOL_OK = 0,
    VPN_PROTOCOL_ERR_MALFORMED = -1,
    VPN_PROTOCOL_ERR_UNSUPPORTED_VERSION = -2,
    VPN_PROTOCOL_ERR_INVALID_TYPE = -3,
    VPN_PROTOCOL_ERR_UNSUPPORTED_FLAGS = -4,
    VPN_PROTOCOL_ERR_INSUFFICIENT_LENGTH = -5
};

size_t vpn_protocol_envelope_size(void);
int vpn_protocol_parse_envelope(const uint8_t *data, size_t length, struct vpn_protocol_envelope *out);
int vpn_protocol_validate_envelope(const struct vpn_protocol_envelope *envelope);

#ifdef __cplusplus
}
#endif

#endif /* VPN_PROTOCOL_H */
