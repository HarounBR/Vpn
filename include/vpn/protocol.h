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

/* Payload structures for handshake messages */

struct vpn_protocol_client_hello {
    uint8_t client_id_length;
    uint8_t client_id[VPN_PROTOCOL_MAX_CLIENT_ID];
    uint32_t requested_virtual_ip;
    uint32_t client_nonce;
    uint16_t key_exchange_length;
    uint8_t key_exchange_bytes[256];
};

struct vpn_protocol_server_hello {
    uint64_t session_id;
    uint32_t assigned_virtual_ip;
    uint32_t server_nonce;
    uint8_t retry_policy_id;
    uint32_t lifetime_hint_ms;
    uint16_t key_exchange_length;
    uint8_t key_exchange_bytes[256];
};

struct vpn_protocol_client_finish {
    uint64_t session_id;
    uint16_t key_exchange_length;
    uint8_t key_exchange_bytes[256];
};

struct vpn_protocol_server_finish {
    uint64_t session_id;
    uint16_t key_exchange_length;
    uint8_t key_exchange_bytes[256];
};

/* KEEPALIVE payload */
struct vpn_protocol_keepalive {
    uint64_t session_id;
    uint64_t timestamp_ms;
    uint8_t authenticator[32];
    uint8_t authenticator_length;
};

/* KEEPALIVE_ACK payload */
struct vpn_protocol_keepalive_ack {
    uint64_t session_id;
    uint64_t original_timestamp_ms;
    uint8_t authenticator[32];
    uint8_t authenticator_length;
};

/* CLOSE payload */
struct vpn_protocol_close {
    uint64_t session_id;
    uint8_t reason;
    uint8_t authenticator[32];
    uint8_t authenticator_length;
};

/* REJECT payload */
struct vpn_protocol_reject {
    uint64_t session_id;
    uint8_t rejection_code;
    uint64_t failed_message_id;
};

/* Envelope encode/decode */
size_t vpn_protocol_envelope_size(void);
int vpn_protocol_parse_envelope(const uint8_t *data, size_t length, struct vpn_protocol_envelope *out);
int vpn_protocol_encode_envelope(uint8_t *data, size_t length, const struct vpn_protocol_envelope *envelope);
int vpn_protocol_validate_envelope(const struct vpn_protocol_envelope *envelope);

/* CLIENT_HELLO encode/decode */
int vpn_protocol_parse_client_hello(const uint8_t *data, size_t length, struct vpn_protocol_client_hello *out);
int vpn_protocol_encode_client_hello(uint8_t *data, size_t length, const struct vpn_protocol_client_hello *hello);

/* SERVER_HELLO encode/decode */
int vpn_protocol_parse_server_hello(const uint8_t *data, size_t length, struct vpn_protocol_server_hello *out);
int vpn_protocol_encode_server_hello(uint8_t *data, size_t length, const struct vpn_protocol_server_hello *hello);

/* CLIENT_FINISH encode/decode */
int vpn_protocol_parse_client_finish(const uint8_t *data, size_t length, struct vpn_protocol_client_finish *out);
int vpn_protocol_encode_client_finish(uint8_t *data, size_t length, const struct vpn_protocol_client_finish *finish);

/* SERVER_FINISH encode/decode */
int vpn_protocol_parse_server_finish(const uint8_t *data, size_t length, struct vpn_protocol_server_finish *out);
int vpn_protocol_encode_server_finish(uint8_t *data, size_t length, const struct vpn_protocol_server_finish *finish);

/* KEEPALIVE encode/decode */
int vpn_protocol_parse_keepalive(const uint8_t *data, size_t length, struct vpn_protocol_keepalive *out);
int vpn_protocol_encode_keepalive(uint8_t *data, size_t length, const struct vpn_protocol_keepalive *keepalive);

/* KEEPALIVE_ACK encode/decode */
int vpn_protocol_parse_keepalive_ack(const uint8_t *data, size_t length, struct vpn_protocol_keepalive_ack *out);
int vpn_protocol_encode_keepalive_ack(uint8_t *data, size_t length, const struct vpn_protocol_keepalive_ack *ack);

/* CLOSE encode/decode */
int vpn_protocol_parse_close(const uint8_t *data, size_t length, struct vpn_protocol_close *out);
int vpn_protocol_encode_close(uint8_t *data, size_t length, const struct vpn_protocol_close *close);

/* REJECT encode/decode */
int vpn_protocol_parse_reject(const uint8_t *data, size_t length, struct vpn_protocol_reject *out);
int vpn_protocol_encode_reject(uint8_t *data, size_t length, const struct vpn_protocol_reject *reject);

#ifdef __cplusplus
}
#endif

#endif /* VPN_PROTOCOL_H */
