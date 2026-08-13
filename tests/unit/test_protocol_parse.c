#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include "vpn/protocol.h"

static void test_protocol_parse_valid_envelope(void)
{
    uint8_t buffer[VPN_PROTOCOL_ENVELOPE_SIZE] = {0};
    struct vpn_protocol_envelope envelope;
    uint32_t magic = htonl(VPN_PROTOCOL_MAGIC);
    uint32_t message_id = htonl(1u);

    memcpy(buffer, &magic, sizeof(magic));
    buffer[4] = VPN_PROTOCOL_VERSION;
    buffer[5] = VPN_MSG_CLIENT_HELLO;
    memcpy(buffer + 8, &message_id, sizeof(message_id));

    assert(vpn_protocol_parse_envelope(buffer, sizeof(buffer), &envelope) == VPN_PROTOCOL_OK);
    assert(envelope.magic == VPN_PROTOCOL_MAGIC);
    assert(envelope.version == VPN_PROTOCOL_VERSION);
    assert(envelope.type == VPN_MSG_CLIENT_HELLO);
    assert(envelope.message_id == 1u);
    assert(envelope.payload_length == 0u);
}

static void test_protocol_parse_rejects_bad_magic(void)
{
    uint8_t buffer[VPN_PROTOCOL_ENVELOPE_SIZE] = {0};
    struct vpn_protocol_envelope envelope;

    buffer[3] = 0x21;
    buffer[4] = VPN_PROTOCOL_VERSION;
    buffer[5] = VPN_MSG_CLIENT_HELLO;

    assert(vpn_protocol_parse_envelope(buffer, sizeof(buffer), &envelope) == VPN_PROTOCOL_ERR_MALFORMED);
}

static void test_protocol_parse_rejects_mismatched_length(void)
{
    uint8_t buffer[VPN_PROTOCOL_ENVELOPE_SIZE] = {0};
    struct vpn_protocol_envelope envelope;

    buffer[0] = 0x00;
    buffer[1] = 0x00;
    buffer[2] = 0x00;
    buffer[3] = 0x20;
    buffer[4] = VPN_PROTOCOL_VERSION;
    buffer[5] = VPN_MSG_CLIENT_HELLO;
    buffer[20] = 0x00;
    buffer[21] = 0x01;

    assert(vpn_protocol_parse_envelope(buffer, sizeof(buffer), &envelope) == VPN_PROTOCOL_ERR_MALFORMED);
}

static void test_protocol_parse_rejects_truncated_envelope(void)
{
    uint8_t buffer[10] = {0};
    struct vpn_protocol_envelope envelope;
    
    /* Truncated: only 10 bytes instead of minimum 22 */
    assert(vpn_protocol_parse_envelope(buffer, sizeof(buffer), &envelope) == VPN_PROTOCOL_ERR_INSUFFICIENT_LENGTH);
}

static void test_protocol_parse_rejects_unsupported_version(void)
{
    uint8_t buffer[VPN_PROTOCOL_ENVELOPE_SIZE] = {0};
    struct vpn_protocol_envelope envelope;
    uint32_t magic = htonl(VPN_PROTOCOL_MAGIC);
    
    memcpy(buffer, &magic, sizeof(magic));
    buffer[4] = 99;  /* Unsupported version */
    buffer[5] = VPN_MSG_CLIENT_HELLO;
    
    assert(vpn_protocol_parse_envelope(buffer, sizeof(buffer), &envelope) == VPN_PROTOCOL_ERR_UNSUPPORTED_VERSION);
}

static void test_protocol_parse_rejects_unknown_message_type(void)
{
    uint8_t buffer[VPN_PROTOCOL_ENVELOPE_SIZE] = {0};
    struct vpn_protocol_envelope envelope;
    uint32_t magic = htonl(VPN_PROTOCOL_MAGIC);
    
    memcpy(buffer, &magic, sizeof(magic));
    buffer[4] = VPN_PROTOCOL_VERSION;
    buffer[5] = 42;  /* Unknown message type */
    
    assert(vpn_protocol_parse_envelope(buffer, sizeof(buffer), &envelope) == VPN_PROTOCOL_ERR_INVALID_TYPE);
}

static void test_protocol_parse_rejects_nonzero_flags(void)
{
    uint8_t buffer[VPN_PROTOCOL_ENVELOPE_SIZE] = {0};
    struct vpn_protocol_envelope envelope;
    uint32_t magic = htonl(VPN_PROTOCOL_MAGIC);
    
    memcpy(buffer, &magic, sizeof(magic));
    buffer[4] = VPN_PROTOCOL_VERSION;
    buffer[5] = VPN_MSG_CLIENT_HELLO;
    buffer[6] = 0x00;
    buffer[7] = 0x01;  /* Nonzero flags */
    
    assert(vpn_protocol_parse_envelope(buffer, sizeof(buffer), &envelope) == VPN_PROTOCOL_ERR_UNSUPPORTED_FLAGS);
}

static void test_protocol_parse_valid_envelope_with_payload(void)
{
    uint8_t buffer[VPN_PROTOCOL_ENVELOPE_SIZE + 10] = {0};
    struct vpn_protocol_envelope envelope;
    uint32_t magic = htonl(VPN_PROTOCOL_MAGIC);
    uint32_t message_id = htonl(2u);
    uint16_t payload_len = htons(10u);
    
    memcpy(buffer, &magic, sizeof(magic));
    buffer[4] = VPN_PROTOCOL_VERSION;
    buffer[5] = VPN_MSG_SERVER_HELLO;
    memcpy(buffer + 8, &message_id, sizeof(message_id));
    memcpy(buffer + 20, &payload_len, sizeof(payload_len));
    memset(buffer + VPN_PROTOCOL_ENVELOPE_SIZE, 0xAA, 10);  /* Payload */
    
    assert(vpn_protocol_parse_envelope(buffer, sizeof(buffer), &envelope) == VPN_PROTOCOL_OK);
    assert(envelope.payload_length == 10u);
    assert(envelope.type == VPN_MSG_SERVER_HELLO);
}

/* T016: CLIENT_HELLO and SERVER_HELLO payload tests */

static void test_client_hello_valid_payload(void)
{
    struct vpn_protocol_client_hello hello;
    uint8_t buffer[256] = {0};
    
    hello.client_id_length = 4;
    memcpy(hello.client_id, "test", 4);
    hello.requested_virtual_ip = htonl(0xC0A80001u);  /* 192.168.0.1 */
    hello.client_nonce = htonl(12345u);
    hello.key_exchange_length = 32;
    memset(hello.key_exchange_bytes, 0xBB, 32);
    
    assert(vpn_protocol_encode_client_hello(buffer, sizeof(buffer), &hello) > 0);
    
    struct vpn_protocol_client_hello parsed;
    assert(vpn_protocol_parse_client_hello(buffer, sizeof(buffer), &parsed) > 0);
    assert(parsed.client_id_length == 4);
    assert(memcmp(parsed.client_id, "test", 4) == 0);
    assert(parsed.client_nonce == htonl(12345u));
}

static void test_client_hello_rejects_empty_id(void)
{
    struct vpn_protocol_client_hello hello;
    uint8_t buffer[256] = {0};
    
    hello.client_id_length = 0;  /* Empty client ID */
    hello.requested_virtual_ip = htonl(0xC0A80001u);
    hello.client_nonce = htonl(12345u);
    hello.key_exchange_length = 0;
    
    assert(vpn_protocol_encode_client_hello(buffer, sizeof(buffer), &hello) < 0);
}

static void test_client_hello_rejects_oversized_id(void)
{
    struct vpn_protocol_client_hello hello;
    uint8_t buffer[512] = {0};
    
    hello.client_id_length = VPN_PROTOCOL_MAX_CLIENT_ID + 1;  /* Oversized */
    hello.requested_virtual_ip = htonl(0xC0A80001u);
    hello.client_nonce = htonl(12345u);
    hello.key_exchange_length = 0;
    
    assert(vpn_protocol_encode_client_hello(buffer, sizeof(buffer), &hello) < 0);
}

static void test_server_hello_valid_payload(void)
{
    struct vpn_protocol_server_hello hello;
    uint8_t buffer[512] = {0};
    
    hello.session_id = 0x0123456789ABCDEFuLL;
    hello.assigned_virtual_ip = htonl(0xC0A80001u);
    hello.server_nonce = htonl(54321u);
    hello.retry_policy_id = 1;
    hello.lifetime_hint_ms = htonl(60000u);
    hello.key_exchange_length = 32;
    memset(hello.key_exchange_bytes, 0xCC, 32);
    
    assert(vpn_protocol_encode_server_hello(buffer, sizeof(buffer), &hello) > 0);
    
    struct vpn_protocol_server_hello parsed;
    assert(vpn_protocol_parse_server_hello(buffer, sizeof(buffer), &parsed) > 0);
    assert(parsed.session_id == hello.session_id);
    assert(parsed.server_nonce == htonl(54321u));
    assert(parsed.retry_policy_id == 1);
}

static void test_server_hello_rejects_zero_session_id(void)
{
    struct vpn_protocol_server_hello hello;
    uint8_t buffer[512] = {0};
    
    hello.session_id = 0;  /* Invalid: zero session ID */
    hello.assigned_virtual_ip = htonl(0xC0A80001u);
    hello.server_nonce = htonl(54321u);
    hello.retry_policy_id = 1;
    hello.lifetime_hint_ms = htonl(60000u);
    hello.key_exchange_length = 0;
    
    assert(vpn_protocol_encode_server_hello(buffer, sizeof(buffer), &hello) < 0);
}

int test_protocol_parse(void)
{
    test_protocol_parse_valid_envelope();
    test_protocol_parse_rejects_bad_magic();
    test_protocol_parse_rejects_mismatched_length();
    test_protocol_parse_rejects_truncated_envelope();
    test_protocol_parse_rejects_unsupported_version();
    test_protocol_parse_rejects_unknown_message_type();
    test_protocol_parse_rejects_nonzero_flags();
    test_protocol_parse_valid_envelope_with_payload();
    test_client_hello_valid_payload();
    test_client_hello_rejects_empty_id();
    test_client_hello_rejects_oversized_id();
    test_server_hello_valid_payload();
    test_server_hello_rejects_zero_session_id();
    printf("test_protocol_parse.c passed\n");
    return 0;
}
