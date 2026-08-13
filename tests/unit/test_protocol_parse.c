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

int test_protocol_parse(void)
{
    test_protocol_parse_valid_envelope();
    test_protocol_parse_rejects_bad_magic();
    test_protocol_parse_rejects_mismatched_length();
    printf("test_protocol_parse.c passed\n");
    return 0;
}
