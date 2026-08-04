#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include "vpn/protocol.h"

static void test_protocol_parse_envelope(void)
{
    uint8_t buffer[sizeof(struct vpn_protocol_envelope)] = {0};
    struct vpn_protocol_envelope envelope;
    int result = vpn_protocol_parse_envelope(buffer, sizeof(buffer), &envelope);
    assert(result != VPN_PROTOCOL_OK);
}

int main(void)
{
    test_protocol_parse_envelope();
    printf("test_protocol_parse.c skeleton passed\n");
    return 0;
}
