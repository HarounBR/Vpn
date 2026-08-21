# Crypto Protocol Contract

This contract defines the isolated interface between the Phase 5 handshake/session code and the educational crypto module. It does not define UDP or TUN framing.

## Version and algorithm identifiers

- Context version: `1`.
- X25519: `1`.
- SHA-256/HMAC-SHA-256: `2`.
- HKDF-SHA-256: `3`.
- ChaCha20-Poly1305-compatible AEAD: `4`.

Unsupported versions or identifiers are rejected before context creation.

## Derivation handoff

The caller supplies the established Phase 5 session ID, client/server handshake nonces, assigned virtual IP, protocol version, negotiated algorithm IDs, and both X25519 public keys. The crypto module derives an opaque `CryptoContext`; raw key bytes are not exposed through handshake or session APIs.

The canonical transcript is the fixed-width, network-byte-order encoding of those fields. `transcript_hash = SHA-256(transcript)`. `shared_secret = X25519(local_private, peer_public)`. An all-zero shared secret is rejected. HKDF-SHA-256 uses the transcript hash as salt and shared secret as input key material.

Expand labels:

```text
vpn-002/client-to-server/key
vpn-002/server-to-client/key
vpn-002/client-to-server/nonce-prefix
vpn-002/server-to-client/nonce-prefix
vpn-002/key-confirmation
```

## Protected message

The serialized record is:

```text
version       u8
context_id    u32
session_id    u64
direction     u8       # 0 client-to-server, 1 server-to-client
sequence      u64
payload_len   u16
ciphertext    payload_len bytes
tag           16 bytes
```

All integers are big-endian. Associated data is the header through `payload_len`. The 96-bit nonce is the direction-specific 32-bit prefix followed by the 64-bit sequence. Payload length is bounded by the Phase 5 protocol limit and by the implementation's buffer capacity.

Authentication is verified before any plaintext is returned. Malformed, truncated, wrong-session, wrong-direction, wrong-context, modified, and unsupported records return one generic authentication/format failure class and do not update replay or liveness state.

## Replay policy

Each direction/context has a 64-message sliding window. A fresh higher sequence advances the window; an unseen sequence within it is accepted; duplicate or below-window values are rejected. A sender must refuse further protection before sequence wrap and initiate context replacement instead.

## Confirmation and replacement

Confirmation is the 32-byte HMAC described in `data-model.md`, bound to transcript, session, and context. Protected data is accepted only after confirmation succeeds.

`KEY_UPDATE` and `KEY_UPDATE_ACK` are authenticated control operations. They carry a new context ID and fresh ephemeral public keys. The old context remains valid only until the acknowledgement boundary; after switching, records under the retired context are rejected.

## Security posture

The implementation is educational custom crypto and is not suitable for production or real sensitive traffic. It intentionally excludes transport integration and does not claim resistance to the risks of a professionally reviewed cryptographic library.
