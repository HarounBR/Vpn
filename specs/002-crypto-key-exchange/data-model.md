# Data Model: VPN Crypto and Key Exchange

## CryptoContext

Session-bound, in-memory state owned only by the crypto module.

Fields:

- `version`: context format version; currently `1`.
- `session_id`: nonzero Phase 5 session identity.
- `context_id`: nonzero generation identifier.
- `transcript_hash[32]`: canonical handshake transcript digest.
- `client_to_server_key[32]`, `server_to_client_key[32]`: direction keys.
- `client_to_server_nonce_prefix[4]`, `server_to_client_nonce_prefix[4]`: nonce prefixes.
- `confirmation_key[32]`: context confirmation key.
- `lifecycle`: `ACTIVE`, `UPDATE_PENDING`, `TRANSITION`, or `RETIRED`.
- `send_sequence[2]`: next sequence for each direction.
- `replay[2]`: receiver replay state for each direction.

Validation: session and context IDs are nonzero; all key material is initialized before use; a retired context cannot protect or open messages; sequence exhaustion requires replacement.

## ProtectedMessage

Wire-facing authenticated record:

- version (1 byte)
- context ID (4 bytes)
- session ID (8 bytes)
- direction (1 byte)
- sequence (8 bytes)
- payload length (2 bytes)
- ciphertext (bounded payload)
- Poly1305 tag (16 bytes)

The header through payload length is associated data. The nonce is the direction's 4-byte prefix followed by the 8-byte big-endian sequence. Parsing and authentication precede plaintext output.

## ReplayState

Per direction and context: highest accepted sequence and a 64-bit bitmap for the current window. A newer sequence advances the window; an unseen sequence inside the window is accepted; duplicates and values below the window are rejected without state changes.

## KeyConfirmation

The expected 32-byte value is:

`HMAC-SHA256(confirmation_key, "vpn-002/key-confirmation" || transcript_hash || session_id || context_id)`.

Confirmation is valid only for the expected session, context, and handshake state.

## ContextReplacement

Authenticated lifecycle operation containing the proposed new context ID and fresh ephemeral public keys. `KEY_UPDATE` creates `UPDATE_PENDING`; `KEY_UPDATE_ACK` confirms both sides derived the same replacement. The new context becomes active at the acknowledgement boundary and the old context becomes retired.

## TestVector

Deterministic fixture containing handshake inputs, private/public keys, expected shared secret, transcript hash, derived keys/prefixes, confirmation value, and protected-message bytes. Test vectors are checked byte-for-byte and are not production credentials.
