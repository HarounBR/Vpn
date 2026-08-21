# Research: VPN Crypto and Key Exchange

## Decision 1: Educational primitive suite

- **Decision**: Implement an educational X25519 key exchange, SHA-256/HMAC-SHA-256, HKDF-SHA-256, and ChaCha20-Poly1305-compatible AEAD suite in the dedicated crypto module, without an external crypto library.
- **Rationale**: The suite gives the feature explicit key agreement, transcript-bound derivation, authentication, and associated-data protection while matching the project's C/no-external-library constraint. The specifications provide stable constructions and known-answer vectors suitable for isolated tests.
- **Alternatives considered**: AES-GCM was rejected because it adds a more involved block-cipher implementation and does not improve the learning scope. A production crypto library was rejected because the constitution requires the project cipher/key exchange to be implemented in-project. Inventing a new cipher or MAC was rejected as unjustified and unsafe even for an educational exercise.
- **References**: [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748), [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869), [RFC 6234](https://www.rfc-editor.org/rfc/rfc6234), [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439).

## Decision 2: Transcript-bound derivation

- **Decision**: Canonically encode the Phase 5 session ID, both handshake nonces, assigned virtual IP, protocol version, algorithm identifiers, and both public keys; hash that transcript with SHA-256; use the transcript hash as HKDF salt and the X25519 shared secret as HKDF input key material. Expand separate labeled values for each direction's key, nonce prefix, and key-confirmation key.
- **Rationale**: Including all negotiated and identity-bearing inputs prevents two sessions, directions, or algorithm contexts from accidentally sharing traffic keys. Domain-separated labels prevent key-purpose confusion.
- **Alternatives considered**: Deriving one undifferentiated key was rejected because it weakens direction and purpose separation. Using only the session ID was rejected because it omits the negotiated handshake transcript. Persisting keys was rejected because the feature requires in-memory contexts only.

## Decision 3: Nonces and replay

- **Decision**: Each direction owns an independent traffic key, 32-bit nonce prefix, and 64-bit sequence counter. The 96-bit AEAD nonce is `prefix || sequence` in network byte order. A sender must replace the context before sequence exhaustion. A receiver uses a 64-message sliding replay window per direction/context.
- **Rationale**: Direction-specific state prevents nonce reuse across directions. Explicit sequence values handle UDP reordering and make duplicates deterministic. The bounded window is simple to test and keeps receiver memory fixed.
- **Alternatives considered**: Random per-message nonces were rejected because uniqueness cannot be demonstrated as cleanly in deterministic tests. An unbounded replay set was rejected because memory grows with traffic. Rejecting all reordering was rejected because it is unnecessarily strict for UDP.

## Decision 4: Confirmation and replacement

- **Decision**: Key confirmation is a 32-byte HMAC-SHA-256 over a fixed label, transcript hash, session ID, and context ID. Replacement is an authenticated `KEY_UPDATE` / `KEY_UPDATE_ACK` exchange that creates a new context ID and fresh ephemeral X25519 keys. Both peers switch only after acknowledgement; the old context is accepted only during the transition and is retired at the boundary.
- **Rationale**: Confirmation proves both sides derived the same context. An explicit authenticated boundary prevents silent key changes and gives loss handling a deterministic state machine.
- **Alternatives considered**: Immediate unilateral replacement was rejected because peers could disagree about active keys. Keeping old contexts indefinitely was rejected because it permits stale traffic and unbounded state.

## Security and scope note

This is custom cryptographic code for learning and protocol experimentation. It MUST NOT be used for real sensitive traffic or presented as production-grade VPN security. TUN, UDP socket ownership, packet routing, NAT, and the event loop remain outside this feature.
