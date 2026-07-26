# Phase 0 Research: VPN Handshake and Session State Machine

## Message Encoding

**Decision**: Use a compact binary control-message envelope with fixed
network-byte-order integer fields and length-prefixed variable payloads.

**Rationale**: The project handles UDP datagrams and raw packet plumbing in C.
A fixed binary envelope keeps parsing deterministic, bounds validation work, and
matches the low-level learning goal. Length-prefixed payloads allow the future
crypto feature to define key-exchange bytes without changing the envelope.

**Alternatives considered**:

- Text commands: easier to read manually, but less representative of packet
  protocol work and easier to parse inconsistently.
- JSON/CBOR: convenient for tooling, but adds dependencies or larger parsers
  outside the project's narrow C scope.

## Establishment Flow

**Decision**: Use a four-message flow:
`CLIENT_HELLO -> SERVER_HELLO -> CLIENT_FINISH -> SERVER_FINISH`.

**Rationale**: Four messages give both peers a clear point to contribute nonce
and key-exchange material, confirm the negotiated session, and agree that
ordinary tunnel traffic is allowed only after final acknowledgement.

**Alternatives considered**:

- Two messages: simpler, but weak for key confirmation and duplicate handling.
- Three messages: workable, but leaves one peer's final established transition
  harder to acknowledge deterministically.

## Session Identity

**Decision**: The server assigns a 64-bit `session_id` in `SERVER_HELLO`.
`session_id` is zero in the initial `CLIENT_HELLO` and nonzero afterward.

**Rationale**: Server-assigned session identity avoids client-chosen collisions
and gives later data-plane code a compact lookup key.

**Alternatives considered**:

- Client-generated session ID: simpler for the client, but creates collision and
  spoofing questions too early.
- Address-only identity: fails when clients reconnect or peer addresses change.

## Virtual IP Conflict Policy

**Decision**: Reject registration when the requested virtual IP is already owned
by an active session.

**Rationale**: The user selected this clarification. It keeps ownership
deterministic and avoids surprising reassignment during early protocol work.

**Alternatives considered**:

- Auto-assign a new virtual IP: useful later, but hides configuration mistakes.
- Replace the existing session: dangerous without stronger identity and replay
  rules.

## Real UDP Peer Address Rebinding

**Decision**: Record the peer address from `CLIENT_HELLO`. After establishment,
allow the peer address to update only when a datagram for the existing session
passes session authentication and replay checks.

**Rationale**: UDP clients may experience NAT rebinding. Accepting address
changes only after an authenticated session message supports that behavior
without allowing unauthenticated address takeover.

**Alternatives considered**:

- Fixed address until expiration: simpler, but brittle across NAT changes.
- Full re-handshake on every address change: safe and simple, but makes common
  UDP rebinding cases unnecessarily disruptive.

## Retry and Timeout Policy

**Decision**: Use a 1 second initial retry interval, double it up to 4 seconds,
allow 4 attempts per handshake message, expire incomplete handshakes after 10
seconds, send keepalives every 15 seconds when idle, and expire established
sessions after 45 seconds without authenticated traffic.

**Rationale**: These values are short enough for tests and learning feedback,
but long enough to model real UDP loss and stale-session cleanup.

**Alternatives considered**:

- No retries: does not model UDP loss.
- Unbounded retries: makes failure handling hard to test.
- Much longer timeouts: realistic for production, but slow for a learning
  project and early tests.

## Replay and Duplicate Handling

**Decision**: Include `message_id`, `session_id`, and peer nonces in control
messages. Each state accepts only the next valid message type for that state.
Duplicate messages from the immediately previous accepted state may receive the
same response; stale or out-of-order messages are rejected.

**Rationale**: This gives deterministic behavior for UDP duplication while
keeping full replay-window design available for the later crypto/data-plane
feature.

**Alternatives considered**:

- Silently drop all duplicates: harder to debug and can stall retry behavior.
- Full sliding replay window now: better for encrypted data-plane traffic, but
  premature before the crypto module is designed.

## Observable Rejections

**Decision**: Define explicit rejection codes for malformed messages, unsupported
version, invalid state, virtual IP conflict, identity conflict, authentication
failure, replay/stale message, and timeout.

**Rationale**: Clear rejection outcomes make tests precise and make the
educational protocol easier to debug.

**Alternatives considered**:

- Silent drop for every error: closer to some hardened network behavior, but
  poor for learning and unit tests.
- Free-form error strings: easy initially, but harder to parse and test in C.
