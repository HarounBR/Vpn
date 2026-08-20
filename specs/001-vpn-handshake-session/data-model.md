# Data Model: VPN Handshake and Session State Machine

## ClientIdentity

Represents the stable identity material a client presents during registration.

**Fields**:

- `client_id`: length-prefixed opaque byte string, 1 to 64 bytes.
- `display_name`: optional debug label, 0 to 64 bytes, not used for security.

**Validation Rules**:

- `client_id` MUST be present in `CLIENT_HELLO`.
- Empty or oversized identities are rejected as malformed.
- Duplicate active identities are rejected unless they refer to the same
  in-progress session and valid duplicate handling applies.

## HandshakeMessage

Represents one control-plane UDP datagram.

**Common Fields**:

- `magic`: constant identifying this VPN control protocol.
- `version`: protocol version, initially `1`.
- `type`: one of the defined control message types.
- `flags`: reserved for future use; unknown nonzero flags are rejected.
- `message_id`: sender-chosen 32-bit value for duplicate handling.
- `session_id`: server-assigned 64-bit session identity; zero before assignment.
- `payload_length`: byte length of the message-specific payload.
- `payload`: message-specific fields.

**Message Types**:

- `CLIENT_HELLO`: starts registration.
- `SERVER_HELLO`: assigns session identity and virtual IP or rejects.
- `CLIENT_FINISH`: confirms the server response and key-exchange handoff.
- `SERVER_FINISH`: marks the session established.
- `KEEPALIVE`: proves liveness for an established session.
- `KEEPALIVE_ACK`: acknowledges liveness.
- `CLOSE`: requests orderly teardown.
- `REJECT`: reports a deterministic rejection outcome.

**Validation Rules**:

- Unknown versions, types, invalid lengths, and invalid state transitions are
  rejected.
- Data-plane traffic is not accepted through this model unless the session state
  is `ESTABLISHED`.
- Duplicate and stale messages are silently ignored and must not create
  sessions, advance state, refresh liveness, or change peer mappings.

## Session

Represents the lifecycle state shared by the client and server after registration
begins.

**Fields**:

- `session_id`: nonzero 64-bit server-assigned identifier.
- `client_id`: associated `ClientIdentity`.
- `state`: lifecycle state.
- `assigned_virtual_ip`: virtual IPv4 address owned by this session.
- `peer_address`: real UDP IP address and port last authenticated for this
  session.
- `client_nonce`: opaque client nonce from registration.
- `server_nonce`: opaque server nonce from response.
- `key_exchange_context`: opaque bytes or handle passed to the future crypto
  module.
- `last_message_id`: last accepted control-message ID for duplicate handling.
- `last_seen_at`: monotonic timestamp of last authenticated traffic.
- `attempt_count`: total handshake transmissions, including the initial transmission.
- `handshake_deadline_ms`: fixed monotonic deadline for an in-progress handshake.
- `next_retry_at_ms`: monotonic deadline for the next retransmission only.

**Validation Rules**:

- `session_id` is assigned only by the server.
- `assigned_virtual_ip` MUST be unique among active sessions.
- `peer_address` is first recorded from `CLIENT_HELLO`.
- After establishment, `peer_address` may update only after authenticated
  session traffic passes validation.
- A handshake with an expired `handshake_deadline_ms`, or an established
  session with an expired `last_seen_at + session_idle_timeout_ms`, is removed
  and releases its virtual IP.

## VirtualIPAssignment

Represents ownership of one virtual IP by one active session.

**Fields**:

- `virtual_ip`: virtual IPv4 address.
- `session_id`: owning session.
- `client_id`: identity associated with the owner.
- `assigned_at`: monotonic timestamp for debugging and test assertions.

**Validation Rules**:

- One virtual IP maps to at most one active session.
- Registration requesting an already-owned virtual IP is rejected.
- Assignment is released when the owning session expires or closes.

## TimeoutPolicy

Represents retry and expiration settings for control-plane behavior.

**Fields**:

- `initial_retry_ms`: `1000`.
- `max_retry_ms`: `4000`.
- `max_attempts`: `4`.
- `handshake_timeout_ms`: `10000`.
- `keepalive_interval_ms`: `15000`.
- `session_idle_timeout_ms`: `45000`.

**Validation Rules**:

- The initial transmission is attempt 1; at most three retries follow after
  1s, 3s, and 7s cumulative delays from handshake start.
- Retry exhaustion immediately transitions the in-progress session to `FAILED`
  and releases any reserved virtual IP.
- In-progress sessions expire after `handshake_timeout_ms`.
- Established sessions expire after `session_idle_timeout_ms` without
  authenticated traffic.

## State Transitions

### Client Session States

```text
IDLE
  -> HELLO_SENT
  -> FINISH_SENT
  -> ESTABLISHED
  -> CLOSING
  -> CLOSED
```

Failure transitions:

- Any in-progress state -> `FAILED` after retry exhaustion or rejection.
- Any established state -> `EXPIRED` after idle timeout.

### Server Session States

```text
NO_SESSION
  -> HELLO_RECEIVED
  -> SERVER_HELLO_SENT
  -> ESTABLISHED
  -> CLOSING
  -> CLOSED
```

Failure transitions:

- `HELLO_RECEIVED` or `SERVER_HELLO_SENT` -> `FAILED` on malformed,
  conflicting, or timed-out handshakes.
- `ESTABLISHED` -> `EXPIRED` after idle timeout.
