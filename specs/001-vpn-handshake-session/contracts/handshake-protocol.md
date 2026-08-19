# Contract: VPN Handshake Control Protocol

## Scope

This contract defines control-plane UDP datagrams for client registration,
session establishment, keepalive, rejection, and teardown. It does not define
ordinary encrypted tunnel packet format.

## Common Envelope

All control messages use this envelope in network byte order.

| Field | Size | Rule |
|-------|------|------|
| `magic` | 32 bits | Constant protocol marker |
| `version` | 8 bits | `1` for this contract |
| `type` | 8 bits | One defined message type |
| `flags` | 16 bits | `0`; nonzero rejected for v1 |
| `message_id` | 32 bits | Sender-chosen message ID |
| `session_id` | 64 bits | `0` until assigned by server |
| `payload_length` | 16 bits | Number of payload bytes |
| `payload` | variable | Type-specific fields |

Receivers MUST reject datagrams shorter than the envelope, payload lengths that
do not match the datagram, unknown versions, unknown types, and unsupported
flags.

## Message Types

| Type | Name | Direction | Purpose |
|------|------|-----------|---------|
| `1` | `CLIENT_HELLO` | Client -> Server | Start registration |
| `2` | `SERVER_HELLO` | Server -> Client | Assign session and virtual IP |
| `3` | `CLIENT_FINISH` | Client -> Server | Confirm server response |
| `4` | `SERVER_FINISH` | Server -> Client | Mark establishment complete |
| `5` | `KEEPALIVE` | Either | Prove established-session liveness |
| `6` | `KEEPALIVE_ACK` | Either | Acknowledge keepalive |
| `7` | `CLOSE` | Either | Request orderly teardown |
| `255` | `REJECT` | Either | Report deterministic rejection |

## Payload Contracts

### CLIENT_HELLO

Required payload fields:

- `client_id`
- `requested_virtual_ip`
- `client_nonce`
- `key_exchange_payload`

Rules:

- `session_id` MUST be `0`.
- `client_id` MUST be 1 to 64 bytes.
- `requested_virtual_ip` MUST be either an allowed virtual IPv4 address or zero
  to request server assignment.
- Server records the UDP source address as the initial `peer_address`.

### SERVER_HELLO

Required payload fields:

- `assigned_virtual_ip`
- `server_nonce`
- `key_exchange_payload`
- `retry_policy_id`
- `session_lifetime_hint`

Rules:

- `session_id` MUST be nonzero and server-assigned.
- If requested virtual IP is actively owned, server MUST send `REJECT` with
  `VIRTUAL_IP_CONFLICT`.
- Assigned virtual IP MUST become reserved for this session until failure,
  expiration, or close.

### CLIENT_FINISH

Required payload fields:

- `client_key_confirmation`
- `accepted_virtual_ip`

Rules:

- `session_id` MUST match the server-assigned session.
- Client confirmation is verified by the future crypto/key-exchange module.
- Failure produces `REJECT` with `AUTHENTICATION_FAILED`.

### SERVER_FINISH

Required payload fields:

- `server_key_confirmation`
- `established_at`

Rules:

- After sending this message, the server marks the session `ESTABLISHED`.
- After receiving this message, the client marks the session `ESTABLISHED`.
- Data-plane traffic remains rejected before this transition completes.

### KEEPALIVE and KEEPALIVE_ACK

Required payload fields:

- `last_seen_session_id`
- `authenticator`

Rules:

- Keepalives are valid only for established sessions.
- Valid authenticated keepalive traffic updates `last_seen_at`.
- If the datagram source differs from the stored `peer_address`, the server may
  update `peer_address` only after authentication and replay checks pass.

### CLOSE

Required payload fields:

- `reason_code`
- `authenticator`

Rules:

- Valid close releases virtual IP ownership.
- Invalid close is rejected or ignored according to authentication result.

### REJECT

Required payload fields:

- `rejection_code`
- `rejected_message_id`

Rejection codes:

- `MALFORMED_MESSAGE`
- `UNSUPPORTED_VERSION`
- `INVALID_STATE`
- `VIRTUAL_IP_CONFLICT`
- `IDENTITY_CONFLICT`
- `AUTHENTICATION_FAILED`
- `REPLAY_OR_STALE_MESSAGE`
- `TIMEOUT`

## State Contract

Client establishment path:

```text
IDLE -> HELLO_SENT -> FINISH_SENT -> ESTABLISHED
```

Server establishment path:

```text
NO_SESSION -> HELLO_RECEIVED -> SERVER_HELLO_SENT -> ESTABLISHED
```

Required behavior:

- Out-of-order messages that do not match the current state are rejected with
  `INVALID_STATE`.
- Duplicate and stale messages are silently ignored and must not create
  sessions, advance state, refresh liveness, or change peer mappings.
- In-progress sessions expire after 10 seconds.
- Each pending message is transmitted at most 4 times total: the initial send
  followed by retries at 1s, 3s, and 7s from handshake start. Retry exhaustion immediately fails
  and cleans up the in-progress session.
- Only the client sends keepalive after 15 seconds of idleness; the server
  responds with `KEEPALIVE_ACK`.
- Established sessions expire after 45 seconds without authenticated traffic.

## Security Note

This protocol is for learning. Authentication and key-confirmation fields define
where the later educational crypto module plugs in; they do not claim
production-grade security.
