# VPN Handshake and Session Protocol

## Purpose

This document is the entry point for the VPN control-plane protocol. It covers
client registration, session establishment, virtual IP ownership, retries,
timeouts, keepalive behavior, and session expiration.

**When to use this doc:** Implementers working on `protocol.c`, `handshake.c`, or `session.c` should start here for context and then refer to the detailed specifications below.

---

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Client Registration** | How a client announces itself to the server |
| **Session Establishment** | The 4-message handshake that creates a session |
| **Virtual IP Ownership** | How the server assigns and tracks IP addresses |
| **Retries & Timeouts** | How the protocol handles lost messages and stale sessions |
| **Session Expiration** | How the server cleans up dead clients |

---

## Canonical Documentation

| Document | Description |
|----------|-------------|
| [spec.md](../specs/001-vpn-handshake-session/spec.md) | Feature requirements and user stories |
| [handshake-protocol.md](../specs/001-vpn-handshake-session/contracts/handshake-protocol.md) | Technical protocol contract (byte formats, message types, rejection codes) |
| [data-model.md](../specs/001-vpn-handshake-session/data-model.md) | Entity definitions, state transitions, validation rules |

---

## Protocol Overview

The handshake uses a 4-message sequence to establish a session:
CLIENT_HELLO → SERVER_HELLO → CLIENT_FINISH → SERVER_FINISH


### Client State Flow

IDLE → HELLO_SENT → FINISH_SENT → ESTABLISHED


### Server State Flow

NO_SESSION → HELLO_RECEIVED → SERVER_HELLO_SENT → ESTABLISHED


### Timing Summary
- Handshake timeout: **10 seconds**
- Retry schedule: **0s initial, then 1s, 3s, and 7s** (4 total transmissions)
- Session idle timeout: **45 seconds**
- Keepalive interval: **15 seconds** of idleness

---

## Important Constraints

**Educational Purpose Only**
- This protocol is for learning, not production use
- Authentication and key-confirmation fields are handoff points for future crypto work
- No security audit or production guarantees

**Platform & Transport**
- Linux only (`/dev/net/tun`)
- UDP transport
- Star topology (1 server, N clients)
- Ops-level NAT (outside application code)

**Virtual IP and Peer Address Rules**
- Active virtual IP addresses are unique and each lookup resolves to exactly one owning session.
- A `CLIENT_HELLO` origin is recorded once as the peer address while the session is still in progress, and a second pre-establishment peer change is rejected.
- After the session is established, the peer address may be rebound when the authenticated flow confirms a new endpoint.

## Session Mapping

### Virtual IP Ownership

- Each established session owns exactly one virtual IP address.
- A virtual IP of `0` (zero) in a `CLIENT_HELLO` means the client is requesting server-side assignment.
- Once assigned, the virtual IP is reserved for that session until the session is closed, expired, or explicitly released.
- The server is authoritative for final virtual IP ownership.

### Conflict Behavior

- Active virtual IP conflicts are rejected deterministically.
- Conflict detection ignores sessions in `NONE`, `CLOSED`, or `EXPIRED` states.
- Conflict detection rejects matches against sessions in `HANDSHAKE_IN_PROGRESS`, `ESTABLISHED`, or `CLOSING` states.
- When a conflict is detected, the existing owner is **not mutated**; the new registration or assignment is rejected.
- Assignment and conflict functions return explicit result codes (`VPN_SESSION_OK`, `VPN_SESSION_ERR_VIRTUAL_IP_CONFLICT`, etc.) so callers can distinguish rejection reasons.

### Peer Address Capture

- The server records the UDP source address from `CLIENT_HELLO` as the initial peer address while the session is in `HANDSHAKE_IN_PROGRESS`.
- Peer address capture is allowed only once during the handshake. A second pre-establishment capture attempt for the same session is rejected.
- After establishment, **only authenticated `KEEPALIVE` messages may update the peer address** (rebinding). `KEEPALIVE_ACK` only refreshes liveness and does not change the peer address. `vpn_session_table_capture_client_hello_peer()` handles the initial address, and `vpn_session_table_process_keepalive()` is the only established-session rebinding path.

### Outbound Lookup

- Data-plane outbound routing uses `vpn_session_table_lookup_outbound()`.
- This helper returns only the owner of a virtual IP whose state is `ESTABLISHED`.
- Lookup returns `NULL` for unknown virtual IPs, or for sessions in `NONE`, `HANDSHAKE_IN_PROGRESS`, `CLOSING`, `CLOSED`, or `EXPIRED` states.

---

## Retry, Timeout, Keepalive, Expiration, and Rebinding

### Retry Policy

The handshake uses an exponential backoff retry schedule with a maximum of 4 total transmission attempts (1 initial + 3 retries):

| Attempt | Delay since previous attempt | Cumulative |
|---------|-------|------------|
| 1 (initial) | 0s | 0s |
| 2 (retry) | 1s | 1s |
| 3 (retry) | 2s | 3s |
| 4 (retry) | 4s | 7s |

After the 4th transmission attempt fails, the handshake transitions to `FAILED` state immediately. The partial session state is cleaned up and any reserved virtual IP is released.

### Handshake Timeout

In-progress handshakes have a hard timeout of **10 seconds** (`handshake_deadline_ms`). This hard deadline is separate from the per-attempt retry deadlines (`next_retry_at_ms`). If the handshake does not complete within this 10-second window, the server immediately marks the handshake as `FAILED`, removes the partial session state, and releases any reserved virtual IP. The hard deadline always wins - no retry is scheduled if it would exceed the 10-second deadline. The timeout is tracked per-handshake via the `handshake_deadline_ms` field in the handshake context.

### Keepalive and Liveness

- Only the client initiates `KEEPALIVE` messages, sent after **15 seconds** without authenticated traffic.
- The server replies with `KEEPALIVE_ACK` to acknowledge liveness.
- Valid authenticated keepalive traffic (from either side) refreshes the session's `last_seen_at_ms` timestamp.
- **Only authenticated `KEEPALIVE` messages may update the peer address** (rebinding). `KEEPALIVE_ACK` only refreshes liveness and does not change the peer address.
- Keepalive messages carry a timestamp to enable round-trip time estimation and replay detection.
- Duplicate and stale messages (based on message ID) are silently ignored and do not refresh liveness.

### Session Expiration

Established sessions expire after **45 seconds** of inactivity (no authenticated traffic). When a session expires:

1. The session state transitions to `EXPIRED`.
2. The virtual IP ownership is released (assigned_virtual_ip set to 0).
3. The session is removed from the session table.
4. The peer address mapping is cleared.

The server periodically checks for expired handshakes against `handshake_deadline_ms` and established sessions against `last_seen_at_ms + 45s`.

### Authenticated Peer Address Rebinding

- The initial peer address is captured once from the `CLIENT_HELLO` UDP source during `HANDSHAKE_IN_PROGRESS`.
- Pre-establishment peer address changes are rejected.
- After establishment, only authenticated `KEEPALIVE` messages from a new UDP source may update the peer address. `KEEPALIVE_ACK` never changes the peer address.
- Unauthenticated traffic (e.g., data-plane packets, duplicate handshake messages) from a different source address **must not** change the stored peer address.
- `vpn_session_table_process_keepalive()` enforces the established-state, authentication, freshness, and valid-source checks.

### Duplicate and Stale Message Handling

- Duplicate control messages (same `message_id` for a given session) are silently ignored.
- Stale messages (for sessions that have advanced past the expected state) are silently ignored.
- Out-of-order messages (e.g., `CLIENT_FINISH` before `SERVER_HELLO`) are rejected with `INVALID_STATE`.
- Replayed messages after session expiration or closure are silently ignored.
- These rules ensure that message loss, duplication, or reordering cannot create sessions, advance state, refresh liveness, or change peer mappings incorrectly.

---

## Module Ownership

| Module | Responsibility |
|--------|----------------|
| `protocol.c` | Message parsing, encoding, validation |
| `handshake.c` | State machine transitions, retry logic, timeout handling |
| `session.c` | Session table management, virtual IP assignment, lookup, expiration |

Server-side integration code should call `vpn_handshake_reserve_virtual_ip()` before building `SERVER_HELLO` to reserve the assigned virtual IP.

---

## Quick Reference

| Message Type | Direction | Purpose |
|--------------|-----------|---------|
| `CLIENT_HELLO` (1) | Client → Server | Start registration |
| `SERVER_HELLO` (2) | Server → Client | Assign session + virtual IP |
| `CLIENT_FINISH` (3) | Client → Server | Confirm and prove key |
| `SERVER_FINISH` (4) | Server → Client | Complete establishment |
| `KEEPALIVE` (5) | Either | Maintain liveness |
| `KEEPALIVE_ACK` (6) | Either | Acknowledge keepalive |
| `CLOSE` (7) | Either | Orderly teardown |
| `REJECT` (255) | Either | Report rejection |

---

## Related Documentation

- Implementation plan: `../specs/001-vpn-handshake-session/plan.md`
- Research notes: `../specs/001-vpn-handshake-session/research.md`
- Quickstart validation: `../specs/001-vpn-handshake-session/quickstart.md`
- Implementation tasks: `../specs/001-vpn-handshake-session/tasks.md`

---

**Document version:** 1.0
**Last updated:** 2026-07-30
