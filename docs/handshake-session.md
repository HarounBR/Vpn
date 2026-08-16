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
- Retry schedule: **1s, 2s, 4s, 4s** (4 retries max)
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
- After establishment, authenticated keepalive or control traffic may update the peer address in a later phase.

### Outbound Lookup

- Data-plane outbound routing uses `vpn_session_table_lookup_outbound()`.
- This helper returns only the owner of a virtual IP whose state is `ESTABLISHED`.
- Lookup returns `NULL` for unknown virtual IPs, or for sessions in `NONE`, `HANDSHAKE_IN_PROGRESS`, `CLOSING`, `CLOSED`, or `EXPIRED` states.

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
