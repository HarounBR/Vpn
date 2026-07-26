# Implementation Plan: VPN Handshake and Session State Machine

**Branch**: `001-vpn-handshake-session` | **Date**: 2026-07-26 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/001-vpn-handshake-session/spec.md`

## Summary

Define the control-plane protocol that lets one Linux C UDP/TUN VPN server
register many clients, assign or reject virtual IP ownership, establish sessions,
track real UDP peer addresses, retry lost control messages, expire stale state,
and reject all data-plane traffic until a session reaches `ESTABLISHED`.

The technical approach is a small binary control protocol plus explicit client
and server state machines. The feature produces protocol contracts and C module
interfaces for `protocol`, `handshake`, and `session` logic. The crypto payloads
remain opaque handoff fields because the custom cipher and key exchange are
designed in a later feature.

## Technical Context

**Language/Version**: C11  
**Primary Dependencies**: POSIX/Linux system headers only; no external crypto
library for this feature  
**Storage**: In-memory session table; no persistent storage  
**Testing**: Unit tests for parser/state/session behavior plus simulated
integration tests for client/server control-message exchange  
**Target Platform**: Linux with `/dev/net/tun` and UDP sockets  
**Project Type**: Single C system project with CLI/server/client entry points  
**Performance Goals**: Establish or reject a handshake within 10 seconds under
normal local test conditions; support at least 3 simultaneous simulated clients
for this feature  
**Constraints**: Learning-only security posture; UDP transport; star topology;
single-threaded `epoll`; ops-level NAT remains outside application behavior  
**Scale/Scope**: One server, N clients; this feature covers control-plane
session establishment only, not encrypted data-plane packet forwarding

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- Learning-only security posture is preserved. The plan treats key-exchange and
  authentication fields as educational protocol handoff points and does not claim
  production-grade protection.
- Linux `/dev/net/tun`, UDP transport, star topology, single-threaded `epoll`,
  and ops-level NAT constraints are unchanged.
- Owning modules are `protocol`, `handshake`, and `session`. Later `crypto`,
  `transport`, `tun`, and packet handling modules consume their contracts but do
  not own this feature.
- Protocol work includes message formats, state transitions, retry behavior,
  timeout behavior, rejection rules, peer-address mapping, and teardown.
- Tests are planned for message parsing, invalid input, state transitions,
  duplicate messages, virtual IP conflicts, session lookup, expiration, and
  peer-address rebinding.

**Initial Gate Result**: PASS. No constitution violations.

## Project Structure

### Documentation (this feature)

```text
specs/001-vpn-handshake-session/
+-- plan.md
+-- research.md
+-- data-model.md
+-- quickstart.md
+-- contracts/
|   +-- handshake-protocol.md
+-- checklists/
|   +-- requirements.md
+-- tasks.md
```

### Source Code (repository root)

```text
include/
+-- vpn/
    +-- protocol.h
    +-- handshake.h
    +-- session.h

src/
+-- protocol.c
+-- handshake.c
+-- session.c

tests/
+-- unit/
|   +-- test_protocol_parse.c
|   +-- test_handshake_state.c
|   +-- test_session_table.c
+-- integration/
    +-- test_handshake_flow.c
```

**Structure Decision**: Use a single C project layout with public headers under
`include/vpn/`, implementation files under `src/`, and focused unit/integration
tests under `tests/`. This matches the constitution's narrow C module boundary
rule without introducing extra services or frameworks.

## Phase 0: Research Summary

See [research.md](./research.md). All planning unknowns are resolved:

- Binary message envelope with fixed network-byte-order header.
- Four-step establishment flow: `CLIENT_HELLO`, `SERVER_HELLO`,
  `CLIENT_FINISH`, `SERVER_FINISH`.
- Server rejects active virtual IP conflicts.
- Established peer address may update only after an authenticated session
  message.
- Bounded retry and timeout values are defined for testable behavior.

## Phase 1: Design Summary

See [data-model.md](./data-model.md) for entities, fields, validation rules, and
state transitions.

See [contracts/handshake-protocol.md](./contracts/handshake-protocol.md) for the
control-message contract, state-machine contract, rejection codes, and timing
requirements.

See [quickstart.md](./quickstart.md) for validation scenarios that should pass
before this feature is considered complete.

## Constitution Check: Post-Design

- Learning-only custom crypto remains explicit. The contract requires
  authentication/key-confirmation fields but leaves cipher construction to the
  later crypto feature.
- Linux/UDP/star topology constraints remain unchanged.
- Module ownership is clear: protocol parsing, handshake state, and session
  table behavior are independent of UDP socket and TUN modules.
- Test coverage is defined for isolated behavior and simulated integration.
- No complexity violations require justification.

**Post-Design Gate Result**: PASS.

## Complexity Tracking

No constitution violations.
