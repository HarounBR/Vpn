<!--
Sync Impact Report
Version change: template -> 1.0.0
Modified principles:
- PRINCIPLE_1_NAME -> I. Learning-First, Non-Production Security
- PRINCIPLE_2_NAME -> II. Linux TUN and UDP Scope Discipline
- PRINCIPLE_3_NAME -> III. Narrow C Module Boundaries
- PRINCIPLE_4_NAME -> IV. Handshake and Session State Before Data Plane
- PRINCIPLE_5_NAME -> V. Testable Crypto and Packet Behavior
Added sections:
- Technical Constraints
- Development Workflow
Removed sections:
- None
Templates requiring updates:
- updated: .specify/templates/plan-template.md
- updated: .specify/templates/spec-template.md
- updated: .specify/templates/tasks-template.md
- not present: .specify/templates/commands/*.md
Follow-up TODOs:
- None
-->
# Custom VPN in C Constitution

## Core Principles

### I. Learning-First, Non-Production Security
This project MUST remain a learning project for low-level Linux networking and
applied cryptography. Custom cipher, key exchange, and VPN protocol work MUST be
documented as educational and MUST NOT be represented as production-grade
security. Any feature that affects confidentiality, integrity, replay protection,
or key handling MUST state the learning goal and the security limitation it
leaves behind.

Rationale: implementing cryptography from scratch is valuable for learning, but
dangerous if presented as protection for real sensitive traffic.

### II. Linux TUN and UDP Scope Discipline
The implementation MUST target Linux with `/dev/net/tun`, raw IP packets through
a TUN interface, and UDP transport. The network topology MUST remain a star
model with one server and many clients unless the constitution is amended. Server
egress NAT or masquerade MUST be handled as an operations task using
`iptables`/`nftables`, not application code. IP rotation is out of scope until
the core tunnel works end to end.

Rationale: fixed platform and topology choices keep the project small enough to
complete while exercising the intended Linux networking primitives.

### III. Narrow C Module Boundaries
Each major subsystem MUST be a separate C compilation unit with a narrow header
interface: control plane/handshake, crypto, session manager, UDP transport, TUN
interface, packet handling, and config/bootstrap. The UDP transport MUST treat
payloads as opaque bytes. The TUN module MUST not know about encryption or
socket details. Only the crypto module may own raw key material and cipher state.
Server-only session management MUST stay separate from client peer handling.

Rationale: explicit ownership boundaries make packet flow debuggable and keep
security-sensitive state from leaking across unrelated modules.

### IV. Handshake and Session State Before Data Plane
Handshake message formats, state transitions, timeouts, retries, and teardown
rules MUST be designed before ordinary encrypted traffic is implemented. The
session state machine MUST clearly define how a client reaches `ESTABLISHED`,
how a server binds virtual IPs to real UDP addresses, and when sessions expire.
Data-plane packet encryption MUST depend only on keys and metadata produced by
the established session.

Rationale: the handshake determines the crypto API and session table contract;
building data flow first would hide critical protocol decisions.

### V. Testable Crypto and Packet Behavior
Crypto primitives, key derivation, integrity checks, replay protection, packet
parsing, and session lookup behavior MUST be testable in isolation before they
are wired into the event loop. Encrypt/decrypt round trips, tamper rejection,
known-answer vectors where available, malformed packet handling, and stale
session handling MUST have tests or documented manual verification steps before
integration is considered complete.

Rationale: low-level packet and crypto bugs are difficult to diagnose once
TUN, UDP, and event-loop behavior are coupled together.

## Technical Constraints

- Language: C.
- Target platform: Linux only.
- Kernel interface: `/dev/net/tun`.
- Transport: UDP datagrams.
- Concurrency: single-threaded `epoll` event loop over the TUN fd and UDP socket
  fd.
- Crypto dependencies: no external crypto library for the project cipher or key
  exchange implementation.
- Config/bootstrap MUST keep interface names, listen ports, identities, virtual
  addressing, and peer settings out of hardcoded module logic.
- NAT/masquerade configuration belongs in operational documentation or scripts,
  not in the VPN process.

## Development Workflow

- Start each feature by identifying which module owns the behavior and which
  module interfaces change.
- For protocol work, write the message format and state transition notes before
  implementation.
- Build order SHOULD follow: handshake/session design, crypto module, TUN module,
  UDP transport, session manager, integration event loop, NAT documentation.
- Each module change MUST include unit tests, integration tests, or a documented
  manual verification command appropriate to its risk.
- Features that expand scope beyond Linux, UDP, star topology, or educational
  crypto MUST amend this constitution before implementation.

## Governance

This constitution supersedes informal project preferences. Specs, plans, tasks,
reviews, and implementation work MUST pass the principles above before work is
accepted.

Amendments MUST include the reason for the change, affected principles or
sections, migration impact on templates and active specs, and an updated semantic
version. Versioning follows:

- MAJOR: removes or redefines a principle, changes the project topology,
  platform, transport, or crypto stance.
- MINOR: adds a principle or expands required workflow, testing, or technical
  constraints.
- PATCH: clarifies wording without changing project obligations.

Compliance review happens during planning and again before implementation is
marked complete. Any violation MUST be documented with a simpler alternative and
the reason that alternative was rejected.

**Version**: 1.0.0 | **Ratified**: 2026-07-24 | **Last Amended**: 2026-07-24
