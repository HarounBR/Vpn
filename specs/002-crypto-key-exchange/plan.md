# Implementation Plan: VPN Crypto and Key Exchange

**Branch**: `002-crypto-key-exchange` | **Date**: 2026-08-20 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `/specs/002-crypto-key-exchange/spec.md` and [requirements.md](checklists/requirements.md)

**Note**: This template is filled in by the `/speckit-plan` command. See `.specify/templates/plan-template.md` for the execution workflow.

## Summary

Add an isolated, educational crypto module to the Phase 5 handshake/session
implementation. It derives transcript-bound per-direction contexts with
X25519 and HKDF-SHA-256, protects bounded payloads with a
ChaCha20-Poly1305-compatible AEAD, and enforces confirmation, sequence, replay,
and explicit context replacement rules. TUN, UDP, NAT, routing, and event-loop
integration remain out of scope.

## Technical Context

<!--
  ACTION REQUIRED: Replace the content in this section with the technical details
  for the project. The structure here is presented in advisory capacity to guide
  the iteration process.
-->

**Language/Version**: C11  
**Primary Dependencies**: libc/POSIX headers and existing project modules; no external crypto library  
**Storage**: In-memory opaque crypto contexts; no key persistence  
**Testing**: Existing Makefile test runner with unit and integration suites, plus deterministic known-answer vectors  
**Target Platform**: Linux only  
**Project Type**: C library/module within the existing VPN project  
**Performance Goals**: Bounded payload processing and fixed-size replay state; correctness and auditability take priority over throughput  
**Constraints**: Educational custom crypto, single-threaded ownership, network-byte-order wire fields, no TUN/UDP/event-loop integration  
**Scale/Scope**: One active context per session direction, 64-message replay window, Phase 5 payload bounds

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- Confirm the feature preserves the learning-only, non-production security
  posture and documents any custom-crypto limitation it touches.
- Confirm the design stays within Linux `/dev/net/tun`, UDP transport, star
  topology, single-threaded `epoll`, and ops-level NAT unless the constitution
  has been amended.
- Identify the owning C module(s) and any header/interface changes across
  handshake, crypto, session manager, transport, TUN, packet handling, or config.
- For protocol work, include handshake/session state transitions, message
  formats, timeout/retry behavior, and teardown rules before data-plane work.
- Define tests or manual verification for crypto, packet parsing, session lookup,
  event-loop integration, and malformed input handling as applicable.

**Gate result: PASS.** The design preserves the non-production learning posture,
keeps crypto state in a narrow C module, consumes only established Phase 5
handoff data, and tests crypto behavior without requiring data-plane devices.

## Project Structure

### Documentation (this feature)

```text
specs/[###-feature]/
├── plan.md              # This file
├── research.md          # Research decisions and references
├── data-model.md        # Crypto entities and lifecycle rules
├── quickstart.md        # Isolated validation workflow
├── contracts/           # Crypto wire/API contract
└── tasks.md             # Created later by /speckit-tasks
```

### Source Code (repository root)
<!--
  ACTION REQUIRED: Replace the placeholder tree below with the concrete layout
  for this feature. Delete unused options and expand the chosen structure with
  real paths (e.g., apps/admin, packages/something). The delivered plan must
  not include Option labels.
-->

```text
include/vpn/
├── crypto.h                 # Opaque public crypto API
└── [existing handshake/session headers]

src/
├── crypto.c                  # Context, derivation, protection, replay lifecycle
├── crypto_sha256.c           # SHA-256 and HMAC-SHA-256 primitive
├── crypto_hkdf.c             # HKDF-SHA-256
├── crypto_x25519.c           # X25519
├── crypto_chacha.c           # ChaCha20
└── crypto_poly1305.c         # Poly1305 and AEAD composition

tests/
├── unit/test_crypto.c
├── integration/test_crypto_handshake.c
└── vectors/crypto_vectors.h
```

**Structure Decision**: Extend the existing single C project with one public
opaque crypto header and private primitive compilation units. Keep unit tests
for primitives/state and integration tests for two simulated peers; do not add
transport or device directories for this feature.

## Phase 0: Research Summary

Research decisions and alternatives are recorded in [research.md](research.md).
The selected suite follows RFC 7748, RFC 5869, RFC 6234, and RFC 8439 while
remaining explicitly educational and non-production.

## Phase 1: Design Summary

- [data-model.md](data-model.md) defines contexts, protected messages, replay,
  confirmation, replacement, and vectors.
- [contracts/crypto-protocol.md](contracts/crypto-protocol.md) defines the
  derivation handoff, protected record, replay policy, and update boundary.
- [quickstart.md](quickstart.md) defines isolated validation and build checks.

**Post-design gate: PASS.** All specification requirements have a documented
design location; no unresolved clarification items remain. The crypto module
owns raw key material and no design expands the project's platform, topology,
transport, or security claims.

## Complexity Tracking

No constitution violations. The separate primitive compilation units are a
deliberate narrow-module/testability choice required by Principle III, not an
additional project or architectural layer.
