# Feature Specification: VPN Crypto and Key Exchange

**Feature Branch**: `002-crypto-key-exchange`  
**Created**: 2026-08-20  
**Status**: Draft  
**Input**: User description: "Create the educational VPN crypto and key-exchange module for the existing handshake and session protocol, including session-key derivation, encryption, integrity authentication, nonces, replay protection, key confirmation, and isolated known-answer tests while keeping TUN and UDP transport integration out of scope."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Protect an Established Session (Priority: P1)

As a VPN learner, I want an established handshake session to produce a shared
cryptographic context so that a plaintext tunnel payload can be protected and
recovered by both peers.

**Why this priority**: Without a shared key and integrity-protected payload
format, the established session cannot safely hand data to a future tunnel
transport.

**Independent Test**: Two simulated peers provide the same negotiated handshake
inputs, derive compatible session contexts, encrypt a bounded payload, and
successfully authenticate and decrypt it on the other side.

**Acceptance Scenarios**:

1. **Given** matching client/server handshake inputs and nonces, **When** both
   peers derive the session context, **Then** they produce compatible keying
   material without exposing key bytes through unrelated session APIs.
2. **Given** a valid established-session context, **When** a payload is
   protected and then opened by the peer, **Then** the recovered bytes exactly
   match the original payload and the associated metadata is validated.
3. **Given** a payload with modified ciphertext, tag, nonce, or session binding,
   **When** the peer opens it, **Then** authentication fails and no plaintext is
   returned.

---

### User Story 2 - Resist Replay and Context Confusion (Priority: P2)

As a VPN learner testing over UDP, I want protected messages to carry explicit
nonce and sequence context so that duplicated, reordered, or cross-session
messages are rejected deterministically.

**Why this priority**: UDP duplication and reordering can otherwise cause valid
tunnel data to be replayed or applied to the wrong session.

**Independent Test**: A simulated receiver processes valid, duplicate, stale,
reordered, and wrong-session protected messages and produces the documented
accept/reject outcomes.

**Acceptance Scenarios**:

1. **Given** a valid protected message with a fresh sequence value, **When** the
   receiver verifies it, **Then** it accepts the message and advances replay
   state.
2. **Given** a previously accepted protected message, **When** the receiver
   receives it again, **Then** it rejects it as a replay without returning
   plaintext or changing replay state.
3. **Given** a protected message from a different session, direction, or key
   context, **When** the receiver verifies it, **Then** authentication fails.
4. **Given** messages within the supported reordering policy, **When** the
   receiver verifies them, **Then** it accepts only messages not already
   accepted and rejects values outside the replay policy.

---

### User Story 3 - Confirm and Replace Keying Context (Priority: P3)

As a VPN learner, I want both peers to confirm the derived context and support
an explicit replacement boundary so that handshake completion and future key
changes are unambiguous.

**Why this priority**: Key confirmation prevents peers from treating different
keying material as equivalent, while a replacement boundary gives later work a
safe extension point without silently changing active traffic keys.

**Independent Test**: Simulated peers generate matching and mismatching key
confirmations, verify establishment outcomes, and replace a context only at a
documented boundary while rejecting messages protected by the retired context.

**Acceptance Scenarios**:

1. **Given** matching derived contexts, **When** both peers verify key
   confirmation values bound to the session, **Then** confirmation succeeds.
2. **Given** a mismatched or altered key confirmation, **When** either peer
   verifies it, **Then** confirmation fails and protected payloads remain
   unusable.
3. **Given** an explicitly initiated context replacement, **When** both peers
   complete the documented replacement exchange, **Then** new messages use
   the new context and old-context messages are rejected after the boundary.

### Edge Cases

- Empty, oversized, truncated, or malformed protected payloads.
- Counter or nonce wraparound before context replacement.
- Duplicate, stale, reordered, or cross-direction messages.
- A message authenticated with the wrong session identity or virtual peer.
- Key confirmation arriving before the required handshake state.
- Context replacement requested by only one peer or interrupted by loss.
- Reuse of a nonce with different plaintext or associated metadata.
- Unsupported crypto context version or algorithm identifier.
- Authentication failure must not reveal whether key derivation or payload
  validation failed.
- Documentation or command output implying production-grade security.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST define the cryptographic context inputs received
  from the Phase 5 handshake, including session identity, both peer nonces,
  direction binding, and key-exchange handoff data.
- **FR-002**: The system MUST define deterministic session-key derivation for
  matching handshake inputs and MUST distinguish contexts for different
  sessions or directions.
- **FR-003**: The system MUST define a protected payload contract containing
  context/version binding, nonce or sequence value, protected bytes, and an
  integrity authenticator.
- **FR-004**: The system MUST authenticate associated metadata binding a
  protected message to its session, direction, and message context.
- **FR-005**: The system MUST reject modified, truncated, malformed, or
  unauthenticated protected messages without returning plaintext.
- **FR-006**: The system MUST define nonce generation, uniqueness
  requirements, sequence handling, and behavior before exhaustion.
- **FR-007**: The system MUST define replay handling for duplicates, stale
  values, reordered values, and values outside the supported replay policy.
- **FR-008**: The system MUST define key-confirmation inputs and the exact
  conditions required before protected payloads may be accepted.
- **FR-009**: The system MUST define an explicit context replacement boundary,
  including transition coexistence and when the old context is rejected.
- **FR-010**: The system MUST expose crypto operations through narrow context
  boundaries so unrelated modules do not directly manipulate raw key material.
- **FR-011**: The system MUST provide deterministic test vectors and round-trip
  tests for derivation, protection, authentication failure, replay rejection,
  direction binding, and context replacement.
- **FR-012**: The system MUST preserve the Phase 5 handshake/session contract
  and identify the handoff fields consumed from it.
- **FR-013**: The system MUST keep TUN configuration, UDP socket ownership,
  packet routing, NAT setup, and full data-plane integration out of scope.
- **FR-014**: The system MUST state that the custom crypto is educational and
  must not be relied on for real sensitive traffic or production security.
- **FR-015**: The system MUST preserve the Linux-only, UDP, star-topology, and
  single-server multi-client project constraints.

### Key Entities

- **Crypto Context**: Session-bound keying state derived from handshake inputs,
  including context version, direction, lifecycle, and replacement status.
- **Protected Message**: Authenticated context metadata, nonce or sequence
  information, protected bytes, and an integrity value.
- **Replay State**: Receiver state recording accepted sequence values and the
  supported reordering policy for one direction and context.
- **Key Confirmation**: A value derived from the negotiated context and session
  transcript that proves compatible keying material.
- **Context Replacement**: The lifecycle transition from an active context to
  a new context at an explicit, authenticated boundary.
- **Test Vector**: Fixed inputs and expected outputs for deterministic checks.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Two independent implementations using documented inputs produce
  compatible context outputs for 100% of published test vectors.
- **SC-002**: Every valid payload round-trip test recovers the original bytes
  exactly, including empty and maximum-bounded payload cases.
- **SC-003**: 100% of modified ciphertext, tag, nonce, session-binding, and
  direction-binding cases are rejected without plaintext output.
- **SC-004**: 100% of duplicate and stale replay cases are rejected without
  advancing replay state or refreshing session liveness.
- **SC-005**: Context replacement tests show new-context messages succeeding and
  retired-context messages failing after the replacement boundary.
- **SC-006**: The crypto module can be tested without a TUN device, UDP socket,
  external service, or production deployment environment.
- **SC-007**: Documentation makes no claim that the custom crypto provides
  production-grade security.

## Assumptions

- Phase 5 remains authoritative for session identity, handshake state, peer
  nonces, and key-confirmation handoff points.
- The exact educational cipher and key-exchange primitive are selected during
  planning from a documented, testable design; this specification does not
  claim production cryptographic strength.
- Key material remains in crypto-owned contexts and is not persisted to disk.
- The first version supports one active context per session direction, with
  replacement reserved for an explicit authenticated transition.
- Tests use deterministic inputs and simulated time or counters rather than
  real network devices.
- TUN, UDP transport, packet forwarding, NAT/masquerade, and event-loop
  integration are separate future features.
