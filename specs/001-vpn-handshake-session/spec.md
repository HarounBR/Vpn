# Feature Specification: VPN Handshake and Session State Machine

**Feature Branch**: `001-vpn-handshake-session`  
**Created**: 2026-07-25  
**Status**: Draft  
**Input**: User description: "Design the VPN handshake and session state machine for a Linux C UDP/TUN VPN. It must define client registration, message formats, state transitions, retries, timeouts, session establishment, session expiration, and server mapping of virtual IP to real UDP address."

## Clarifications

### Session 2026-07-25

- Q: How should the server handle a registration request for a virtual IP that
  is already owned by an active session? -> A: Reject the registration.

### Session 2026-08-19

- Q: How should `max_attempts = 4` count handshake transmissions? -> A: Count
  the initial transmission as attempt 1; retry at 1s, 3s, and 7s from handshake start, then fail
  after the fourth total transmission.
- Q: What should happen after retry exhaustion? -> A: Immediately transition
  the handshake to `FAILED`, remove partial session state, and release any
  reserved virtual IP.
- Q: Which peers send keepalives? -> A: Only the client sends a `KEEPALIVE`
  after 15 seconds without authenticated traffic; the server replies with
  `KEEPALIVE_ACK`, and valid authenticated keepalive traffic refreshes
  `last_seen_at`.
- Q: Which message may authenticate a changed UDP source address? -> A: Only
  an authenticated `KEEPALIVE` from the new address may rebind the session;
  other traffic must not change the stored peer address.
- Q: How should duplicate and stale control messages be handled? -> A:
  Silently ignore duplicate and stale messages; they must not create sessions,
  advance state, refresh liveness, or change peer mappings.

### Session 2026-08-20

- Q: Which style-check policy should T056 implement? -> A: Use compiler
  warnings and `git diff --check`, plus `clang-format` when available.
- Q: How should T053 record test results? -> A: Add a dated validation record
  to `quickstart.md` containing the commands run, test environment, and
  pass/fail summary.
- Q: How should T054 resolve protocol constant mismatches? -> A: Treat the
  implemented C behavior as authoritative and update the protocol contract to
  match it, preserving the educational scope.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Establish a Client Session (Priority: P1)

As a VPN learner running one client and one server, I want the client to
complete a defined handshake with the server so that both sides agree a session
is established before any tunneled packets are accepted.

**Why this priority**: Without a defined session establishment flow, the data
plane cannot safely know which peer, virtual address, or key material belongs to
incoming UDP datagrams.

**Independent Test**: A simulated client and server can exchange the required
handshake messages in order and both end in an established state with the same
session identity and assigned virtual IP.

**Acceptance Scenarios**:

1. **Given** a server is ready to accept clients, **When** a new client sends a
   registration request and completes the expected exchange, **Then** the client
   and server both mark the session as established.
2. **Given** a session is not established, **When** data-plane traffic arrives
   from that peer, **Then** the traffic is rejected and the session remains
   non-established.
3. **Given** a client repeats a registration request during an in-progress
   handshake, **When** the server receives the duplicate, **Then** the server
   responds deterministically without creating duplicate active sessions.

---

### User Story 2 - Route Sessions by Virtual IP and Real Address (Priority: P2)

As the VPN server, I want to map each established client to a virtual IP and its
current UDP source address so that packets can be routed to the correct client
and replies can be accepted from the expected peer.

**Why this priority**: Multi-client star topology depends on stable ownership of
virtual addresses while still tracking the real network address seen by UDP.

**Independent Test**: With multiple simulated clients, the server can assign or
accept distinct virtual IPs, look up the owning session for an outbound packet,
and reject conflicting ownership.

**Acceptance Scenarios**:

1. **Given** two clients complete handshakes, **When** each receives a virtual IP,
   **Then** the server records two distinct virtual-IP-to-session mappings.
2. **Given** an outbound packet targets a known virtual IP, **When** the server
   performs a session lookup, **Then** it selects the session that owns that
   virtual IP and the peer address associated with it.
3. **Given** a client attempts to register with a virtual IP already owned by an
   active session, **When** the server validates the registration, **Then** the
   server rejects the registration without changing the existing session.

---

### User Story 3 - Recover from Loss and Expire Stale Sessions (Priority: P3)

As a user testing over UDP, I want handshake retries, timeouts, keepalive
expectations, and session expiration to be defined so that packet loss or stale
clients do not leave ambiguous state behind.

**Why this priority**: UDP does not guarantee delivery, and stale session state
can break reconnection, routing, and future security work.

**Independent Test**: A simulated packet-loss scenario can drop selected
handshake or keepalive messages and verify retries, timeout transitions, and
eventual session cleanup.

**Acceptance Scenarios**:

1. **Given** a handshake message is lost, **When** the retry interval elapses,
   **Then** the sender retransmits or restarts according to the documented retry
   policy.
2. **Given** a client never completes the handshake, **When** the handshake
   timeout expires, **Then** the server removes any partial session state.
3. **Given** an established client is silent beyond the expiration interval,
   **When** the server checks session liveness, **Then** the server removes the
   session and releases its virtual IP mapping.

### Edge Cases

- Duplicate handshake messages arrive after either peer has already advanced to
  a later state.
- Handshake messages arrive out of order or are missing mandatory fields.
- A UDP datagram is malformed, truncated, unauthenticated, replayed, or uses an
  unknown session identity.
- A peer sends ordinary tunnel traffic before reaching the established state.
- Two clients claim the same identity or virtual IP.
- A client reconnects after its previous session expired.
- A client's real UDP source address changes during an active session.
- Session cleanup occurs while a packet lookup is in progress.
- Documentation or command output implies the custom VPN is production-grade
  security instead of an educational implementation.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST define the client-visible registration flow from
  first contact through established session.
- **FR-002**: The system MUST define the server-side session state machine,
  including initial, in-progress, established, expired, and failed states.
- **FR-003**: The system MUST define every handshake message type, required
  field, optional field, field validation rule, and invalid-message outcome.
- **FR-004**: The system MUST define how client identity is presented during
  registration and how duplicate client identities are handled.
- **FR-005**: The system MUST define how a virtual IP is assigned, accepted, or
  rejected for a client session, and MUST reject registration for a virtual IP
  already owned by an active session.
- **FR-006**: The system MUST define how the server maps virtual IP addresses to
  active sessions and maps active sessions to real UDP peer addresses.
- **FR-007**: The system MUST define when the real UDP peer address is first
  recorded and whether it may be updated during an active session. It is first
  recorded from `CLIENT_HELLO` and may change only after an authenticated
  `KEEPALIVE` from the new address passes replay checks.
- **FR-008**: The system MUST define the exact conditions required before a
  session is considered established by the client and by the server.
- **FR-009**: The system MUST reject data-plane traffic for sessions that are
  unknown, failed, expired, or not yet established.
- **FR-010**: The system MUST define retry intervals, maximum retry counts, and
  timeout behavior for each in-progress handshake state. The default policy is
  four total transmissions per pending message, including the initial send,
  with retries at 1s, 3s, and 7s from handshake start; exhaustion transitions the handshake to
  `FAILED` immediately, removes partial session state, and releases any
  reserved virtual IP.
- **FR-011**: The system MUST define keepalive or last-seen behavior for
  established sessions. Only the client sends `KEEPALIVE` after 15 seconds
  without authenticated traffic; the server replies with `KEEPALIVE_ACK`.
  Valid authenticated keepalive traffic refreshes `last_seen_at`.
- **FR-012**: The system MUST define session expiration rules, including cleanup
  of virtual IP ownership and peer-address mappings.
- **FR-013**: The system MUST define deterministic handling for duplicate,
  delayed, out-of-order, and replayed control messages. Duplicate and stale
  messages are silently ignored and must not create sessions, advance state,
  refresh liveness, or change peer mappings; genuinely out-of-order messages
  are rejected with `INVALID_STATE`.
- **FR-014**: The system MUST define observable outcomes for rejected control
  messages and failed handshakes.
- **FR-015**: The system MUST state that the handshake and custom crypto are for
  learning only and must not be relied on for real sensitive traffic.
- **FR-016**: The system MUST preserve Linux TUN, UDP transport, star topology,
  and educational custom-crypto constraints.

### Key Entities

- **Client Identity**: Stable identity material presented by a client during
  registration so the server can distinguish clients for learning and testing.
- **Handshake Message**: A control-plane datagram exchanged to register a client,
  negotiate session parameters, acknowledge progress, reject invalid input, or
  terminate setup.
- **Session**: Server and client state created by a successful handshake,
  including session identity, lifecycle state, assigned virtual IP, peer address,
  key metadata, counters or replay metadata, and last-seen time.
- **Virtual IP Assignment**: The virtual address owned by one active client
  session and used by the server to route tunneled packets.
- **Peer Address**: The real UDP source address and port associated with an
  active client session.
- **Timeout Policy**: The retry, expiration, and cleanup rules that determine
  when in-progress or established sessions are abandoned.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A reader can implement the handshake state machine from the spec
  without needing additional decisions about message names, required fields,
  state transitions, retry limits, or timeout outcomes.
- **SC-002**: In a simulated one-client scenario, the documented flow reaches an
  established state from a clean start and rejects data traffic before
  establishment.
- **SC-003**: In a simulated multi-client scenario with at least three clients,
  the documented mapping rules assign distinct virtual IP ownership and route an
  outbound packet to the correct session.
- **SC-004**: In simulated loss cases, each in-progress handshake state has a
  defined retry or failure outcome within a bounded number of attempts.
- **SC-005**: In stale-session scenarios, the documented expiration policy
  removes inactive sessions and releases their virtual IP mappings within a
  defined interval.
- **SC-006**: Review of the generated protocol documentation finds no claim that
  the custom VPN provides production-grade security.

## Assumptions

- The server is authoritative for final virtual IP ownership.
- The first feature produces a protocol/state-machine design artifact; ordinary
  encrypted data-plane implementation follows later.
- The project remains a Linux-only, UDP-based, single-server multi-client VPN.
- The exact cipher and key-exchange primitive may be refined during crypto
  design, but this feature must identify the handshake fields and state handoff
  needed by that future work.
- NAT/masquerade setup remains operational documentation and is outside this
  feature's application behavior.
