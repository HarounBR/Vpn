# Tasks: VPN Handshake and Session State Machine

**Input**: Design documents from `/specs/001-vpn-handshake-session/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/handshake-protocol.md, quickstart.md

**Tests**: Required by the plan for protocol parsing, state transitions, session lookup, expiration, malformed input, duplicate messages, and peer-address rebinding.

**Organization**: Tasks are grouped by user story so each story can be implemented and tested independently after the shared foundation is complete.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel with other [P] tasks in the same phase
- **[Story]**: User story label for story phases only
- Every task includes an exact repository path

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Create the C project skeleton and test entry points used by all later tasks.

- [x] T001 Create project directories in include/vpn/, src/, tests/unit/, and tests/integration/
- [x] T002 Create C11 build targets for vpn_handshake_tests in Makefile
- [x] T003 [P] Add shared test assertion helpers in tests/test_helpers.h
- [x] T004 [P] Add feature protocol documentation reference in docs/handshake-session.md

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Define shared types, constants, and module interfaces that all user stories depend on.

**CRITICAL**: No user story work can begin until this phase is complete.

- [x] T005 Define protocol constants, message type enum, rejection code enum, and envelope struct in include/vpn/protocol.h
- [x] T006 Define handshake state enums, retry policy struct, and handshake context structs in include/vpn/handshake.h
- [x] T007 Define client identity, peer address, session, virtual IP assignment, and session table structs in include/vpn/session.h
- [x] T008 Create protocol module stub and validation entry points in src/protocol.c
- [x] T009 Create handshake module stub and state transition entry points in src/handshake.c
- [x] T010 Create session module stub and session table entry points in src/session.c
- [x] T011 [P] Add protocol parser unit test skeleton in tests/unit/test_protocol_parse.c
- [x] T012 [P] Add handshake state unit test skeleton in tests/unit/test_handshake_state.c
- [x] T013 [P] Add session table unit test skeleton in tests/unit/test_session_table.c
- [x] T014 [P] Add simulated handshake integration test skeleton in tests/integration/test_handshake_flow.c

**Checkpoint**: Shared headers, source stubs, and test skeletons compile.

---

## Phase 3: User Story 1 - Establish a Client Session (Priority: P1)

**Goal**: A simulated client and server complete `CLIENT_HELLO -> SERVER_HELLO -> CLIENT_FINISH -> SERVER_FINISH` and reject data-plane traffic before establishment.

**Independent Test**: Run `tests/integration/test_handshake_flow.c` clean-establishment case and verify both peers reach `ESTABLISHED` with matching `session_id` and virtual IP.

### Tests for User Story 1

- [ ] T015 [P] [US1] Add unit tests for valid and malformed common envelope parsing in tests/unit/test_protocol_parse.c
- [ ] T016 [P] [US1] Add unit tests for CLIENT_HELLO and SERVER_HELLO payload validation in tests/unit/test_protocol_parse.c
- [ ] T017 [P] [US1] Add unit tests for client state path IDLE to HELLO_SENT to FINISH_SENT to ESTABLISHED in tests/unit/test_handshake_state.c
- [ ] T018 [P] [US1] Add unit tests for server state path NO_SESSION to HELLO_RECEIVED to SERVER_HELLO_SENT to ESTABLISHED in tests/unit/test_handshake_state.c
- [ ] T019 [P] [US1] Add integration test for clean four-message establishment in tests/integration/test_handshake_flow.c
- [ ] T020 [P] [US1] Add integration test that data-plane traffic is rejected before SERVER_FINISH in tests/integration/test_handshake_flow.c

### Implementation for User Story 1

- [ ] T021 [US1] Implement common envelope encode/decode and length validation in src/protocol.c
- [ ] T022 [US1] Implement CLIENT_HELLO and SERVER_HELLO payload encode/decode in src/protocol.c
- [ ] T023 [US1] Implement CLIENT_FINISH and SERVER_FINISH payload encode/decode in src/protocol.c
- [ ] T024 [US1] Implement client handshake state transitions for establishment in src/handshake.c
- [ ] T025 [US1] Implement server handshake state transitions for establishment in src/handshake.c
- [ ] T026 [US1] Implement session creation and server-assigned session_id allocation in src/session.c
- [ ] T027 [US1] Implement pre-establishment data-plane rejection helper in src/session.c
- [ ] T028 [US1] Wire clean establishment simulation helpers in tests/integration/test_handshake_flow.c

**Checkpoint**: User Story 1 works independently; a single simulated client establishes a session and early data traffic is rejected.

---

## Phase 4: User Story 2 - Route Sessions by Virtual IP and Real Address (Priority: P2)

**Goal**: The server records virtual IP ownership, maps active sessions to real UDP peer addresses, routes by virtual IP, and rejects active virtual IP conflicts.

**Independent Test**: Run session table tests with at least three simulated clients and verify distinct virtual IP mappings, outbound lookup, and `VIRTUAL_IP_CONFLICT` rejection.

### Tests for User Story 2

- [ ] T029 [P] [US2] Add unit tests for virtual IP assignment uniqueness in tests/unit/test_session_table.c
- [ ] T030 [P] [US2] Add unit tests for virtual IP lookup returning the owning session in tests/unit/test_session_table.c
- [ ] T031 [P] [US2] Add unit tests for peer address recording from CLIENT_HELLO in tests/unit/test_session_table.c
- [ ] T032 [P] [US2] Add integration test for three simultaneous simulated clients in tests/integration/test_handshake_flow.c
- [ ] T033 [P] [US2] Add integration test for VIRTUAL_IP_CONFLICT rejection without changing the existing session in tests/integration/test_handshake_flow.c

### Implementation for User Story 2

- [ ] T034 [US2] Implement virtual IP assignment insert, lookup, and release functions in src/session.c
- [ ] T035 [US2] Implement active virtual IP conflict detection and VIRTUAL_IP_CONFLICT rejection in src/session.c
- [ ] T036 [US2] Implement peer address capture from CLIENT_HELLO source metadata in src/session.c
- [ ] T037 [US2] Implement outbound virtual IP to session lookup helper in src/session.c
- [ ] T038 [US2] Update server handshake flow to reserve virtual IP during SERVER_HELLO in src/handshake.c
- [ ] T039 [US2] Document virtual IP conflict behavior and peer address mapping in docs/handshake-session.md

**Checkpoint**: User Story 2 works independently after US1; multiple simulated clients can be mapped and conflicts are rejected deterministically.

---

## Phase 5: User Story 3 - Recover from Loss and Expire Stale Sessions (Priority: P3)

**Goal**: The handshake has bounded retries, in-progress handshakes time out, established sessions expire after inactivity, and authenticated keepalive traffic can update the peer address.

**Independent Test**: Run loss, timeout, expiration, and peer rebinding tests from quickstart scenarios 3 through 6.

### Tests for User Story 3

- [ ] T040 [P] [US3] Add unit tests for retry schedule 1s, 2s, 4s, 4s in tests/unit/test_handshake_state.c
- [ ] T041 [P] [US3] Add unit tests for incomplete handshake expiration after 10 seconds in tests/unit/test_handshake_state.c
- [ ] T042 [P] [US3] Add unit tests for established session expiration after 45 seconds in tests/unit/test_session_table.c
- [ ] T043 [P] [US3] Add unit tests for duplicate, stale, and out-of-order control message handling in tests/unit/test_handshake_state.c
- [ ] T044 [P] [US3] Add integration test for lost SERVER_HELLO retry exhaustion in tests/integration/test_handshake_flow.c
- [ ] T045 [P] [US3] Add integration test for authenticated peer address rebinding in tests/integration/test_handshake_flow.c

### Implementation for User Story 3

- [ ] T046 [US3] Implement retry policy calculation and retry exhaustion transitions in src/handshake.c
- [ ] T047 [US3] Implement in-progress handshake timeout cleanup in src/handshake.c
- [ ] T048 [US3] Implement session idle expiration and virtual IP release in src/session.c
- [ ] T049 [US3] Implement KEEPALIVE, KEEPALIVE_ACK, CLOSE, and REJECT payload encode/decode in src/protocol.c
- [ ] T050 [US3] Implement duplicate and out-of-order control message handling in src/handshake.c
- [ ] T051 [US3] Implement authenticated peer address rebinding gate in src/session.c
- [ ] T052 [US3] Document retry, timeout, keepalive, expiration, and rebinding behavior in docs/handshake-session.md

**Checkpoint**: User Story 3 works independently after US1 and US2; loss and stale-session behavior are bounded and testable.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Tighten validation, documentation, and maintainability across all stories.

- [ ] T053 Run the full C test target and record results in specs/001-vpn-handshake-session/quickstart.md
- [ ] T054 Review protocol constants against specs/001-vpn-handshake-session/contracts/handshake-protocol.md
- [ ] T055 Review docs/handshake-session.md to ensure it states the protocol is educational and not production-grade security
- [ ] T056 Run formatting or style checks for include/vpn/protocol.h, include/vpn/handshake.h, include/vpn/session.h, src/protocol.c, src/handshake.c, and src/session.c

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies.
- **Foundational (Phase 2)**: Depends on Setup; blocks all user stories.
- **User Story 1 (Phase 3)**: Depends on Foundational.
- **User Story 2 (Phase 4)**: Depends on User Story 1 for established-session creation.
- **User Story 3 (Phase 5)**: Depends on User Story 1 and User Story 2 for sessions, mappings, and peer addresses.
- **Polish (Phase 6)**: Depends on all selected user stories.

### User Story Dependencies

- **US1**: Establishment MVP; can be delivered first.
- **US2**: Builds on established sessions to add multi-client mapping and conflict rejection.
- **US3**: Builds on sessions and mappings to add loss recovery, expiration, and rebinding.

### Within Each User Story

- Tests are written before implementation tasks for the same behavior.
- Protocol encode/decode tasks precede state-machine tasks that consume messages.
- Session table behavior precedes handshake integration that reserves or releases sessions.
- Integration tests are completed before each story checkpoint is accepted.

---

## Parallel Opportunities

- T003 and T004 can run in parallel after T001.
- T011 through T014 can run in parallel after T005 through T010 define the initial files.
- US1 test tasks T015 through T020 can run in parallel.
- US2 test tasks T029 through T033 can run in parallel.
- US3 test tasks T040 through T045 can run in parallel.
- Documentation tasks T039 and T052 can run after their corresponding behavior is implemented.

## Parallel Example: User Story 1

```bash
Task: "T015 [P] [US1] Add unit tests for valid and malformed common envelope parsing in tests/unit/test_protocol_parse.c"
Task: "T017 [P] [US1] Add unit tests for client state path IDLE to HELLO_SENT to FINISH_SENT to ESTABLISHED in tests/unit/test_handshake_state.c"
Task: "T019 [P] [US1] Add integration test for clean four-message establishment in tests/integration/test_handshake_flow.c"
```

## Parallel Example: User Story 2

```bash
Task: "T029 [P] [US2] Add unit tests for virtual IP assignment uniqueness in tests/unit/test_session_table.c"
Task: "T031 [P] [US2] Add unit tests for peer address recording from CLIENT_HELLO in tests/unit/test_session_table.c"
Task: "T033 [P] [US2] Add integration test for VIRTUAL_IP_CONFLICT rejection without changing the existing session in tests/integration/test_handshake_flow.c"
```

## Parallel Example: User Story 3

```bash
Task: "T040 [P] [US3] Add unit tests for retry schedule 1s, 2s, 4s, 4s in tests/unit/test_handshake_state.c"
Task: "T042 [P] [US3] Add unit tests for established session expiration after 45 seconds in tests/unit/test_session_table.c"
Task: "T045 [P] [US3] Add integration test for authenticated peer address rebinding in tests/integration/test_handshake_flow.c"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1 and Phase 2.
2. Complete Phase 3.
3. Validate clean establishment and pre-establishment data-plane rejection.
4. Stop and review the protocol API before expanding to multi-client routing.

### Incremental Delivery

1. US1 establishes one client session.
2. US2 adds virtual IP and peer-address mapping for multiple clients.
3. US3 adds retry, timeout, keepalive, expiration, and rebinding behavior.

### Validation Gates

- Each user story must pass its unit tests and integration test checkpoint.
- No story is complete if documentation implies production-grade security.
- No later data-plane task may accept traffic from a session below `ESTABLISHED`.
