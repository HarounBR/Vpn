# Quickstart: Validate VPN Handshake and Session Planning

This quickstart describes the expected validation flow for the handshake/session
feature before implementation proceeds.

## Prerequisites

- Linux development environment.
- C compiler and test runner selected during implementation.
- No external crypto library for project crypto behavior.
- Feature artifacts present under `specs/001-vpn-handshake-session/`.

## Validation Scenarios

### 1. Clean Establishment

1. Start a simulated server session table.
2. Send `CLIENT_HELLO` with a unique `client_id` and available virtual IP.
3. Verify server returns `SERVER_HELLO` with nonzero `session_id`.
4. Send `CLIENT_FINISH` for that `session_id`.
5. Verify server returns `SERVER_FINISH`.
6. Assert client and server state are both `ESTABLISHED`.

Expected result: establishment completes within 10 seconds and no data-plane
traffic is accepted before `SERVER_FINISH`.

### 2. Virtual IP Conflict

1. Establish session A with virtual IP `10.8.0.2`.
2. Attempt session B registration with the same virtual IP.
3. Verify session B receives `REJECT: VIRTUAL_IP_CONFLICT`.
4. Verify session A remains unchanged.

Expected result: active virtual IP ownership is stable and deterministic.

### 3. Lost Handshake Message

1. Drop the first `SERVER_HELLO`.
2. Let the retry interval elapse.
3. Verify the initial send is followed by retries at 1s, 3s, and 7s from handshake start.
4. Verify the fourth total transmission failing transitions the in-progress
   session to `FAILED` and cleans up its partial state.

Expected result: loss has bounded behavior and does not leave stale partial
session state.

### 4. Established Session Expiration

1. Establish one session.
2. Advance time beyond 45 seconds without authenticated traffic.
3. Run session cleanup.
4. Verify the session is removed and its virtual IP is released.

Expected result: stale sessions do not retain routing ownership.

### 5. Authenticated Peer Address Rebinding

1. Establish one session from peer address A.
2. Send unauthenticated traffic for the same `session_id` from peer address B.
3. Verify the stored peer address remains A.
4. Send an authenticated keepalive from peer address B.
5. Verify the stored peer address updates to B.

Expected result: NAT rebinding is supported only after session authentication.

### 6. Malformed and Out-of-Order Messages

1. Send a truncated envelope.
2. Send an unknown version.
3. Send `CLIENT_FINISH` before `SERVER_HELLO`.
4. Replay an already completed control message.

Expected result: each invalid case produces the documented rejection outcome or
idempotent duplicate response.

## Next Step

Run `/speckit-tasks` after this plan is accepted to generate implementation
tasks.
