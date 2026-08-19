1. Protect vpn_session_table_record_peer_address()
Choose one of these designs:
- Best: remove it from the public header and make it a private helper.
- Or change it so it requires an explicit authentication result and message type.
The function must reject updates when:
- session is not ESTABLISHED;
- authentication is not VPN_AUTH_OK;
- message is not an authenticated KEEPALIVE;
- message ID is duplicate or stale.
Keep vpn_session_table_capture_client_hello_peer() only for the initial handshake address. It must never update an established session.
The only established-session address update should happen inside authenticated keepalive processing:
1. Find the session.
2. Verify it is established.
3. Verify authentication.
4. Verify the message ID is newer.
5. Update last_seen_at_ms.
6. Update the peer address.
7. Store the accepted message ID.
Update all tests and callers so they use process_keepalive() instead of directly calling record_peer_address().
2. Make handshake timeout perform full cleanup
vpn_handshake_check_timeout() currently receives only the handshake context. It cannot remove a session without access to the session table.
Change the API so it receives the table:
vpn_handshake_check_timeout(context, current_time_ms, session_table)
Then, when the hard deadline is reached:
1. Set client and server states to FAILED.
2. Find the session by context->session_id.
3. Set its state to EXPIRED or CLOSED.
4. Release its virtual IP.
5. Clear its peer address.
6. Remove it from the session table.
7. Clear retry deadlines.
8. Return the timeout result.
Use one cleanup helper for both timeout and retry exhaustion, for example conceptually:
cleanup_failed_handshake(context, table)
Do not duplicate cleanup logic in multiple branches.
Update the header, implementation, and every caller consistently.
3. Test complete timeout cleanup
Add a test that:
1. Creates a handshake session.
2. Assigns it a virtual IP.
3. Sets the handshake deadline to 10 seconds.
4. Calls vpn_handshake_check_timeout() before the deadline.
5. Verifies the session still exists.
6. Calls it at the deadline.
7. Verifies:
   - both handshake states are FAILED;
   - session lookup by ID returns NULL;
   - virtual-IP lookup returns NULL;
   - the virtual IP can be assigned to a new session;
   - the peer address is no longer retained.
Also test retry exhaustion separately and verify it performs the same cleanup.
4. Add rebinding tests
Test all three cases:
- Unauthenticated address update: rejected; old address remains.
- Authenticated KEEPALIVE: accepted; new address is stored.
- Direct call to the old address-update API: unavailable or rejected.