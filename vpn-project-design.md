# Custom VPN in C — Design Document

## 1. Goal

Build a working VPN from scratch in C, on Linux, primarily as a vehicle to learn
low-level networking (TUN/TAP, raw socket I/O, event-driven servers) and applied
cryptography (implementing the cipher and key exchange ourselves, not using an
existing crypto library).

This is a **learning project**, not a production security tool. The custom
crypto exists to understand how VPNs work internally — it should never be
relied on to protect real sensitive traffic.

## 2. Scope decisions (locked in)

| Decision | Choice |
|---|---|
| Topology | Star: 1 server, N clients |
| Platform | Linux only (`/dev/net/tun`) |
| Transport | UDP |
| Crypto | Implemented by us (cipher + handshake/key exchange), no external crypto lib |
| Concurrency model | Single-threaded event loop (`epoll`) over TUN fd + UDP socket fd |
| IP hiding | NAT/masquerade on the server's egress interface (ops-level `iptables`/`nftables` config, not application code) |
| IP rotation | Out of scope for now — revisit after the core tunnel works end-to-end |
| Build order | Handshake / session state machine designed first, since it constrains the crypto module's API |

## 3. High-level architecture

Every node (server and client) runs the same core pipeline; only the
control-plane logic differs between them.

```
[TUN interface] <-> [Packet handler] <-> [Crypto layer] <-> [UDP transport] <-> [network]
                                              ^
                                              |
                                     [Session manager]   (server only:
                                              |            tracks all connected clients)
                                     [Control plane / handshake]
```

### Data flow — server, outbound (LAN → tunnel)
1. Packet arrives on the server's TUN interface.
2. Packet handler reads the destination virtual IP from the IP header.
3. Session manager looks up which client owns that virtual IP.
4. Crypto module encrypts the packet using that client's session key.
5. Transport module sends the ciphertext as a UDP datagram to that client's
   real (public) address.

### Data flow — server, inbound (tunnel → LAN)
1. UDP datagram arrives on the server's listening socket.
2. Transport hands the raw bytes + source address to the session manager.
3. Session manager identifies which session that source address belongs to.
4. Crypto module decrypts and verifies integrity using that session's key.
5. Packet handler writes the resulting plaintext IP packet into the TUN
   interface.

The client side is the same pipeline, just with a single fixed peer (the
server) instead of a session table.

## 4. Module breakdown

Each module should be a separate compilation unit with a narrow, well-defined
interface. Suggested build order is listed after the table.

### 4.1 Control plane / handshake state machine  *(design first)*
- Defines how a client registers with the server and how a session key is
  established.
- Proposed states: `HELLO → KEY_EXCHANGE → ESTABLISHED` (refine as the crypto
  design solidifies).
- Owns: connection setup/teardown logic, timeouts/retries for handshake
  packets.
- Does **not** own: encryption of ordinary data-plane traffic (that's the
  crypto module, invoked with whatever key this module negotiates).

### 4.2 Crypto module
- Exposes something like:
  - `encrypt(plaintext, session_key) -> ciphertext + integrity tag`
  - `decrypt(ciphertext + tag, session_key) -> plaintext | failure`
  - Key exchange primitive used during handshake.
- Owns all key material and cipher internals. No other module touches raw
  keys or cipher state directly.
- Open design questions to resolve here: which cipher to implement, how to
  derive the session key from the handshake, how to prevent replay attacks
  (e.g. sequence numbers / nonces), how integrity is verified (MAC).

### 4.3 Session manager (server only)
- Table of: virtual IP ↔ real UDP address ↔ session key ↔ last-seen time.
- Updated whenever a packet arrives from a client.
- Consulted whenever a packet needs to be routed to a client.
- This is the piece that turns a point-to-point tunnel into a real
  multi-client concentrator.

### 4.4 Transport module
- Owns the UDP socket(s).
- Sends/receives opaque byte blobs to/from a peer address.
- Knows nothing about what's inside the payload (encryption-agnostic).

### 4.5 TUN interface module
- Creates and configures `/dev/net/tun` (IP, MTU, interface up/down).
- Reads/writes raw IP packets from/to the kernel.
- Knows nothing about encryption or sockets.

### 4.6 Config / bootstrap
- Reads interface names, listen port, pre-shared identity material, etc.
- Keeps the rest of the system free of hardcoded values.

## 5. Concurrency model

Single-threaded event loop using `epoll`, watching both the TUN fd and the
UDP socket fd for readability. Chosen over a multi-threaded design because:
- The work per packet is small and I/O-bound, not CPU-bound (aside from
  crypto, which doesn't currently need to scale across threads).
- Avoids locking the session table entirely.
- `epoll` is the Linux-native idiom for this exact problem shape.

## 6. Suggested work breakdown (for splitting effort)

1. **Handshake / session state machine design** — define the message formats
   and state transitions on paper before writing any code (current focus).
2. **Crypto module** — implement cipher + key exchange against the interface
   the handshake design implies. Testable in isolation (encrypt → decrypt
   round-trip, known-answer tests).
3. **TUN interface module** — get raw packets flowing through a TUN device
   with no encryption yet (loopback sanity check).
4. **Transport module** — basic UDP send/receive, independent of the above.
5. **Session manager** — wire together TUN + transport + crypto for a single
   client (point-to-point first), then extend to multi-client.
6. **Integration** — full client/server, epoll event loop tying every module
   together.
7. **NAT/masquerade setup** — `iptables`/`nftables` config on the server for
   internet egress (ops task, not C code).

## 7. Open questions still to be decided

- Exact handshake message format (fields, encoding).
- Which cipher to implement, and why (this deserves its own design
  discussion — trade-offs between implementation complexity and the
  security properties you want to learn about).
- Replay protection scheme (sequence numbers, sliding window, etc.).
- Session timeout / keepalive strategy (how the server evicts stale
  clients).
- Error handling / logging conventions across modules.
