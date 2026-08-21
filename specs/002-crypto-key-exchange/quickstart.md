# Crypto Feature Quickstart

## Scope

Run these checks without a TUN device, UDP socket, network peer, or external service. The feature is educational custom crypto and must not protect real sensitive traffic.

## Required checks

1. Build with the existing strict flags: `make clean && make test`.
2. Run primitive known-answer tests for SHA-256, HMAC-SHA-256, HKDF-SHA-256, X25519, ChaCha20, and Poly1305 using `tests/vectors/crypto_vectors.h`.
3. Derive two contexts from matching simulated client/server handoffs and compare transcript-bound outputs byte-for-byte.
4. Protect and open empty, ordinary, and maximum-bounded payloads. Mutate ciphertext, tag, nonce, session ID, direction, truncation, and length; each must fail without plaintext or replay-state changes.
5. Submit duplicate, stale, reordered, and cross-context records and verify the 64-message replay-window policy.
6. Verify matching confirmation succeeds, altered confirmation fails, and payload acceptance remains blocked after failed confirmation.
7. Complete `KEY_UPDATE` / `KEY_UPDATE_ACK`; verify new-context traffic succeeds and retired-context traffic fails.

## Recommended implementation validation

```bash
make clean && make test
make clean
make CFLAGS='-std=c11 -Wall -Wextra -Wpedantic -O2 -Iinclude' test
git diff --check
```

No command in this quickstart implies production security or full VPN readiness.
