# transferd (Python)

A Python implementation of the [Transferd](../README.md) wire protocol. It follows the specification in [`docs/`](../docs/) and interoperates with the reference implementation in [`crates/`](../crates/).

## What is implemented

| Area | Module | How it is checked |
|------|--------|-------------------|
| Hybrid identity, node ids, key fingerprints | `identity`, `crypto` | `vectors/crypto.json` |
| Authenticated handshake (X25519 + ML-KEM-768, Ed25519 + ML-DSA-87) | `handshake` | reference vectors, loopback tests, live against `interop_peer` in both directions |
| Tunnel keys, sealed frames, 4096-wide replay window | `tunnel` | reference vectors, live |
| Overlay frames and their bincode bodies | `frames`, `bincode` | `vectors/wire.json`, every frame kind |
| Session opening: HELLO and HELLO_ACK, version negotiation | `session` | live against `interop_peer` in both directions |
| Stream multiplexer: send and receive sides, flow control, in-order delivery, SACK ranges | `mux` | a port of the reference's `mux.rs` unit tests |
| Stream engine: OPEN, DATA, ACK, WINDOW, CLOSE; SACK and duplicate-ACK losses; RTO resends | `streams` | engine rules with an explicit clock, loopback |
| Stream driver: reliable control frames, receipts, the timer, the asyncio read and write loops | `stream_session` | loopback over TCP, and live against `interop_peer echo` (600 KiB each way) |
| Invites (`tdov2:`) | `invite` | reference invites, and invites we make |
| Relay messages, proof of work, payload padding | `relay` | `vectors/wire.json` |
| Relay client: register, keepalive, locate, forward | `relay_client` | live against the reference `relayd` |
| Hole-punch probes and the gateway envelope | `punch` | `vectors/wire.json` |

**Not implemented yet:** route probing and failover across several links (the engine has one RTO estimator, not one per route), congestion control and pacing, the hole-punching state machine, mesh DNS, `transferd-cat`, the DHT node, and registering ghost keys with a relay. The stream engine resends on the RTO it is given and on the loss signals it sees; choosing among routes is not done.

## Install and test

Python 3.10 or later.

```bash
cd python
pip install -e ".[test]"
pytest
```

The live interop tests need the reference binaries. Without them they are skipped. Build them from the repository root, then point the tests at them:

```bash
cargo build -p transferd-overlay --example interop_peer
cargo build -p relayd --bin relayd
cd python
TRANSFERD_INTEROP_PEER=../target/debug/examples/interop_peer \
TRANSFERD_RELAYD=../target/debug/relayd \
pytest
```

On Windows the executables end in `.exe`, and the variables are set with `set NAME=value` (cmd) or `$env:NAME = "value"` (PowerShell).

## Layout

- `transferd/` is the package. Each module corresponds to a part of the specification.
- `tests/` holds the vector-driven tests, the loopback handshake tests, and the live interop tests. The vectors are read from [`../vectors/`](../vectors/), which the Rust reference examples generate.

## Notes

- Values that are `u64` on the wire and can exceed 2^53 (attempt ids, nonces, proof-of-work nonces, tunnel counters) are Python `int`s and are never converted to floats.
- The package depends on `cryptography` (X25519, AES-GCM, ML-KEM, ML-DSA, Ed25519) and `blake3`.
