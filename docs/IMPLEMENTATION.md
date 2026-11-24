# Implementing Transferd

## Reference Implementation

The reference implementation is in this repository, under [`crates/`](../crates/). It is one Cargo workspace with no dependency outside it. The crates that carry this specification:

| Crate | Role |
|-------|------|
| `transferd-crypto` | Hybrid identity, handshake, key derivation, AES-GCM |
| `transferd-core` | Adaptive multi-path scheduling and the transport lane trait |
| `transferd-overlay` | Session, streams, routes, congestion control, hole punching, invites |
| `transferd-dns` | Host-name resolution with DNSSEC checks, used by the overlay's mesh DNS |
| `relayd` | Blind relay (`relayd`, and `relayd-ws` for WebSocket) |
| `transferd-relay` | DHT bootstrap node (`dhtd`) |
| `transferd-cat` | `netcat` over Transferd, a small client built on the same crates |
| `ring-channel` | Zero-copy ring used on the local data path |

The wire protocol is independent of any user interface and of the TransferDaemon application's control plane (its gRPC API and control hub). The crate names describe this codebase's internal layout. They are informative and may change; the specification is what matters for interoperability.

## Building a Conforming Node

A minimal conforming node must:

1. Implement the hybrid handshake and tunnel framing exactly as specified in [PROTOCOL.md](PROTOCOL.md).
2. Speak the frame kinds it claims to support, and correctly ignore unknown kinds and trailing fields.
3. Honor the version negotiation rules.
4. When acting as a relay, implement the token registration and blind forwarding rules in [RELAY.md](RELAY.md).
5. Protect long-term identity material.

Optional but recommended:

- Hole punching (version ≥ 3)
- Congestion control and pacing
- Constant-rate padding for additional metadata protection

## Testing Interoperability

The reference implementation's overlay tests cover the behavior in this specification. They are in [`crates/transferd-overlay/tests`](../crates/transferd-overlay/tests):

- `paths.rs`: a current peer, a peer limited to version 1 (`max_version = 1`) and a simulated newer peer each agree on the highest common version.
- `punch.rs`: two cone NATs get a punched route beside the relay, and a stream crosses it. A symmetric NAT cannot be punched and the relay keeps working. A stranger's probe is ignored. A peer that agreed on an older version is never sent a punch frame.
- `lossy.rs`: the relayed path loses a fifth of its datagrams in both directions, and everything still arrives.

From the root of this repository, `cargo test -p transferd-overlay` runs them. The end-to-end conformance tests in [`crates/transferd-conformance/tests`](../crates/transferd-conformance/tests) drive the handshake, the tunnel, the lanes and the relay together; `scripts/test-core.sh` runs every check. An independent implementation can use the same scenarios as its acceptance tests.

Two independent implementations live in this repository, and both test against the reference over the network:

- [`python/`](../python/) (`python/tests/test_interop.py`, `test_relay_interop.py`) runs the session opening in both directions against `interop_peer`, and drives the reference `relayd` as a client.
- [`typescript/`](../typescript/) (`test/interop.test.ts`, `test/relay_interop.test.ts`) does the same.

Both check every frame, tunnel and proof-of-work value against the reference vectors in [`vectors/`](../vectors/), which the Rust examples in `crates/transferd-crypto` and `crates/transferd-overlay` generate. The live tests are built on `interop_peer`, an example in `crates/transferd-overlay` that speaks the handshake and HELLO exchange over TCP.

## Protocol Evolution

All changes to frame formats, key derivation labels, or version ranges are made in this repository first, then implemented. The documents here are the source of truth for the wire protocol. If an implementation behaves differently from them, the difference is a bug in one or the other, and should be reported as an issue in this repository.
