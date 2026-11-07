# Transferd protocol in TransferDaemon

The wire protocol that TransferDaemon speaks is specified in its own repository:

**https://github.com/LoopyLuci/Transferd** — start with [docs/PROTOCOL.md](https://github.com/LoopyLuci/Transferd/blob/main/docs/PROTOCOL.md) for the bytes and [docs/OVERLAY.md](https://github.com/LoopyLuci/Transferd/blob/main/docs/OVERLAY.md) for the behavior.

This page covers only what is specific to this implementation: which protocol versions it speaks, where each part of the specification lives in the code, and how it is tested. If this page and the specification disagree, the specification wins, and the disagreement is a bug to report.

## Versions this build speaks

| Constant | Value | Where |
|---|---|---|
| `VERSION_MIN` | 1 | `crates/transferd-overlay/src/protocol.rs` |
| `VERSION_CURRENT` | 3 | `crates/transferd-overlay/src/protocol.rs` |
| `VERSION_PUNCH` (hole punching) | 3 | `crates/transferd-overlay/src/protocol.rs` |
| Handshake version | 2 | `transferd_crypto::auth_handshake` |
| Ciphersuite | `0x0002` (X25519 + ML-KEM-768, Ed25519 + ML-DSA-87) | `crates/transferd-crypto` |

A node negotiates the highest version both peers speak. A peer outside `1..=3` is refused at HELLO.

## Where each part lives

| Specification section | Implementation |
|---|---|
| §1 Identity and handshake | `crates/transferd-crypto` (`auth_handshake`) |
| §2 Tunnel and replay window | `crates/transferd-overlay/src/wire.rs` (`REPLAY_WINDOW` = 4096) |
| §3 Relay encapsulation and `Locate` | `crates/transferd-overlay`, `crates/relayd` |
| §4 Frames and kinds | `crates/transferd-overlay/src/protocol.rs` (`MAX_BODY` = 60 KiB) |
| §5 Session, streams, flow control, routes | `crates/transferd-overlay/src/session.rs`, `mux.rs` |
| §6 Invites | `crates/transferd-overlay` |
| §7 Compatibility | `protocol.rs` (version range), `state.json` migration in the overlay state code |
| §8 Hole punching | `crates/transferd-overlay/src/punch.rs` (probes, `TDPB` and `TDGW` envelopes) |
| Per-route congestion control | `crates/transferd-overlay/src/cc.rs` |

The gRPC control plane (`transferd-api`) is a separate interface between the daemon and its user interfaces. It is not part of the wire protocol.

## Tests that exercise the wire format

- **Versions.** A current peer talking to an older one (`max_version = 1`) and to a simulated newer one, each agreeing on the highest common version.
- **Hole punching.** Two port-restricted cone NATs give a punched route that carries a stream with the relay removed. A symmetric NAT fails cleanly and the relay carries the stream. A replayed probe from a stranger is ignored.
- **Loss.** Streams through a relay path that drops 20% of datagrams each way arrive intact and in order.

Run them with `cargo test -p transferd-overlay`.

## Notes for this codebase

- The fixed strings `TransferDaemon-overlay-*` in the key derivation are wire-visible. They are kept unchanged. Changing them would break every existing pairing.
- The per-route retransmission timer is adaptive in `cc.rs`. `session.rs` also defines a fixed 400 ms resend interval. Which one governs resends should be confirmed, and [the specification §5](https://github.com/LoopyLuci/Transferd/blob/main/docs/PROTOCOL.md) updated to match.
