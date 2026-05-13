# Architectural Context

This document records the non-obvious design decisions in TransferDaemon. Each decision has a constraint that drove it — knowing the constraint helps judge future changes.

---

## 1. 128-byte DMI Descriptor

`VBusDmiDescriptor` is exactly 128 bytes (two cache lines on x86). This is intentional: a descriptor fits in a single cache-line pair, so producer and consumer never share a cache line, eliminating false sharing without padding.

## 2. Mirrored Hugepage Ring

The ring buffer maps the same hugepage twice at consecutive virtual addresses. This means a read or write that crosses the ring boundary never needs a wrap-around branch — the OS handles it transparently. The producer writes sequentially; the consumer reads sequentially. Branch-free hot path.

## 3. ECF-RG ATE Scheduler

Earliest Completion First with Reorder Guard. ECF minimises per-message latency under congestion; the Reorder Guard ensures chunks arrive in-order at the reassembler even when lanes have different RTTs. ATE = Adaptive Traffic Engine — it adjusts lane weights based on measured throughput and loss.

## 4. Blind Relay Design

`relayd` never decrypts payload. It forwards `(session_token, ciphertext)` tuples. The session token is a BLAKE3 hash of a PoW nonce — this rate-limits relay abuse without requiring accounts. The relay cannot learn sender, receiver, or content.

## 5. Zero Metadata Leakage

Message size is padded to power-of-two before encryption. Timing is jittered at the relay. The relay sees only fixed-size ciphertext blobs. Sender and receiver IP addresses are the only unavoidable metadata, and even those are hidden when using Tor transport (future work).

## 6. Post-Quantum Agility

The handshake mixes X25519 (classical) and ML-KEM-768 (post-quantum). The session key is `BLAKE3(x25519_shared || mlkem_shared)`. If either primitive is broken, the other still provides security. The algorithm identifiers are negotiated in the handshake header, so new KEMs can be added without breaking existing clients.

## 7. Hardware-Bound Keys (future)

The `transferd-crypto` crate exposes a `KeyStore` trait. The current implementation stores keys in RAM only (zeroized on drop). A future `HardwareKeyStore` will bind keys to TPM 2.0 (Windows) or Secure Enclave (macOS/iOS) via the same trait, with no changes to the protocol layer.

## 8. Single Socket Transport (SST)

All lanes — relay UDP, direct TCP, DMI — multiplex over a single logical connection per peer using `WireChunk { lane_id, seq, payload }`. This avoids the TCP head-of-line blocking problem while keeping the number of open sockets bounded.

## 9. TDON (Transfer Daemon On-demand Network)

The launcher does not require the daemon to be running. `probe_daemon()` checks liveness; if the daemon is absent, `spawn_daemon()` starts it and `wait_for_daemon()` polls until ready. This means users can kill the daemon and the next UI launch restarts it automatically.

## 10. Launcher Binary Search Order

1. Sibling of the current executable (installed state)
2. Platform install prefix (`~/.local/bin` or `%LOCALAPPDATA%\TransferDaemon\bin`)
3. `$PATH` (development state)

The sibling check comes first so a portable installation (e.g., USB drive) always uses its own binaries, not a system-wide install.

## 11. DaemonApi Trait

`DaemonApi` is an `async_trait` abstraction over both `GrpcDaemon` (live daemon) and `MockDaemon` (offline dev/test). The UI never knows which it has. This makes the UI fully testable without a running daemon and lets the mobile embedding inject a different implementation.

## 12. No External Services

TransferDaemon has zero runtime dependencies on external servers — no update servers, no telemetry endpoints, no STUN/TURN servers (the relay replaces TURN). The only network traffic is peer-to-peer and relay traffic that the user explicitly initiates.
