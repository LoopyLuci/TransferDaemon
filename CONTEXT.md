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

## 13. Protocol v2 - Authenticated Hybrid Wire Format

The peer handshake is Protocol v2 (see `transferd_crypto::auth_handshake`), replacing the original X25519-only scheme. Every flight is a self-describing envelope: protocol version + ciphersuite id + X25519 key + ML-KEM-768 key material + the peer's 2624-byte hybrid identity (Ed25519 || ML-DSA-87) + a BLAKE3 transcript + a hybrid signature over the transcript. The signature binds the ephemeral key exchange to the long-term identity, so a man-in-the-middle cannot substitute key material without the victim's signing key. The ML-KEM serialization ("the ml-kem crate lacks public encode/decode") was solved via the `kem` crate's `KeyExport`/`TryKeyInit` traits; note the ML-KEM ciphertext type is already raw bytes.

## 14. Ciphersuite Registry with Sunset Dates

`CIPHERSUITES` (in `auth_handshake.rs`) records every ciphersuite with `introduced`/`sunset` year-months plus `negotiate()`/`newest_active()`. Handshake negotiation picks the newest non-sunset suite both peers support, so new KEMs can be added and old ones retired without breaking existing clients - the protocol-evolution story.

## 15. Peer-Identity Enforcement + Trust-on-First-Use + Safety Numbers

Session establishment (`establish_tcp_session`/`establish_relay_session`) now verifies the peer's authenticated Ed25519 identity against the contact's public key - a poisoned relay/DHT can no longer swap you onto an attacker's session. On first verified contact the full hybrid fingerprint is persisted (`Contact.hybrid_public_key`); a changed identity on later sessions is refused. Both peers derive the same Signal-style safety number from `BLAKE3(lo || hi)` of the two canonical-sorted hybrid identities, shown in the chat header for out-of-band verification.

## 16. Inbound Notification Hook

The daemon exposes a global `set_inbound_notify` callback fired on each new inbound 1:1 text. The mobile embedding sets it to raise a system notification via a JNI bridge (`transferd_mobile::notifications`). Desktop can hook the same seam for OS notifications later.

## 17. Manual-Only Update Policy (reconciled with #12)

An auto-updater exists (`transferd::update`), but it is wired strictly opt-in: a Settings "Check for updates" button calls a new `UpdateService` RPC only when the user clicks it. There is no background phone-home, preserving decision #12's "no automatic external traffic" guarantee.

## 18. Desktop-Gated Native Dialogs

`rfd` (native file dialogs for QR import) is a target-gated dependency (`cfg(not(any(android, ios)))`) because rfd has no mobile backend. This keeps the Android build clean - a break that otherwise surfaces only when cross-compiling.

## 19. Local On-Device CI/CD Pipeline

`build_pipeline.ps1` (repo root) is the canonical local pipeline for BOTH artifacts: preflight (toolchain + connected device), static (check + clippy -D warnings), tests + deterministic wire fuzz, desktop EXE release build, Android APK (3 ABIs -> gradle -> apksigner), and deploy+smoke to a connected Android device (adb install, launch, wait for "Daemon ready" + "gRPC connected"). It is incremental (cargo/gradle caches), fail-fast, logs a JSON summary, and supports `-Fast`/`-SkipTests`/`-SkipExe`/`-SkipApk`/`-SkipDeploy`/`-RequireDevice` for CI-loop use. CI (`.github/workflows/ci.yml`) mirrors it and adds a 2M-iteration fuzz job.

## 20. Per-Message Forward Secrecy (Double Ratchet)

Established on top of the authenticated hybrid handshake: the session key becomes the ratchet ROOT (`transferd_crypto::ratchet::DoubleRatchet`). Each message is encrypted under a fresh key derived from a BLAKE3 KDF chain, and every `RATCHET_INTERVAL` (10) sends the sender performs an X25519 DH ratchet that mixes a fresh ephemeral into the root. Compromising one message key (or even the session key) reveals neither earlier messages (forward secrecy) nor messages sent after a DH ratchet (future secrecy). The chunk payload is now `bincode(RatchetMessage)` wrapping the AES-256-GCM'd WireMsg; the initiator's `PeerSession`, the TCP responder (`transport.rs`) and the relay responder (`relay_hub.rs`) each own a ratchet aligned by role. In-order delivery is assumed (the lane + GSN reassembly guarantee it), so no skipped-key store is needed - documented for any future unordered transport. **Post-quantum future secrecy**: each DH ratchet step ALSO performs an ML-KEM-768 encapsulation (fresh keypair, encapsulate to the peer's published ML-KEM ek, mix `kem_ss` into the root alongside the X25519 DH output via `root = KDF(root, x25519_ss ‖ kem_ss)`). The first message publishes both the X25519 pk and the ML-KEM ek; a DH-step message carries the 1088-byte KEM ciphertext. An attacker holding every classical secret cannot derive post-ratchet keys - the quantum component protects future secrecy exactly as the handshake's hybrid exchange protects the session. `RatchetMessage` gained `kem_ek`/`kem_ct` (serde-defaulted, so old/new envelopes interoperate).

## 21. Mobile daemon.config (relay/DHT settings file)

Android processes cannot be given env vars, so `daemon_thread::spawn_with_config` reads `<files>/TransferDaemon/daemon.config` (`KEY=VALUE` lines) and applies `TRANSFERD_PORT` / `TRANSFERD_RELAY_ADDR` / `TRANSFERD_DHT_BIND` / `TRANSFERD_DHT_BOOTSTRAP` / `TRANSFERD_DIFFICULTY` as env defaults (real env wins; missing file is a no-op). This lets the mobile app be pointed at a relay/DHT without a code change - used to verify relay delivery on-device.

## 22. UDP Cross-Host Rules (learned on the wire)

Three hard-won facts from the desktop<->Kindle relay E2E: (1) `adb forward/reverse` is TCP-only, so a UDP relay/DHT can NEVER be reached through adb - the peers must share a LAN/subnet. (2) A UDP socket bound to `127.0.0.1` cannot route to a non-loopback destination, and a node bound to `0.0.0.0` advertises an unreachable address to remote peers - bind explicit LAN IPs for cross-host DHT nodes. (3) A UDP server's reply must go to the datagram's actual `src`, not the peer's advertised address (the `handle_request` in `transferd-relay::dht` did the latter - fixed). A node's advertised address is whatever it bound; loopback or wildcard binds break remote peers.

## 23. relayd recv-loop resilience

`relayd`'s main loop propagated `recv_from` errors with `?` - on Windows a stale UDP datagram to a just-closed client socket surfaces as `WSAECONNRESET` (10054) on the NEXT recv, killing the relay with an ICMP-triggered error that Linux never sees. The recv loop now logs and `continue`s with a 10ms backoff instead of exiting. Rule: UDP servers must never treat a transient recv error as fatal.

## 24. The transport tick is library code, not binary code

`process_all_sessions` (the 50ms tick that flushes queued messages over lanes, applies acks/inbound, and marks "sent") originally lived ONLY in the desktop `transferd` binary's `main.rs`. The mobile daemon - which boots the same library - never spawned it, so the mobile daemon could RECEIVE but never SEND: messages stayed "pending" forever. Extracted as `transferd::transport::spawn_transport_tick(state)` and called from the binary, the mobile `daemon_thread`, and any embedder (e.g. probes). Anyone spawning a daemon via the library must call it.

## 25. Relay hub session map is per-peer-token (FIXED)

`RelayHub::sessions` is keyed by the PEER's relay token only, so a peer that initiates to us AND that we initiate to cannot hold both roles simultaneously - the second handshake overwrites the first session. Consequence: a desktop that initiated a session to the Kindle cannot cleanly receive the Kindle's own reverse-initiated session reply (observed in the on-device relay E2E: inbound delivery works, the reverse reply leg does not). **Fixed**: sessions are keyed by `(peer_token, we_initiated)`, so both roles coexist; `handle_chunk` tries each role's recv-key and keeps whichever passes the GCM tag. Proven by `text_round_trips_between_two_daemons_over_relay` and a live desktop↔Kindle bidirectional conversation over the LAN relay. Two related bugs found while proving it: `store_inbound_text` dedup'd by `msg_id` alone (the per-daemon "d-N" counter makes ids collide across peers, silently dropping inbound messages) - now dedups on `(sender_pk, msg_id)`; and the two relay tests raced on the process-global `TRANSFERD_RELAY_ADDR` env var - now serialized behind a test lock.

## 26. Hosted relay deployment (Internet-routability)

Decision #12's 'relay replaces TURN' claim needs a publicly reachable relay+DHT pair. The deployment package (deploy/relayd.Dockerfile + docker-compose.yml + docs/DEPLOYMENT.md) runs elayd (blind UDP relay) + dhtd (DHT bootstrap) on a VPS. NAT-friendliness is by design: clients register + keepalive every 45s (inside the 90s relay TTL, and inside home-NAT UDP mapping timeouts), relayd replies to the datagram's actual src, and discovery is bootstrap-centric (NAT'd clients publish to / look up through the public bootstrap). The one real code gap fixed for public operation: a DHT node bound to 0.0.0.0 advertised an unreachable address (the #22 wildcard problem, now fatal on a public node) - DhtNode::start_with_advertised + TRANSFERD_DHT_ADVERTISE let it advertise the public address. Live Internet E2E requires an actual VPS (not available in this environment); the Docker image build was also not verifiable here (Docker engine down).

## 27. Multi-relay + auto-routing

A peer publishes a LIST of relay endpoints (PeerEndpoint.relays, serde-defaulted); TRANSFERD_RELAY_ADDR takes a comma-separated list; the daemon registers its identity token on every relay (the token is identity-derived, so it is the same on all of them). A session builds one lane per shared relay; the ATE ranks all lanes (equal-RTT tie-break prefers the relay that survived the handshake) and fails over when a relay dies - proven by 	ext_round_trips_over_two_relays_with_failover (both directions survive killing one relay). The handshake is routed through the first relay that RESPONDS, so a dead relay cannot block a session with live paths.

## 28. WebSocket relay + Cloudflare free-tier relay

elayd-ws forwards the same blind, PoW-authenticated blobs over WebSocket frames (identical relayd::protocol wire format), traversing any NAT/firewall. The Cloudflare Worker (deploy/cloudflare-worker/) implements the relay as a Durable Object on Cloudflare's edge - zero servers, free tier - using byte-level bincode (token = body[0..32]; DeliveredMsg body == ForwardMsg body[40..]) so the same client logic speaks to it. PoW is intentionally off in the Worker (edge rate-limit + per-IP bucket); self-hosted relayd/relayd-ws keep full BLAKE3 PoW. The daemon's relay lanes are now UDP AND WebSocket: TRANSFERD_RELAY_ADDR accepts ws:// entries, RelayWsClient/RelayWsLane route the daemon through relayd-ws or the Worker, PeerEndpoint publishes ws:// addresses (resolve returns wsrelay://), and establish_relay_session builds a WS lane per shared WS relay - proven by text_delivers_between_two_daemons_over_ws_relay.
