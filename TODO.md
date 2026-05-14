# TODO

## Completed (Phases 1–10)

- [x] Phase 0 — DMI zero-copy ring, `VBusDmiDescriptor`, hugepage mapping
- [x] Phase 1 — AES-256-GCM, BLAKE3, ML-KEM-768 hybrid handshake, `DmiEncryptor`
- [x] Phase 2 — `RelayLane` (UDP), BLAKE3 PoW, forwarding table with TTL, `relayd`
- [x] Phase 3 — Relay integration tests (23 tests)
- [x] Phase 4 — ECF-RG ATE scheduler, `TransportLane` trait, lane health monitoring
- [x] Phase 5 — `TcpLane`, `SwarmLane` stub, `ProtocolPlugin`, `PluginRegistry`, `WireChunk`
- [x] Phase 6 — egui/eframe UI: Home, Contacts, Chat, Transfers, Settings pages; `MockDaemon`
- [x] Phase 7 — `transferd-api` protobuf schema (5 services), tonic codegen, `GrpcDaemon`, 7 gRPC integration tests
- [x] Phase 8 — `CallService` proto (6 RPCs + streaming), `transferd-webrtc` crate, `SimulatedCallSession`, `MediaCapture`, call overlay in Chat UI, 25 new tests
- [x] Phase 9 — Real daemon gRPC server (`DaemonState`, 6 `*ServiceImpl`s, `add_all_services()`), 16 daemon integration tests
- [x] Phase 9.5 — `transferd-mobile` cdylib with C-ABI `start_daemon()` / `start_ui()`
- [x] Phase 10 — `launcher` crate, `probe_daemon`, `find_binary`, `spawn_daemon`, 10 tests; `install.sh`, `install_mac.sh`, `install.ps1`

- [x] Phase 10.5 — `transferd-tui` crate: full ratatui terminal UI, all screens, modals, call overlay
- [x] Phase 11 — `transferd-tui-video` crate: 4 video backends (Kitty, Sixel, HalfBlock, ASCII), runtime detection
- [x] Phase 12 — `DesktopMediaCapture` (nokhwa + cpal, feature `desktop-capture`), `new_default_capture()` factory
- [x] Phase 12.5 — `GrpcSignaling` module, WebRTC e2e integration test (`webrtc_e2e.rs`)
- [x] Phase 13 — Packaging: Windows MSI (WiX 4), Linux .deb/.rpm, macOS .dmg + entitlements; `v1.0.0` git tag

**Total: 120+ tests, 0 failures**

## v1.1.0 Planned

- [ ] Android camera/mic integration (Camera2 API + AudioRecord) behind `MediaCapture` trait
- [ ] iOS camera/mic integration (AVFoundation) behind `MediaCapture` trait
- [ ] Public relay node deployment
- [ ] `SwarmLane` real implementation (libp2p or custom DHT)
- [ ] Hardware-bound keys: TPM 2.0 (Windows), Secure Enclave (macOS/iOS)
- [ ] Tor transport layer for sender/receiver IP anonymity
- [ ] App store packaging (F-Droid, Mac App Store sandboxing)
- [ ] Hardware wallet integration for identity key storage
- [ ] Mesh-only mode (no relay, direct peer connections only)
- [ ] Persistent message store (encrypted SQLite via `rusqlite`)
- [ ] File resume: track transferred ranges, resume interrupted transfers
- [ ] Multi-device identity sync via QR code
