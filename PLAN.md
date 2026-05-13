# Development Plan

## Status: Production-Ready — 118 tests, 0 failures

---

## Sprint History

### Sprint 1 — Core Data Plane (Phase 0–1)
- DMI zero-copy ring with mirrored hugepages
- AES-256-GCM + BLAKE3 fused encryption
- X25519 + ML-KEM-768 hybrid post-quantum handshake
- `DmiEncryptor`, `SessionKey`, `KeyPair`

### Sprint 2 — Relay & Transport (Phase 2–5)
- `relayd` blind relay with BLAKE3 PoW
- `RelayLane` (UDP), `TcpLane` (binary-framed AES-GCM), `DmiLane`, `SwarmLane` stub
- ECF-RG ATE scheduler, lane health monitoring
- `WireChunk`, `ProtocolPlugin`, `PluginRegistry`
- 23 relay integration tests

### Sprint 3 — Desktop UI (Phase 6)
- egui/eframe OLED dark-theme UI, 420×740 window
- Pages: Home, Contacts, Chat, Transfers, Settings
- `DaemonApi` trait, `MockDaemon`

### Sprint 4 — gRPC Layer (Phase 7–8)
- `transferd.proto` — 6 services, 30+ RPCs
- tonic codegen, `transferd-api` crate
- `GrpcDaemon` with 500ms connect timeout
- `CallService` server-streaming via broadcast channel
- `transferd-webrtc`: `SimulatedCallSession`, `MediaCapture`, `CallManager`
- Call overlay in Chat UI (Outgoing/Active/Ended states)
- 32 new tests (7 gRPC + 8 call gRPC + 17 session)

### Sprint 5 — Daemon Server & Mobile (Phase 9–9.5)
- Real daemon: `DaemonState`, 6 `*ServiceImpl`s, `add_all_services()`
- `transferd-mobile` cdylib: C-ABI `start_daemon()` / `start_ui()`
- Platform dispatch: Android stub, iOS stub, desktop no-op
- 16 daemon integration tests

### Sprint 6 — Launcher & Installer (Phase 10)
- `launcher` crate: `probe_daemon`, `wait_for_daemon`, `find_binary`, `spawn_daemon`
- `install.sh` (Linux: systemd + .desktop), `install_mac.sh` (macOS: launchd + .app), `install.ps1` (Windows: scheduled task + Start Menu + firewall)
- 10 launcher integration tests

---

## Next Steps

1. **`cargo-mobile` scaffolding** — run `cargo mobile init` to generate Android Gradle project and iOS Xcode project; wire `TransferDaemonApp` into the generated entry points
2. **Native rendering stubs** — replace `unimplemented!()` in `transferd-mobile/src/platform.rs` with real Android `SurfaceView` + `GLSurfaceView` and iOS `MTKView` bindings
3. **Native camera/mic** — implement `MediaCapture` for Android (Camera2 + AudioRecord) and iOS (AVFoundation) behind the existing trait
4. **Persistent storage** — encrypted SQLite via `rusqlite` for message history and transfer state
5. **Git tag v1.0.0** and publish to GitHub
