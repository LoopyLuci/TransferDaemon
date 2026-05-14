# Development Plan

## Status: v1.0.0 Released — 120+ tests, 0 failures

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

### Sprint 7 — Terminal TUI (Phase 10.5–11)
- `transferd-tui` crate: ratatui 0.27 + crossterm 0.27 full terminal UI
- Onboarding, Chats, Contacts, Transfers, Settings tabs; all modals; call overlay
- `GrpcDaemon` / `MockDaemon` backends; 250 ms tick; 50 ms event poll
- `transferd-tui-video` crate: `VideoCallOverlay` with Kitty, Sixel, HalfBlock, ASCII backends
- Runtime capability detection; `TRANSFERD_VIDEO_BACKEND` override

### Sprint 8 — Real Media & E2E Tests (Phase 12–12.5)
- `DesktopMediaCapture` (feature `desktop-capture`): nokhwa webcam + cpal mic
- Bridges blocking hardware APIs into tokio channels via `spawn_blocking`
- Handles F32/I16/U16 audio formats; graceful fallback on missing hardware
- `new_default_capture()` factory: selects real or mock backend by feature flag
- `GrpcSignaling` module (feature `grpc-signaling`): thin gRPC wrapper for call signaling
- `tests/webrtc_e2e.rs`: full signaling pipeline — invite → accept → ICE → video frames
- Fixed broadcast-timing invariant: subscribe before `StartCall`

### Sprint 9 — Packaging & Release (Phase 13)
- WiX 4 MSI (`installer/windows/`): embeds all binaries, Start Menu + desktop shortcuts, `MajorUpgrade`
- Linux `.deb` (`dpkg-deb`, FHS layout, `.desktop` file)
- Linux `.rpm` (`rpmbuild` spec file)
- macOS `.dmg` (`.app` bundle, `Info.plist`, drag-to-Applications, optional notarization)
- macOS entitlements: camera, mic, network, file access for hardened runtime
- Git tag `v1.0.0`; `dist/TransferDaemon-1.0.0.msi` verified (5.7 MB)

---

## Next Steps (v1.1.0)

1. **Android camera/mic** — implement `MediaCapture` for Android (Camera2 + AudioRecord) behind the existing trait
2. **iOS camera/mic** — implement `MediaCapture` for iOS (AVFoundation) behind the existing trait
3. **Public relay deployment** — deploy relay nodes on public infrastructure
4. **Persistent storage** — encrypted SQLite via `rusqlite` for message history and transfer state
