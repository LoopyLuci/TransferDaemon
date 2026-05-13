# Changelog

## v1.0.0 — 2025-05-13

### Initial production release

**Core data plane**
- DMI zero-copy ring buffer with mirrored hugepages and 128-byte `VBusDmiDescriptor`
- AES-256-GCM + BLAKE3 fused SIMD encryption via `DmiEncryptor`
- Hybrid post-quantum handshake: X25519 + ML-KEM-768 → `SessionKey`

**Transport**
- ECF-RG ATE multi-path scheduler with lane health monitoring
- `TransportLane` trait: `RelayLane` (UDP), `TcpLane` (binary-framed AES-GCM), `DmiLane`, `SwarmLane` (stub)
- `WireChunk` shared wire type; `ProtocolPlugin` + `PluginRegistry`

**Relay**
- Blind relay daemon (`relayd`) with BLAKE3 proof-of-work
- Forwarding table with TTL, ephemeral session tokens, no plaintext at relay

**gRPC daemon**
- Six tonic services: `AccountService`, `FriendService`, `MessageService`, `TransferService`, `SettingsService`, `CallService`
- `DaemonState` in-memory store; `add_all_services()` wires all services to a tonic server
- `CallService` with server-streaming `StreamCallEvents` via `tokio::sync::broadcast`

**Desktop UI**
- egui/eframe immediate-mode GPU UI, OLED dark theme, 420×740 window
- Pages: Home, Contacts, Chat (with call overlay), Transfers, Settings
- `DaemonApi` trait; `GrpcDaemon` for live daemon, `MockDaemon` for offline development
- Call overlay: Outgoing / Incoming / Active states with mute and hang-up controls

**Calls**
- `SimulatedCallSession`: full state machine (Idle → Outgoing/Incoming → Active → Ended)
- `MediaCapture` trait: `MockMediaCapture` (440 Hz sine + color-bar video), `SilentCapture`
- `CallManager` for single active call lifecycle
- ICE candidate pre-seeding and JSON roundtrip

**Mobile**
- `transferd-mobile` cdylib with C-ABI `start_daemon()` / `start_ui()`
- Platform dispatch: Android/iOS stubs, desktop no-op

**Launcher & Installer**
- `probe_daemon`, `wait_for_daemon`, `find_binary`, `spawn_daemon`
- Binary search: sibling directory → platform install prefix → PATH
- `install.sh` (Linux), `install_mac.sh` (macOS), `install.ps1` (Windows)
- Autostart: systemd user service / launchd agent / Windows scheduled task

**Test suite: 118 tests, 0 failures**
