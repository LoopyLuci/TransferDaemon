# Changelog

## v1.0.0 — 2026-05-14

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

**Terminal TUI**
- `transferd-tui` crate: full ratatui 0.27 + crossterm 0.27 terminal UI
- Onboarding flow (Welcome → EnterName → ShowPhrase → ConfirmPhrase), BIP-39 + Ed25519
- Tabs: Chats (split pane, message history, send input), Contacts, Transfers (Gauge progress bars), Settings
- Live call overlay — corner widget for audio calls, right-half overlay for video
- Modals: AddContact (QR / hex key), SendFile, ConfirmDelete, ShowQr, RevealPhrase
- `GrpcDaemon` (live) / `MockDaemon` (offline fallback) — same `DaemonApi` trait as egui UI
- 250 ms tick for transfer and video refresh; 50 ms crossterm event poll

**Terminal video calling**
- `transferd-tui-video` crate: `VideoCallOverlay` widget with four adaptive rendering backends
- **Kitty graphics protocol** — APC escape sequences, chunked base64 RGBA, image ID reuse
- **Sixel protocol** — DCS band encoding, 216-color cube palette, RLE compression
- **Half-block Unicode** — `▀` with per-cell Rgb fg/bg mapped to camera pixel pairs (default fallback)
- **ASCII art** — luminance-mapped characters for basic terminals
- Runtime capability detection from `TERM` / `TERM_PROGRAM` / `COLORTERM`; override via `TRANSFERD_VIDEO_BACKEND`
- `DesktopMediaCapture` (feature `desktop-capture`): real webcam via **nokhwa** (MSMF/v4l2/AVFoundation) and real microphone via **cpal** (WASAPI/ALSA/CoreAudio); graceful hardware-absent fallback to silence / no-video

**WebRTC end-to-end test harness**
- `GrpcSignaling` module in `transferd-webrtc` (feature `grpc-signaling`): thin gRPC wrapper for `StartCall`, `AcceptCall`, `SendIceCandidate`, `EndCall`, `StreamCallEvents`
- `tests/webrtc_e2e.rs`: full gRPC signaling flow — invite → accept → ICE exchange → video frame delivery, using `SimulatedCallSession` + `MockMediaCapture` loopback
- Fixed broadcast-timing invariant: both subscribers must call `StreamCallEvents` before `StartCall`
- Fixed `daemon_restore_identity_twelve_words` test: replaced hardcoded invalid BIP-39 phrase with dynamically generated one

**Packaging**
- `installer/windows/TransferDaemon.wxs` — WiX 4 MSI; embeds all four binaries, creates Start Menu entry + desktop shortcut, supports `MajorUpgrade`
- `installer/windows/build.ps1` — automated build + MSI pipeline; `installer\windows\build.ps1` produces `dist/TransferDaemon-1.0.0.msi` (5.7 MB)
- `installer/linux/build-deb.sh` — `dpkg-deb` package with FHS layout, `.desktop` file
- `installer/linux/build-rpm.sh` — `rpmbuild` spec-file pipeline
- `installer/macos/build-dmg.sh` — `.app` bundle, `Info.plist`, drag-to-Applications DMG; optional `codesign` + `xcrun notarytool` hooks
- `installer/macos/entitlements.plist` — hardened runtime entitlements for camera, mic, network, and file access

**Test suite: 120+ tests, 0 failures**
