# Changelog

## Unreleased

### Appearance settings — theme, accent color, UI scaling, text size

- **Theme**: OLED / Dark / Light / High Contrast (was already present).
- **Accent color** (new): 8 presets (blue, green, orange, purple, red, teal,
  pink, amber) — swatch picker in Settings. The accent re-themes buttons,
  active tabs, outbound bubbles, focus borders and selection globally.
- **UI scaling** (new): 0.8–1.4 slider — zooms the whole interface (layouts,
  spacing, touch targets) on top of the platform density.
- **Text size** (new): 0.85–1.4 slider — scales text further without changing
  layout density.
- Both sliders have a "Reset" (100%) button; every control has hover help.
- **Persistence**: all four preferences are saved to the local DB
  (`appearance.*`) and restored on next launch (legacy `theme` key still read).
- **Scaling model**: `pixels_per_point = base_density × ui_scale × font_scale`.
  On Android the base is the device density (so Display-size changes still
  re-track); on desktop it is the OS-DPI value captured on first frame. The
  multiplier model means every element — including explicitly-sized text —
  scales globally on any screen.
- Refactor: `UiPreferences` is the single appearance struct; `DesignTokens`
  derives palette (with accent override), scaled typography and theme from it.

### High-quality responsive UI (Android + Desktop)

- **Scrollable bottom nav bar (phone)**: each tab is a fixed comfortable width;
  tabs that don't fit are reached by side-scrolling (touch drag, mouse drag, or
  shift+wheel). No more squeezing 7 tabs into whatever width is available.
- **Auto-reveal**: when the active tab changes, the strip scrolls the tab into
  view (centers it) — one-shot, so manual side-scrolling is never overridden.
- **Left nav rail (tablet/desktop)**: at widths >= 600pt the bottom strip
  becomes a vertical navigation rail on the left edge — the standard desktop
  pattern — so the app scales from a phone up to a maximized desktop window.
- **Polish**: active tab renders as an accent pill with inverse text + subtle
  border stroke; consistent touch targets.

## v2.2.0 - 2026-09-27

### WS relay resilience (from the on-device E2E)

- **Self-healing WS client**: `RelayWsClient` is now a connection manager —
  reconnects + re-registers with backoff on a dropped socket, feeds a stable
  inbound channel, and re-registers every 45s so registrations survive relay
  hibernation. A dead relay link no longer lapses a registration forever.
- **Worker hibernation recovery**: the DO rebuilds its token→socket map from
  `state.getWebSockets()` on every message (token persisted on `_meta`), so
  forwards route again after a free-tier hibernation wake.
- **Authority-based relay matching**: `ensure_contact_session` matches relays
  by hostname:port (not resolved IP), fixing DNS round-robin breaking sessions
  on DNS-named relays (Cloudflare Worker).
- `mobile_identity` example (create/fetch an on-device identity via adb
  forward) + an ignored desktop→real-Kindle E2E test. 250 tests, clippy clean.

### Data-transfer limits (presets + custom) at every layer

- **Limits model** (`relayd::limits`): `Preset` quick-picks (1 MB → 5 GB +
  Unbounded), `MaxBytes { preset | custom }`, content types
  (message/photo/video/voice/file/call, MIME-classified), `TransferLimits`
  (per-type caps + daily/weekly/monthly budgets). One serde/bincode-stable
  model shared by users and relay nodes.
- **Relay nodes enforce**: `relayd`, `relayd-ws` and the Cloudflare Worker
  refuse over-size blobs (`MAX_BLOB_BYTES`) and per-token bandwidth budgets
  (`MAX_MB_PER_DAY/WEEK/MONTH`) via a rolling `BandwidthTracker` — an
  over-budget FORWARD is refused before the relay commits bandwidth.
- **Peers enforce**: `PeerEndpoint.limits` + `Contact.limits` advertise what a
  peer accepts; the sender refuses text/files over the peer's advertised caps
  (`failed_precondition`); the receiver drops inbound transfers over its own
  caps.
- **Config**: daemon env keys (`TRANSFERD_MAX_MSG/PHOTO/VIDEO/VOICE/FILE_BYTES`,
  `TRANSFERD_CALL_KBPS`, `TRANSFERD_MAX_MB_PER_DAY/WEEK/MONTH`; presets like
  `"5mb"` or byte counts) — the same keys work in the mobile `daemon.config`.
- 14 new tests: presets, bandwidth windows + rollover, relay forward refusal,
  daemon sender/receiver enforcement. **247 tests green**, clippy clean.

## v2.1.0 - 2026-09-26

### Autonomous nodes + resilient transport

- **Live Internet E2E**: the free-tier Cloudflare Worker relay is deployed at
  `transferd-relay.limpidluci.workers.dev`; two daemons deliver a message
  across the public Internet through it (ignored test
  `text_delivers_between_two_daemons_over_public_cloudflare_worker`). The live
  E2E caught three Worker bugs (WebSocket hibernation forbids `ws.accept()`;
  tag bytes swapped vs `relayd::protocol`; the `>=32` guard dropped the bare
  Challenge ask) and forced daemon-side `wss://` relays, DNS hostname relay
  addresses (SNI-correct TLS connect + hostname publish/discover), a 30s
  challenge timeout (DO cold start), and rustls TLS support.

- **Multi-relay protocol + auto-routing**: a peer publishes a LIST of relay
  endpoints (`PeerEndpoint.relays`); `TRANSFERD_RELAY_ADDR` is comma-separated;
  a session builds one lane per shared relay and the ATE fails over when a
  relay dies (proven both directions by `text_round_trips_over_two_relays_with_failover`).
  The handshake routes through the first relay that responds.
- **WebSocket relay (`relayd-ws`)**: the same blind, PoW-authenticated relay
  over WebSocket frames (same wire format) — traverses any NAT/firewall.
- **WS relay client lane**: `TRANSFERD_RELAY_ADDR` accepts `ws://` entries,
  `RelayWsClient`/`RelayWsLane` carry the daemon's traffic over `relayd-ws` or
  the Cloudflare Worker, endpoints publish `ws://` addresses, and sessions build
  a WS lane per shared WS relay (proven end-to-end by
  `text_delivers_between_two_daemons_over_ws_relay`).
- **Tailscale / direct-lane P2P**: the daemon detects LAN + Tailscale
  (100.64/10) addresses, binds its peer transport reachably via
  `TRANSFERD_BIND_ADDR`, and publishes `tcp://` direct endpoints to the DHT.
  Discovery PREFERS the direct address over any relay, so peers sharing a
  tailnet/LAN connect directly — no relay involved (proven by
  `peer_discovers_direct_address_and_connects_without_a_relay`).
- **Ops matrix**: `relayd-ws` added to the Docker image + compose stack,
  NGINX reverse-proxy configs (UDP relay, UDP DHT, TLS'd WebSocket relay,
  HTTP/2 gRPC), Android node-mode doc (`docs/ANDROID_NODE.md`) and router
  (OpenWrt) cross-compile guide (`docs/OPENWRT.md`).
- **Cloudflare free-tier Worker** (`deploy/cloudflare-worker/`): the relay as a
  Durable Object on Cloudflare's edge, zero servers, byte-level bincode
  compatible with the Rust client. PoW delegated to Cloudflare edge protections;
  self-hosted relays keep full BLAKE3 PoW.
- **System design** (`docs/NODE_SYSTEM.md`): node roles (relay/relay-ws/
  bootstrap/peer/ingress), the ranked-lanes transport model, the deployment
  matrix (VPS/Docker/Cloudflare/Android/router/metal), Tailscale/NGINX
  integration plan, and the security/evolution model.

## v2.0.1 - 2026-09-26

### Hosted relay + Internet-routability

- **`DhtNode::start_with_advertised` + `TRANSFERD_DHT_ADVERTISE`**: a DHT node bound to `0.0.0.0` (as a public bootstrap must be) can now advertise its externally-reachable address, fixing the #22 wildcard problem for public operation. New test `advertised_address_is_used_for_routing`.
- **`dhtd`** (transferd-relay): standalone DHT bootstrap binary for a VPS.
- **Deployment package** (`deploy/relayd.Dockerfile`, `docker-compose.yml`, `docs/DEPLOYMENT.md`): runs `relayd` + `dhtd` publicly. NAT rationale documented (45 s keepalive inside the 90 s relay TTL; reply-to-src; bootstrap-centric discovery), client config for desktop env + mobile `daemon.config`, and the security model (PoW difficulty, per-IP token bucket, TTL pruning).

## v2.0.0 - 2026-09-26

### On-device relay E2E (desktop <-> Kindle over the LAN relay)

- **Bidirectional relay sessions fixed**: `RelayHub` now keeps BOTH roles per peer (keyed by `(peer_token, we_initiated)`), so a peer that initiates to us AND that we initiate to no longer overwrites the first session. Proven by a new `text_round_trips_between_two_daemons_over_relay` test AND a live desktop↔Kindle **bidirectional conversation** over the LAN relay on the Fire (each side sent and received).
- **Post-quantum ratchet**: the double ratchet's DH steps now ALSO perform an ML-KEM-768 encapsulation, mixing `kem_ss` into the root alongside the X25519 DH output. An attacker holding all classical secrets can't derive post-ratchet keys (verified by `kem_mix_blocks_classical_only_future_secrecy`). First message publishes both X25519 + ML-KEM keys; DH-step messages carry the 1088-byte KEM ciphertext.
- **Mobile daemon.config**: the Android daemon reads `TRANSFERD_RELAY_ADDR` / `TRANSFERD_DHT_*` from `<files>/TransferDaemon/daemon.config` (Android cannot take env vars), so a device can be pointed at a relay without a rebuild.
- **Inbound dedup bug fixed**: `store_inbound_text` dedup'd by `msg_id` alone, but the per-daemon "d-N" id counter makes ids collide across peers - silently dropping real inbound messages. Now dedups on `(sender_pk, msg_id)`.
- **Verified on real hardware**: a desktop daemon discovers the Kindle via the DHT, completes the authenticated hybrid relay handshake, and delivers a ratcheted message over the LAN relay - applied on-device and surfaced as a system notification.
- **Cross-host UDP fixes**: DHT replies now go to the datagram's actual source (not the peer's advertised address); a `127.0.0.1`-bound UDP socket cannot route to the LAN, so cross-host DHT nodes must bind explicit LAN IPs; `adb forward/reverse` is TCP-only so a UDP relay/DHT needs a shared LAN subnet.
- **relayd crash fixed**: a transient `WSAECONNRESET` (10054) on Windows - an ICMP echo from a just-closed client socket - used to kill the relay's recv loop; it now logs and continues with a 10ms backoff.
- **Transport tick moved into the library**: the 50ms flush/dispatch tick was only in the desktop binary, so the mobile daemon could receive but never send (messages stuck "pending"). Now `transferd::transport::spawn_transport_tick(state)` is called by the binary, the mobile daemon, and any embedder.

### Protocol v2 - authenticated, post-quantum, forward-secret

- **Authenticated hybrid handshake on the wire** (direct TCP + relay): X25519 + ML-KEM-768 key exchange bound to the Ed25519 + ML-DSA-87 hybrid identity via BLAKE3-transcript signatures - a man-in-the-middle cannot substitute key material without the victim's signing key. Replaces the original X25519-only scheme.
- **Ciphersuite registry with sunset dates** - new KEMs can be added and old ones retired without breaking existing clients.
- **Peer-identity enforcement + trust-on-first-use**: session establishment verifies the peer's authenticated identity against the contact; a changed identity on later sessions is refused. Both peers derive a Signal-style **safety number** shown in the chat header for out-of-band verification.
- **Per-message forward secrecy (double ratchet)**: every message is encrypted under a fresh key from a BLAKE3 KDF chain, with periodic X25519 DH ratchet steps - a recorded wire survives even a mid-session key compromise.

### Chat experience

- Live **typing indicators**, distinct **read-receipt** state, **replies + emoji reactions**, auto-saved **drafts**, an **app-lock PIN** gate, and **media previews** (image thumbnails in chat).

### Mobile (Android)

- **System notifications** for incoming messages (verified live on a Kindle Fire via a real inbound message), **share-intent** ("share to TransferDaemon" from any app), **SAF file picker** with persistable URI permissions, and the on-device **direct TCP transport listener**.
- Verified end-to-end on a Kindle Fire: identity creation, authenticated handshake, ratcheted delivery, and notification posting.

### Operations & engineering

- **Local on-device CI/CD pipeline** (`build_pipeline.ps1`): preflight -> static checks -> full tests + deterministic wire fuzz -> desktop EXEs -> 3-ABI Android APK (gradle + apksigner) -> **deploy + smoke on a connected device**, with per-stage timing and a JSON report.
- **Fuzz-in-CI** (2M-iteration adversarial sweep over every untrusted parser), transport **benchmarks**, and a **manual, opt-in auto-updater** (no background phone-home).
- **Connections tab** with real ATE lane metrics (RTT, bandwidth, policy control).

---
## v1.0.1 — 2026-05-15

### Telemetry UI + Android compatibility

**Telemetry**
- `TelemetryService` gRPC streaming with `SystemHealth` event push
- `TelemetryPage` (egui): live sparkline, CPU/memory cards, scrollable event log
- `TelemetryPage` (TUI): same metrics in a ratatui panel
- `daemon_addr` now wired into `TransferDaemonApp::state` on Android so `TelemetryPage` auto-connects its gRPC stream on first tab open

**Android**
- `minSdk` lowered from 24 → 22; `PermissionsActivity` guards runtime-permission calls behind `Build.VERSION.SDK_INT >= 23` so the app installs and runs on Android 5.1.1 (API 22) devices (e.g. Amazon Kindle Fire KFSUWI)
- Keyboard backspace fix: `Selection.setSelection(s, SENTINEL.length())` after `s.replace()` in `afterTextChanged` ensures the cursor is positioned after the sentinel char so `deleteSurroundingText(1,0)` finds a character to delete
- Typing latency fix: `EGUI_CTX` global + `notify_repaint()` called from JNI keyboard delivery functions wakes the egui render loop immediately; 100ms repaint scheduled while keyboard is open
- DPI/blurry-text fix: `query_device_density()` JNI helper queries `DisplayMetrics.densityDpi` from the Java Activity jobject (`app.activity_as_ptr()` in android-activity 0.5); sets `cc.egui_ctx.set_pixels_per_point(densityDpi / 160.0)` at startup; correctly overrides Amazon Fire OS's compatibility override that sets `DisplayMetrics.density = 1.0` while leaving `densityDpi = 240` on hdpi hardware (e.g. Kindle Fire: `pixels_per_point 1.00 → 1.50`)
- Verified on Kindle Fire KFSUWI (API 22, arm64-v8a): JNI loads, keyboard helper registers, daemon starts on 127.0.0.1:50051, gRPC connects, `TransferDaemonApp` constructs, SQLite DB opens — process stable at ~51 MB RSS, no crash

---

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
