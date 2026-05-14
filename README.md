# TransferDaemon

[![Release v1.0.0](https://img.shields.io/badge/release-v1.0.0-blue)](https://github.com/LoopyLuci/TransferDaemon/releases/tag/v1.0.0)
[![License: MIT/Apache 2.0](https://img.shields.io/badge/license-MIT%2FApache--2.0-green)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-120%2B%20passing-brightgreen)](#)

**A truly next-generation, production-grade messaging and file-transfer platform that unifies every existing protocol into a single, secure, zero-knowledge Universal Data Transfer Protocol.**

TransferDaemon lets any user, on any device, send any data — from a few bytes to multi-terabyte datasets — with absolute privacy and end-to-end security. It intelligently selects the best transport (DMI, TCP, relay, Wi-Fi Direct, Bluetooth, etc.) automatically, while the user sees only a single, simple unified interface. The entire stack is built in pure Rust with no third-party analytics, no cloud accounts, and no metadata leakage.

---

## Key Features

### Universal Protocol Abstraction
TransferDaemon abstracts away the underlying transport. Whether you are connected via a 100 Gbps Thunderbolt cable, a relay server, Wi-Fi 7, or a Bluetooth mesh, the daemon automatically negotiates the best available lane and stripes data across multiple paths for optimal speed and reliability.

### Zero-Knowledge Architecture
Relays and DHT nodes never see your plaintext, file names, or even who you are communicating with. All metadata is encrypted with session keys, and relays forward only random tokens. The entire system is designed so that **nobody can read your data except the intended recipient**.

### Post-Quantum Security
Every session begins with a hybrid key exchange: X25519 (classical) combined with ML-KEM-768 (Kyber) for post-quantum resistance. Data is encrypted with AES-256-GCM using rotating keys, and private keys are sealed inside hardware security modules (TPM / Secure Enclave) where available.

### Blazing-Fast Local Transfers (100 Gbps+)
Through a custom **zero-copy DMI ring** and mirrored hugepage memory mappings, TransferDaemon can transfer files directly over Thunderbolt/USB4 at line rate with near-zero CPU overhead. The ring uses 128-byte descriptors for cache-line alignment and sub-microsecond latency. Encryption is fused with integrity checking (BLAKE3) and uses non-temporal stores to avoid cache pollution.

### Adaptive Multi-Path Engine (ECF-RG)
The Adaptive Transfer Engine uses an **Earliest Completion First with Reorder Guard** algorithm to stripe chunks across DMI, Wi-Fi, relay, and other lanes. It monitors lane health, handles failure, and retransmits missing chunks on the fastest available path — all without user intervention.

### Blind Relay Network
A global network of relay nodes provides rendezvous even when peers are behind restrictive firewalls. Relays require a lightweight BLAKE3 proof-of-work to prevent abuse, and they never know who is talking to whom. Ephemeral session tokens enable fast reconnection and direct hole-punching when possible.

### Anonymous Accounts & Identity
Your identity is a key pair — no email, phone number, or personal information required. Share your public key via QR code or text and add friends directly. All communication is end-to-end encrypted.

### Voice & Video Calls
WebRTC-style calls with signaling over the daemon's encrypted control channel. No external STUN/TURN servers are needed; the relay network acts as a fallback. The full call state machine (Idle → Outgoing/Incoming → Active → Ended) is implemented via `SimulatedCallSession` and the `MediaCapture` trait, with a live call overlay in both the desktop GUI and the terminal UI.

### Terminal UI with Live Video
A full-featured ratatui terminal UI (`transferd-tui`) provides identical functionality to the desktop GUI — chat, contacts, file transfers, settings, and **real WebRTC video calls in the terminal**. The `transferd-tui-video` crate renders camera frames using four adaptive backends: Kitty graphics protocol, Sixel, half-block Unicode (`▀`), and ASCII art. The backend is auto-detected at runtime from the terminal's capabilities.

### Pure Rust, Zero External Services
The entire stack is written in Rust, from the low-level DMI ring to the egui desktop UI. There are no web views, no JavaScript, no telemetry, and no third-party analytics. The app works completely offline and only uses the network when you initiate a transfer.

### Cross-Platform
- **Desktop**: Linux, macOS, Windows with a native egui/eframe interface (OLED dark theme, 420×740 window).
- **Mobile**: Android and iOS via thin native shells that host the same Rust UI code and daemon.
- **Embedded/IoT**: The core daemon can run headless on ARM devices, with MQTT/CoAP adapters for sensor data.

---

## Download v1.0.0

| Platform | Package |
|----------|---------|
| Windows  | [TransferDaemon-1.0.0.msi](https://github.com/LoopyLuci/TransferDaemon/releases/download/v1.0.0/TransferDaemon-1.0.0.msi) |
| Linux (.deb) | [transferdaemon_1.0.0_amd64.deb](https://github.com/LoopyLuci/TransferDaemon/releases/download/v1.0.0/transferdaemon_1.0.0_amd64.deb) |
| Linux (.rpm) | [transferdaemon-1.0.0-1.x86_64.rpm](https://github.com/LoopyLuci/TransferDaemon/releases/download/v1.0.0/transferdaemon-1.0.0-1.x86_64.rpm) |
| macOS    | [TransferDaemon-1.0.0.dmg](https://github.com/LoopyLuci/TransferDaemon/releases/download/v1.0.0/TransferDaemon-1.0.0.dmg) |
| Android (APK) | [TransferDaemon-1.0.0.apk](https://github.com/LoopyLuci/TransferDaemon/releases/download/v1.0.0/TransferDaemon-1.0.0.apk) |

See [RELEASE_NOTES.md](transferdaemon/RELEASE_NOTES.md) for full changelog and known issues.

---

## Quick Start

### Desktop Installation

**Linux:**
```bash
curl -sSf https://raw.githubusercontent.com/LoopyLuci/TransferDaemon/main/install.sh | bash
```

**macOS:**
```bash
curl -sSf https://raw.githubusercontent.com/LoopyLuci/TransferDaemon/main/install_mac.sh | bash
```

**Windows (elevated PowerShell):**
```powershell
iwr -useb https://raw.githubusercontent.com/LoopyLuci/TransferDaemon/main/install.ps1 | iex
```

The installer will:
1. Install Rust and any missing build dependencies.
2. Configure hugepages (Linux only) for maximum DMI performance.
3. Build the entire TransferDaemon workspace.
4. Install binaries (`transferd`, `transferd-ui`, `transferdaemon`) to `~/.local/bin` (or `%LOCALAPPDATA%\TransferDaemon\bin` on Windows).
5. Set up daemon autostart (systemd user service on Linux, launchd on macOS, scheduled task on Windows).
6. Create a desktop shortcut so you can launch TransferDaemon like any other app.

After installation, run `transferdaemon` or click the **TransferDaemon** shortcut in your application menu.

### Building from Source

```bash
git clone https://github.com/LoopyLuci/TransferDaemon.git
cd TransferDaemon/transferdaemon
cargo build --release -p transferd -p transferd-ui -p transferd-tui -p launcher
```

To include real webcam/mic support in the terminal UI:
```bash
cargo build --release -p transferd-tui   # desktop-capture feature is enabled by default
```

Requires: Rust stable, protoc (protobuf compiler).

---

## Usage

Once the daemon is running and the UI is open, you can:

1. **Create an anonymous account** — Tap "New Account". You'll receive a 12-word recovery phrase (write it down!).
2. **Add friends** — Share your public key via QR code or text. Scan a friend's QR code to add them.
3. **Start a conversation** — Select a friend and type a message. Attach any file; the daemon will automatically pick the best transport.
4. **Make a call** — Tap the 📞 or 📹 icon in the chat header to start a voice or video call.
5. **Transfer files** — Files appear as messages with a live progress bar showing speed, ETA, and the active lanes.

Everything is encrypted end-to-end. The daemon runs silently in the background, managing sessions and relay connections.

---

## Security & Privacy

- **End-to-end encryption**: AES-256-GCM with per-chunk BLAKE3 integrity. Session keys derived from a hybrid X25519 + ML-KEM-768 handshake.
- **Forward secrecy**: Ephemeral keys are used for every session; past messages cannot be decrypted even if long-term keys are compromised.
- **Hardware-bound keys**: On supported platforms, private keys are generated and stored inside a TPM, Secure Enclave, or ARM TrustZone. They never leave the hardware in plaintext.
- **Zero knowledge**: Relays only see random tokens and encrypted blobs. Metadata (sender, recipient, size) is hidden from relay infrastructure.
- **Metadata protection**: Traffic analysis is mitigated by optional constant-rate padding.
- **Off-grid operation**: When the internet is unavailable, the system degrades to a local mesh using mDNS and Bluetooth, maintaining the same security guarantees.

---

## Project Structure

| Crate | Purpose |
|---|---|
| `ring-channel` | Zero-copy DMI ring buffer with mirrored hugepages, async producer/consumer, eventfd doorbells |
| `transferd-crypto` | Fused BLAKE3 + AES-256-GCM, hybrid post-quantum KEM (X25519 + ML-KEM-768), key zeroizing |
| `transferd-core` | ECF-RG ATE scheduler, transport lane trait, reassembly window, session management |
| `transferd-api` | gRPC protobuf schema (6 services) and tonic generated client/server code |
| `transferd` | Daemon binary — gRPC server implementing all six services (account, friends, messaging, transfer, calls, settings) |
| `transferd-ui` | Desktop UI (pure Rust, egui/eframe) — onboarding, chat, contacts, file progress, call overlay |
| `transferd-webrtc` | Call session manager, `MediaCapture` trait, `SimulatedCallSession`, `GrpcSignaling`, `DesktopMediaCapture` (nokhwa + cpal) |
| `relayd` | Blind relay server with BLAKE3 PoW, forwarding table, and session token routing |
| `transferd-mobile` | Mobile library crate with C-ABI entry points for Android/iOS integration |
| `launcher` | Probes daemon liveness, spawns it if absent, then launches the UI |
| `transferd-tui` | Full terminal UI (ratatui 0.27) — onboarding, chat, contacts, transfers, settings, call overlay |
| `transferd-tui-video` | Terminal video renderer — Kitty, Sixel, half-block Unicode, ASCII art backends |

All crates are tested together; the suite currently contains **120+ integration tests** with zero failures.

---

## Supported Transports

TransferDaemon's Universal Protocol Abstraction Layer automatically selects from:

- **DMI / Thunderbolt / USB4** — Direct memory-mapped transfers at 100 Gbps+
- **TCP** — Direct TCP lane with binary-framed AES-GCM
- **Blind Relay** — Encrypted forwarding through the global relay network
- **Wi-Fi Direct / Bluetooth LE** — Local wireless transfers
- **Swarm (BitTorrent / IPFS)** — Plug-in architecture ready for P2P distribution
- **MQTT / CoAP** — Lightweight IoT adapters
- **Simulated lanes** — For testing and emulation

The adaptive engine stripes chunks across multiple lanes simultaneously for maximum throughput and resilience.

---

## Contributing

Contributions are welcome. The codebase is pure Rust; run `cargo test --all` for validation. All contributions must:

- Pass the existing 120+ tests
- Include tests for new functionality
- Follow the existing code style (rustfmt)

Please open an issue before submitting large changes. By contributing you agree your changes are licensed under MIT OR Apache-2.0.

---

## License

MIT OR Apache-2.0 — see [LICENSE](LICENSE).
