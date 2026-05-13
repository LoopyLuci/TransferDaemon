# TransferDaemon

**Universal, private, zero-knowledge data transfer and messaging.**

TransferDaemon is a fully custom, zero-external-services desktop application for secure file transfer and real-time messaging. It is built entirely in Rust with no third-party analytics, no cloud accounts, and no metadata leakage.

## Features

- **Zero-knowledge end-to-end encryption** — AES-256-GCM + BLAKE3, post-quantum hybrid handshake (X25519 + ML-KEM-768)
- **DMI zero-copy ring** — mirrored hugepage ring buffer, 128-byte descriptors, sub-microsecond latency
- **Multi-path QoS** — ECF-RG ATE scheduler across relay, TCP, and swarm lanes
- **Blind relay** — BLAKE3 proof-of-work, no plaintext at relay nodes, ephemeral session tokens
- **Voice/video calls** — simulated WebRTC-style call sessions with full state machine
- **Immediate-mode GPU UI** — egui/eframe, OLED dark theme, 420×740 window
- **No accounts, no servers, no tracking** — peer-to-peer by default

## Quick Start

**Linux:**
```bash
curl -fsSL https://raw.githubusercontent.com/transferdaemon/transferdaemon/main/install.sh | bash
```

**macOS:**
```bash
curl -fsSL https://raw.githubusercontent.com/transferdaemon/transferdaemon/main/install_mac.sh | bash
```

**Windows (elevated PowerShell):**
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force; .\install.ps1
```

After installation, run `transferdaemon` or find it in your application menu.

## Crates

| Crate | Description |
|---|---|
| `ring-channel` | DMI zero-copy ring buffer with mirrored hugepages |
| `transferd-crypto` | AES-256-GCM, BLAKE3, ML-KEM-768 hybrid handshake |
| `transferd-core` | Transport lanes, ATE scheduler, relay protocol |
| `transferd` | gRPC daemon — all six service implementations |
| `transferd-api` | Protobuf schema + tonic generated types |
| `transferd-webrtc` | Call sessions, MediaCapture trait, CallManager |
| `transferd-ui` | egui desktop UI with gRPC or mock daemon |
| `transferd-mobile` | C-ABI entry points for Android/iOS embedding |
| `launcher` | Binary discovery, daemon health check, startup orchestration |
| `relayd` | Blind relay daemon (standalone) |

## Security

- All private keys are held in memory only — never written to disk
- Relay nodes see only ciphertext and BLAKE3 PoW tokens
- Metadata (sender, recipient, size) is hidden from relay infrastructure
- Post-quantum key encapsulation provides forward secrecy against harvest-now-decrypt-later attacks

## Building from Source

```bash
cd transferdaemon
cargo build --release -p transferd -p transferd-ui -p launcher
```

Requires: Rust stable, protoc (protobuf compiler).

## Contributing

Issues and pull requests welcome. By contributing you agree your changes are licensed under MIT.

## License

MIT — see [LICENSE](LICENSE).
