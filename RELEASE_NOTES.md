# TransferDaemon v1.0.0

**Privacy-first file transfer and encrypted calling — across every platform.**

---

## What's included

| Binary | Description |
|--------|-------------|
| `TransferDaemon.exe` / `transferdaemon` | Launcher — starts the daemon and opens the GUI |
| `transferd` | gRPC daemon (all services) |
| `transferd-ui` | Desktop GUI (egui) |
| `transferd-tui` | Terminal UI (ratatui) with live video calling |

---

## Installation

### Windows
Download `TransferDaemon-1.0.0.msi` and double-click to install.  
The launcher, daemon, desktop GUI, and terminal UI are installed to `%ProgramFiles%\TransferDaemon\`.

To rebuild from source:
```powershell
cd installer\windows
.\build.ps1
```

### Linux (Debian / Ubuntu)
```bash
sudo dpkg -i transferdaemon_1.0.0_amd64.deb
transferdaemon   # launches the GUI
transferd-tui    # terminal UI
```

To rebuild the .deb from source:
```bash
./installer/linux/build-deb.sh
```

### macOS
Download `TransferDaemon-1.0.0.dmg`, open it, and drag **TransferDaemon** to Applications.

### Android
Download `transferdaemon-1.0.0.apk` and install (enable "Unknown sources" if needed).

---

## Features

- **End-to-end encrypted messaging** — X25519 + ML-KEM-768 (post-quantum hybrid)
- **File transfer** — multi-lane parallel with live progress
- **Voice and video calling** — WebRTC signaling over gRPC; 4 terminal video backends (Kitty, Sixel, HalfBlock, ASCII)
- **Onboarding** — BIP-39 12-word recovery phrase, Ed25519 identity
- **Relay server** — blind forwarding with proof-of-work spam protection
- **Dual interface** — egui desktop GUI and ratatui terminal UI (full feature parity)
- **No third-party dependencies** — no Firebase, no Google Play Services, no analytics

---

## Security

- Post-quantum hybrid key exchange (X25519 + ML-KEM-768)
- All messages encrypted before leaving the device
- Recovery phrase is the only secret — no server-side accounts
- Relay is cryptographically blind to message content

---

## Build from source

```bash
git clone https://github.com/LoopyLuci/TransferDaemon
cd TransferDaemon/transferdaemon
cargo build --release --all
```

Run tests:
```bash
cargo test --all
```

---

## Changelog

- Complete gRPC daemon with account, contact, message, transfer, settings, and call services
- Desktop GUI with onboarding, chats, contacts, transfers, settings, and call overlay
- Terminal TUI with identical feature set
- Terminal video calling: 4 rendering backends, real webcam support via nokhwa + cpal
- WebRTC end-to-end test harness proving full signaling pipeline
- Android APK (minimum API 24 / Android 7.0)
- Windows MSI, Linux .deb/.rpm, macOS .dmg packaging
