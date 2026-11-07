# TransferDaemon

[![Release v2.3.0](https://img.shields.io/badge/release-v2.3.0-blue)](https://github.com/LoopyLuci/TransferDaemon/releases/tag/v2.3.0)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Protocol: Transferd v1–v3](https://img.shields.io/badge/protocol-Transferd%20v1--v3-blue)](docs/PROTOCOL.md)

TransferDaemon is a messaging and file-transfer application for moving data between your own devices and your contacts' devices. A background daemon, `transferd`, does the work. The desktop app, the terminal app, the command line and the mobile shells all sit on top of it, and so does a control hub that scripts and AI agents can drive.

The network layer is the **Transferd protocol**, which is specified in its own repository: [github.com/LoopyLuci/Transferd](https://github.com/LoopyLuci/Transferd). TransferDaemon is that protocol's reference implementation. This repository holds the application and the code that implements the protocol. It does not hold the specification.

---

## What it does

- **Messaging, contacts and file transfer** between paired devices. The daemon chooses the route for each transfer.
- **An overlay network** for paired devices. A service on one machine can be reached from another over a LAN, Tailscale, a direct path or a relay. It has mesh DNS names and optional UDP hole punching. See [docs/OVERLAY.md](docs/OVERLAY.md).
- **Voice and video calls**, with call state and signalling in `transferd-webrtc`. The desktop app and the terminal app show the call.
- **A control hub.** Every daemon operation is available over local HTTP and MCP, and through `transferd-cli`. See [docs/CONTROL.md](docs/CONTROL.md).
- **Checked DNS** for relay host names, in `transferd-dns`. It reports whether an answer passed DNSSEC validation.

---

## Protocol and documentation

This build speaks Transferd protocol versions 1 to 3. The specification has no tagged release yet, so this build follows Transferd's `main` branch.

[docs/PROTOCOL.md](docs/PROTOCOL.md) lists the constants that set those versions, where each part of the specification is implemented, and which tests exercise the wire format. It does not repeat the specification.

| Document | Read it for |
|----------|-------------|
| [docs/PROTOCOL.md](docs/PROTOCOL.md) | How this build maps onto the Transferd specification |
| [docs/OVERLAY.md](docs/OVERLAY.md) | Running the overlay: commands, settings, files, measurements, tests |
| [docs/CONTROL.md](docs/CONTROL.md) | The control hub, the CLI, MCP, and driving the GUI and TUI from outside |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | Hosting relays and a DHT for internet reachability |
| [docs/DERP.md](docs/DERP.md) | Peers on one Tailscale tailnet, connected directly |
| [docs/ANDROID_NODE.md](docs/ANDROID_NODE.md) | Running the daemon on Android |
| [docs/OPENWRT.md](docs/OPENWRT.md) | Running a node on an OpenWrt router |
| [docs/NODE_SYSTEM.md](docs/NODE_SYSTEM.md) | A design document for server nodes and resilient transport. Not a user guide. |
| [docs/PARITY.md](docs/PARITY.md) | Comparison with related projects, and how far each feature has been built |

If the specification and this implementation disagree, the specification is the reference. Report the disagreement to the [Transferd repository](https://github.com/LoopyLuci/Transferd/issues).

---

## Install

Release packages are on the [releases page](https://github.com/LoopyLuci/TransferDaemon/releases). The installer scripts in this repository build from source and install the daemon and the desktop app. Read a script before you run it.

Linux:

```bash
curl -sSf https://raw.githubusercontent.com/LoopyLuci/TransferDaemon/main/install.sh | bash
```

macOS:

```bash
curl -sSf https://raw.githubusercontent.com/LoopyLuci/TransferDaemon/main/install_mac.sh | bash
```

Windows, in an elevated PowerShell:

```powershell
iwr -useb https://raw.githubusercontent.com/LoopyLuci/TransferDaemon/main/install.ps1 | iex
```

---

## Build and test from source

The Cargo workspace is in `transferdaemon/`. You need Rust (stable) and `protoc`.

```bash
cd transferdaemon
cargo build --release -p transferd -p transferd-ui -p transferd-tui -p transferd-cli -p launcher
cargo test --workspace
cargo test -p transferd-overlay      # the overlay and wire-format tests
```

At the repository root, `run_tests.ps1` builds and runs the whole suite. `run_pentest.sh` and `run_pentest.ps1` run the local penetration suite. `test_e2e_two_instance.ps1` runs two daemons against each other.

Platforms: the desktop app and the terminal app run on Windows, Linux and macOS. The Android app is in `android/` and the iOS shell is a Swift package in `ios/`. See [docs/ANDROID_NODE.md](docs/ANDROID_NODE.md) for Android.

---

## Crates

The workspace has 24 crates, grouped here by role.

**Protocol and transport**

| Crate | Role |
|-------|------|
| `ring-channel` | Shared-memory ring buffer for transfers within one machine |
| `transferd-crypto` | Hybrid identity and handshake, tunnel keys, the key-store factory |
| `transferd-core` | Transfer scheduler, transport lane trait, and the lanes |
| `transferd-overlay` | Overlay: pairing, services, routes, streams, congestion control, hole punching, mesh DNS |
| `transferd-dns` | Host-name resolution with DNSSEC checks |
| `transferd-cat` | One-time, netcat-style transfer between two machines |
| `relayd` | Blind relay with proof of work, and a WebSocket variant (`relayd-ws`) |
| `transferd-relay` | Relay engine: Kademlia DHT for discovery, announcements, rate limiting |

**Daemon and services**

| Crate | Role |
|-------|------|
| `transferd` | The daemon. Builds the gRPC services and the control hub |
| `transferd-api` | gRPC schema for the ten services in `transferd.proto`, and the generated code |
| `transferd-control` | Control hub: operation catalog, local HTTP and MCP, a small client |
| `transferd-store` | Encrypted local data store |
| `transferd-replica` | State replicated across a person's devices with Raft, applied to SQLite |
| `transferd-telemetry` | Event collection and health reporting |
| `transferd-webrtc` | Call sessions and the media-capture trait |
| `transferd-mobile` | C-ABI entry points for the Android and iOS shells |
| `launcher` | Starts the daemon if it is not running, then starts the UI |

**Interfaces**

| Crate | Role |
|-------|------|
| `transferd-ui` | Desktop app (egui/eframe) |
| `transferd-ui-shared` | Pages and logic shared by the desktop app |
| `transferd-tui` | Terminal app (ratatui) |
| `transferd-tui-video` | Terminal video rendering: Kitty, Sixel, half-block and ASCII backends |
| `transferd-cli` | Command line and MCP server, through the control hub |

**Testing**

| Crate | Role |
|-------|------|
| `transferd-tests` | Shared test utilities |
| `transferd-pentest` | On-device penetration test suite |

---

## Security

- Identity and sessions use the hybrid constructions in the Transferd specification: Ed25519 with ML-DSA-87 for identity, X25519 with ML-KEM-768 for key exchange, and AES-256-GCM for tunnels. See [CRYPTO.md](https://github.com/LoopyLuci/Transferd/blob/main/docs/CRYPTO.md).
- Relays forward random tokens and padded ciphertext. They do not learn identities or plaintext. See [RELAY.md](https://github.com/LoopyLuci/Transferd/blob/main/docs/RELAY.md).
- Relay host names are resolved over DNS. With `TRANSFERD_DNS_REQUIRE_VALIDATED=1`, an answer counts only if it carries the DNSSEC AD bit.

| DNS variable | Meaning |
|--------------|---------|
| `TRANSFERD_DNS` | Resolver order (default `ironroot,quad9,system`) |
| `TRANSFERD_DNS_IRONROOT` | Where the local Ironroot resolver listens (default `127.0.0.1:5350`) |
| `TRANSFERD_DNS_REQUIRE_VALIDATED` | `1` accepts only answers carrying the AD bit, and fails closed |

To check one host name by hand: `transferd-cli dns relay.example` shows every address, which resolver answered, and whether the answer validated.

---

## Status and limits

- The current release is 2.3.0. [CHANGELOG.md](CHANGELOG.md) describes it.
- Hardware-backed key storage (TPM 2.0, Secure Enclave) is designed in `transferd-crypto` but not implemented. `create_key_store()` returns an in-memory store for now.
- The swarm lane is an in-process model of piece distribution. It does not connect to BitTorrent or IPFS.
- MQTT and CoAP adapters are not implemented. The `mqtt` plugin is marked "future" in `transferd-core`.
- Bluetooth and Wi-Fi Direct are not transport lanes. The connection code only recognises those interface types.

---

## Contributing

- Run `cargo test --workspace` before you open a pull request.
- The workspace denies `unwrap` and `panic` outside test code (`[workspace.lints]` in `transferdaemon/Cargo.toml`).
- Open an issue before a large change. A change to the wire protocol goes to the [Transferd repository](https://github.com/LoopyLuci/Transferd) first, then here.

---

## License

MIT. See [LICENSE](LICENSE).
