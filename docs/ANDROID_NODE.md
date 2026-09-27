# Android node mode

TransferDaemon's daemon is the same library on desktop and Android, so a phone
can act as a **node** in the network — a relay, a DHT bootstrap, or both — not
just a client. This is what makes the mesh resilient: any always-on device (a
spare phone plugged in at home) can carry traffic for peers who can't reach the
public relays.

## What the Android build already gives you

- The full daemon (`transferd` library) runs in `transferd-mobile`'s
  `daemon_thread`, spawned from Java/Kotlin. See
  `android/app/src/main/kotlin/.../MainActivity.kt`.
- Config comes from `<files>/TransferDaemon/daemon.config` (KEY=VALUE lines,
  applied by `daemon_thread::spawn_with_config`), because Android processes
  can't be given env vars. Real env vars win over the file; a missing file is a
  no-op. Keys mirror the desktop env vars:

  | Key | Equivalent env | Meaning |
  |-----|----------------|---------|
  | `TRANSFERD_PORT` | `TRANSFERD_ADDR` | gRPC listen port |
  | `TRANSFERD_RELAY_ADDR` | same | comma-separated `host:port` and/or `ws://host:port` relays this node registers on |
  | `TRANSFERD_DHT_BIND` | `TRANSFERD_DHT_BIND` | DHT socket this node listens on |
  | `TRANSFERD_DHT_BOOTSTRAP` | `TRANSFERD_DHT_BOOTSTRAP` | comma-separated bootstrap nodes to join |
  | `TRANSFERD_DHT_ADVERTISE` | `TRANSFERD_DHT_ADVERTISE` | the address the DHT publishes for this node (MUST be reachable by peers) |
  | `TRANSFERD_DIFFICULTY` | `TRANSFERD_DIFFICULTY` | relay PoW difficulty to solve on registration |
  | `TRANSFERD_BIND_ADDR` | `TRANSFERD_BIND_ADDR` | peer transport bind (e.g. `0.0.0.0` to accept direct lanes) |

## Running the phone as a relay

The phone does NOT run `relayd` itself (that's a separate crate). Instead the
phone node *registers* on a public relay and forwards traffic as a client — the
valuable node roles on-device are **direct-lane peer** and **DHT bootstrap**:

1. Write a `daemon.config` like:
   ```
   TRANSFERD_PORT=50051
   TRANSFERD_RELAY_ADDR=relay.example.com:5901
   TRANSFERD_DHT_BIND=0.0.0.0:7901
   TRANSFERD_DHT_ADVERTISE=<phone-public-or-tailnet-ip>:7901
   TRANSFERD_BIND_ADDR=0.0.0.0
   ```
2. Launch the app. The daemon binds the DHT on all interfaces and the peer
   transport on all interfaces; it publishes `tcp://` direct addresses (LAN +
   Tailscale, see CONTEXT.md #29) and its relay endpoint to the DHT.
3. Other peers set `TRANSFERD_DHT_BOOTSTRAP=<phone-ip>:7901` (or list the phone
   as a bootstrap in the app settings) and can route to/from the phone's relay
   registration directly over its Tailscale address.

## Firewall / battery

- The phone must be reachable on its DHT + peer-transport UDP/TCP ports: on the
  Wi-Fi router forward them, or keep the phone on a Tailscale tailnet so peers
  reach it via the mesh (no inbound port forward needed — Tailscale handles it).
- The transport tick and relay keepalives are low-rate (50 ms tick, 45 s
  keepalive); the DHT is quiet unless queried. This is fine for a phone on a
  charger. Disable OS battery optimization for the app if the node is
  permanent.

## Verifying on-device

```
adb shell am start -n com.example.transferdaemon/.PermissionsActivity
adb shell run-as com.example.transferdaemon cat files/TransferDaemon/daemon.config
```
Watch the daemon log (logcat `AndroidRuntime` / the `[daemon]` prefix) for
`transport listener on`, `DHT bound`, and `registered on relay`.

The on-device relay E2E (desktop <-> Kindle, CONTEXT.md #21-25) is the reference
for a working phone-node setup: the same daemon code path, just with a
`daemon.config` instead of env vars.