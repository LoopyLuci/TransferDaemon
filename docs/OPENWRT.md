# Running a TransferDaemon node on a router (OpenWrt)

An always-on OpenWrt router is a perfect node: it's already on 24/7, has a
public-ish LAN footprint, and can carry a relay/DHT with zero extra hardware.
Two paths, both producing the SAME binaries as the Docker image
(`relayd`, `relayd-ws`, `dhtd`) — or the full `transferd` daemon if the router
has enough flash.

## Path A — cross-compile on a desktop (recommended)

Cross-compiling from a Windows/Linux box is the fastest loop. For `relayd` +
`relayd-ws` + `dhtd` (the relay stack, no tonic/webrtc/UI) the dependency
closure is tiny — pure Rust + tokio, no C libs — so a musl target gives you a
statically-linked binary that runs on any OpenWrt.

1. Install the target for your router's architecture. Common OpenWrt boards:
   - x86_64 (most x86 routers): `x86_64-unknown-linux-musl`
   - arm_cortex-a7 (e.g. many MediaTek/MT7621 boards): `armv7-unknown-linux-musleabihf`
   - aarch64 (e.g. newer IPQ807x / many gl.inet): `aarch64-unknown-linux-musl`
   - mips_24kc (older MT7620, some TP-Link): `mipsel-unknown-linux-musl`

   ```sh
   rustup target add x86_64-unknown-linux-musl
   cd transferdaemon
   cargo build --release -p relayd -p transferd-relay \
       --bin relayd --bin relayd-ws --bin dhtd \
       --target x86_64-unknown-linux-musl
   ```

2. Copy the three binaries to the router and run with the same env config as
   the Docker image:
   ```sh
   scp target/x86_64-unknown-linux-musl/release/{relayd,relayd-ws,dhtd} root@router:/usr/local/bin/
   ssh root@router
   RELAYD_PORT=5901 RELAYD_DIFFICULTY=20 /usr/local/bin/relayd &
   RELAYD_WS_PORT=5902 RELAYD_WS_DIFFICULTY=20 /usr/local/bin/relayd-ws &
   DHTD_BIND=0.0.0.0:7901 DHTD_ADVERTISE=<public-ip>:7901 /usr/local/bin/dhtd &
   ```

3. Open the ports in the firewall so the LAN/subnet can reach the relay:
   ```sh
   uci add firewall rule   # or use LuCI Network → Firewall → Traffic Rules:
   #   Name:   td-relay    Protocol: UDP    Port: 5901   Target: ACCEPT
   #   Name:   td-relay-ws Protocol: TCP    Port: 5902   Target: ACCEPT
   #   Name:   td-dht      Protocol: UDP    Port: 7901   Target: ACCEPT
   ```

   Peers on the LAN use `TRANSFERD_RELAY_ADDR=<router-lan-ip>:5901`; if the
   router is the WAN gateway, port-forward 5901/5902/7901 to it so Internet
   peers can use it too.

## Path B — build ON the router (no cross toolchain needed for tiny boards)

OpenWrt ships enough to build Rust via `rustc` from the SDK; if your board has
≥1 GB flash, install the SDK tools (`opkg install rustc cargo`) and build
in-place. Path A is strictly faster and preferred.

## Ports in one line

| binary | port | protocol | peers use |
|--------|------|----------|-----------|
| relayd | 5901 | UDP | `host:5901` |
| relayd-ws | 5902 | TCP | `ws://host:5902` |
| dhtd | 7901 | UDP | `TRANSFERD_DHT_BOOTSTRAP=host:7901` |

## Notes

- The relay stack has zero C dependencies; the `musl` build above is
  statically linked and copies over with no extra libs. The full `transferd`
  daemon needs more flash/RAM and tonic's TLS stack — a 64 MB router is fine
  for the relay stack, marginal for the daemon.
- A router node's value is the SAME as any node: a public (or LAN-wide) relay +
  DHT that peers can bootstrap from, plus NAT-friendly keepalive behavior
  (registration every 45 s inside the relay TTL — no state held in the relay).
- Pair it with the Tailscale direct lane (CONTEXT.md #29): if the router runs
  Tailscale, peers on the same tailnet connect directly via its 100.x address
  and never touch the relay at all.