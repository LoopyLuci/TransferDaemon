# Autonomous Anonymous Server Nodes + Resilient Transport

This document is the system design for the next generation of TransferDaemon's
backend: a network of autonomous, anonymous nodes and a transport layer that
always finds a path — through servers, around them, or with none at all.

## Design principles

1. **No single point of failure.** A peer is reachable through *many* independent
   paths (direct connections, several relays, WebSocket relays). Data routes
   across whatever is alive.
2. **Nodes are autonomous and anonymous.** A node is a self-contained binary or
   container that performs one or more *roles*. It needs no identity, no
   coordination, no shared secret with other nodes. Anyone can stand one up.
3. **Transport is a ranked set of lanes.** The Adaptive Traffic Engine (ATE)
   already measures RTT/bandwidth/loss per lane. It now ranks across *all* path
   types at once — direct TCP, per-relay UDP, per-relay WebSocket — and
   retransmits over the next-best lane when one dies.
4. **"No servers" is a first-class mode.** Direct P2P remains fully supported.
   Relays are an enhancement, never a requirement.
5. **Runs everywhere, identically.** Every node binary runs natively on metal
   and inside Docker/containers. The same image builds for x86/arm VPS,
   Android (via the existing cdylib path), and routers (musl static builds).
6. **Evolutionary protocol.** All wire changes are serde-defaulted and the
   ciphersuite registry already version-gates ciphers. Old and new clients
   interoperate; this is how the network survives decades.

## Node roles

A host runs one or more of these roles. The binaries are deliberately tiny and
dependency-light so they cross-compile everywhere.

| Role        | Binary   | Transport | Purpose |
|-------------|----------|-----------|---------|
| relay       | `relayd` | UDP       | Blind rendezvous: forwards opaque, PoW-authenticated blobs by token. |
| relay-ws    | `relayd-ws` | WebSocket | Same rendezvous over WebSocket; traverses any NAT/firewall and Cloudflare's edge. |
| bootstrap   | `dhtd`   | UDP       | DHT bootstrap node; holds published `PeerEndpoint` records for discovery. |
| peer/daemon | `transferd` | gRPC + TCP/UDP/WS | Full identity + messaging; can also run relay/bootstrap roles. |
| ingress     | configs | —         | Tailscale / NGINX / cloudflared plumbing that makes the above reachable (TLS, LB, routing). |

### Autonomy
Each role is independently deployable and replaceable. `relayd`/`dhtd`/`relayd-ws`
take all configuration from env vars, so the same container runs on a VPS, an
Android phone, a router, or bare metal without code changes.

## The resilient transport

### Endpoint model (protocol)

A peer's published endpoint becomes a **list** of reachable paths:

```
PeerEndpoint {
  public_key: hex,
  relays: [ { relay_addr: "host:port", token: hex }, ... ],   // NEW: any of these works
  direct: [ "tcp://host:port", "tailscale://100.x.y.z:port", ... ],
  signature
}
```

`relay_addr`/`token` remain as serde-defaulted legacy fields so old clients
still resolve. Discovery (DHT) is bootstrap-centric: NAT'd peers publish
through the public bootstrap; lookups succeed without the peer being directly
reachable.

### Session construction

`ensure_contact_session` now builds a session with **one lane per available
path**:

1. Direct TCP lane to every known direct address (LAN, Tailscale IP, public IP).
2. One relay lane to **every relay the peer published AND we are registered on**
   (a relay lane is only useful if both sides can reach the same relay).
3. One WebSocket relay lane per WS relay (for UDP-blocked networks).

The session holds `Vec<Box<dyn TransportLane>>`; the ATE selects the live lane
per message, measures health continuously, and **fails over mid-session** when
a lane dies (retransmit goes out the next-best lane). A peer on relays A+B+C
with a direct Tailscale path has up to four independent routes; data arrives
as long as any one works.

### Config

`TRANSFERD_RELAY_ADDR` accepts a **comma-separated list** of relays. The daemon
registers its token with every one and publishes all of them. Mobile
`daemon.config` supports the same.

### "Data always makes it"

| Scenario | Path |
|----------|------|
| Peer on LAN | direct TCP (fastest) |
| Peers behind NAT, same public relay | relay UDP |
| UDP blocked (some ISPs, Cloudflare edge) | relay-ws (WebSocket) |
| All relays down | direct TCP/Tailscale (if any address known) |
| Discovery | DHT bootstrap (public) |

## Deployment matrix

| Target | Method |
|--------|--------|
| VPS (metal or container) | `deploy/docker-compose.yml` (relayd + dhtd) or bare `relayd`/`dhtd` binaries |
| Cloudflare (free tier) | A **Cloudflare Worker** brokers WebSocket connections (1M req/day free) and acts as a `relayd-ws` rendezvous with **zero servers**; `cloudflared` Quick Tunnel can additionally expose a self-hosted relay/control port. A Worker "relay" never sees plaintext — it forwards opaque blobs. |
| Android | The mobile daemon can run relay/bootstrap roles; configured via `daemon.config`. |
| Routers (OpenWrt) | `relayd`/`dhtd`/`relayd-ws` compile to musl static (mips/arm); no runtime deps. |
| Tailscale | The daemon detects `100.64.0.0/10` (or `tailscale ip`) and publishes those as direct addresses; Tailscale DERP is a natural last-resort relay. |
| NGINX | `stream{}` UDP proxy in front of `relayd` (TLS/TCP is not needed for UDP, but enables load-balancing + proxy_protocol); HTTP/2 + TLS in front of the gRPC control plane and `relayd-ws`. |
| Bare metal, no containers | The same binaries run directly; systemd units or the existing launcher. Docker is never required. |

### Docker ↔ native parity

Every binary is a plain Rust executable. The Docker images are thin wrappers
(COPY the binary into a `debian-slim`/`scratch`-class base). There is no
container-only behavior: the same env-var config drives both. CI builds both
the native binaries (build matrix) and (when a Docker engine is available) the
images.

## Security model

- **Blind relays**: relays and the Cloudflare Worker forward opaque ciphertext;
  they never hold identity material or plaintext.
- **Anonymous nodes**: relay/bootstrap roles need no identity; abuse is capped
  by PoW difficulty (`RELAYD_DIFFICULTY`) and a per-IP token bucket.
- **Authenticated P2P**: peers still authenticate each other via the hybrid
  handshake (X25519 + ML-KEM, Ed25519 + ML-DSA identity). Relays are
  interchangeable plumbing under that security layer.
- **TTL/keepalive**: 45 s keepalives keep registrations (90 s TTL) and NAT
  mappings alive.

## Protocol evolution

The multi-relay endpoint, the WebSocket relay frame, and the multi-lane session
are all backward-compatible wire changes (`#[serde(default)]` on new fields,
older peers ignore unknown fields). The ciphersuite registry keeps the
cryptographic layer versioned with sunset dates. This is the mechanism that
lets the network survive for decades: new transports and ciphers are additive.

## Implementation order

1. **Multi-relay protocol** (PeerEndpoint list, comma-separated config, hub
   multi-registration, per-relay session lanes) — the foundation.
2. **Auto-routing** (multi-lane sessions, ATE failover across lanes).
3. **relay-ws** (server + client lane) and the **Cloudflare Worker** relay.
4. **Integrations**: Tailscale address detection, NGINX configs, Android node
   mode, router cross-compile guide.
5. Tests for every layer; CI green.