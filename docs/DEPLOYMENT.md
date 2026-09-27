# Hosted relay + DHT deployment (Internet-routability)

TransferDaemon is fully peer-to-peer by default (direct TCP between LAN peers).
To connect peers that are on *different* networks — the "relay replaces TURN"
claim from CONTEXT.md #12 — you run a small public relay stack:

- **`relayd`** — the blind UDP relay. It forwards opaque, PoW-authenticated
  ciphertext blobs between registered tokens. It never sees plaintext and never
  links sender to recipient.
- **`dhtd`** — a DHT bootstrap node. Clients bootstrap against it and publish
  their `relay://<public-addr>/<token>` endpoints to it, so a sender can
  discover a recipient's relay address by public key alone.

Both are tiny, dependency-light binaries (no UI/tonic/webrtc in their build
closure) and run fine on a \$5 VPS.

## Topology

```
Peer A (home NAT) ──┐                    ┌── Peer B (office NAT)
   relay client ────┼─ UDP → relayd ─────┼── relay client
   dht node ────────┼─ UDP → dhtd ───────┼── dht node
                    └─────── VPS ────────┘
```

The relay is a rendezvous: it replies to the datagram's actual `src` and
forwards by token, so it does not care that peers sit behind NAT. The DHT
bootstrap is what makes *discovery* work from behind NAT (clients publish to,
and look up through, the public bootstrap node).

## Why it works behind NAT

- **Registration/keepalive**: each client sends a UDP `Register` then a
  `Keepalive` every 45 s. This both refreshes the relay-side TTL (90 s default)
  and keeps the client's NAT mapping open (home NATs hold UDP mappings for
  ~30 s–5 min, so 45 s is safely inside).
- **Reply-to-src**: `relayd` sends replies/forwards to the datagram's actual
  source address, never to an advertised one — required for NAT'd clients.
- **Discovery**: NAT'd clients reach the *public* DHT bootstrap outbound and
  publish their endpoint; the bootstrap holds the records, so lookups succeed
  without the client being directly reachable.

## Deploying (Docker)

```sh
# From the repo root:
docker compose -f deploy/docker-compose.yml up -d --build
```

Set `PUBLIC_IP` to the VPS's public address (or edit `DHTD_ADVERTISE` in
`deploy/docker-compose.yml`). Open **UDP 5901** (relay) and **UDP 7901**
(DHT) on the host firewall. A standalone binary install works too:

```sh
cargo build --release -p relayd -p transferd-relay --bin relayd --bin dhtd
RELAYD_PORT=5901 RELAYD_DIFFICULTY=20 ./target/release/relayd
DHTD_BIND=0.0.0.0:7901 DHTD_ADVERTISE=<public-ip>:7901 ./target/release/dhtd
```

> **Why `DHTD_ADVERTISE` matters**: `dhtd` binds `0.0.0.0:7901` (reachable on
> any interface) but must *advertise* the public address in routing messages.
> Advertising `0.0.0.0` (or the bound wildcard) makes the node unreachable by
> remote peers — this was learned the hard way on the LAN E2E (CONTEXT.md #22)
> and is now handled by `DhtNode::start_with_advertised`.

## Pointing clients at the relay

**Desktop daemon (env):**

```sh
TRANSFERD_RELAY_ADDR=<public-ip>:5901
TRANSFERD_DHT_BIND=0.0.0.0:7901        # local; bind anything reachable
TRANSFERD_DHT_ADVERTISE=<public-ip>:7901  # only if this node should be reachable
TRANSFERD_DHT_BOOTSTRAP=<public-ip>:7901
```

The daemon publishes `relay://<public-ip>:5901/<token>` to the DHT, so
contacts discover it by public key and connect through the public relay.

**Android app (no env vars):** write `<files>/TransferDaemon/daemon.config`:

```
TRANSFERD_RELAY_ADDR=<public-ip>:5901
TRANSFERD_DHT_BIND=127.0.0.1:7901
TRANSFERD_DHT_BOOTSTRAP=<public-ip>:7901
```

## Security notes

- **Blind relay**: `relayd` forwards only PoW-authenticated, fixed-size
  ciphertext blobs; it has no plaintext access.
- **PoW cost**: `RELAYD_DIFFICULTY` (default 20) is the anti-abuse lever. Raise
  it if registration is being flooded; it costs real CPU per register.
- **Rate limiting**: `relayd` applies a per-source-IP token bucket to every
  datagram (see `relayd::relay::Relay::rate_limited`).
- **TTL pruning**: registrations expire after `RELAYD_TTL` (90 s) without a
  keepalive; expired tokens are pruned every 30 s.
- The relay and DHT hold no identity material: tokens are BLAKE3-derived from
  the sender's public key, and payloads are opaque.

## Known limits

- The relay/DHT are UDP; `adb forward/reverse` is TCP-only, so Android devices
  must be on a network that reaches the public relay directly (they do once
  `daemon.config` points at the public address).
- Two `dhtd` nodes (a small DHT mesh) can be run for redundancy; clients accept
  a comma-separated `TRANSFERD_DHT_BOOTSTRAP`.
## WebSocket relay + Cloudflare free tier

**elayd-ws** (new) is the same blind relay over WebSocket frames (same
elayd::protocol wire format, so the same client logic speaks both). Use it
when UDP is blocked:

`sh
RELAYD_WS_PORT=5902 RELAYD_WS_DIFFICULTY=20 cargo run -p relayd --bin relayd-ws
`

**Cloudflare Worker (free tier, zero servers)** — deploy/cloudflare-worker/
(worker.js + wrangler.toml) implements the relay as a Durable Object on
Cloudflare's edge. It forwards the exact bincode frames (elayd::protocol)
between WebSocket sessions, keyed by opaque token, so a client that speaks
elayd-ws speaks the Worker too. PoW enforcement is intentionally off there
(Cloudflare's edge rate-limits + a per-IP bucket are the free-tier abuse
barrier); self-hosted elayd/elayd-ws keep full BLAKE3 PoW.

## Multi-relay + auto-routing

TRANSFERD_RELAY_ADDR accepts a comma-separated list. The daemon registers its
identity token on every relay and publishes all of them to the DHT; a session
builds one lane per relay it shares with the peer, and the ATE fails over
between them when a relay dies (see docs/NODE_SYSTEM.md). A peer reachable
through relays A, B, C stays connected while any one of them is alive.

## The full stack in Docker (relayd + relayd-ws + dhtd)

`deploy/docker-compose.yml` now runs all three: `relayd` (UDP 5901), `relayd-ws`
(TCP 5902) and `dhtd` (UDP 7901) from one image. Standalone binary install:

```sh
cargo build --release -p relayd -p transferd-relay --bin relayd --bin relayd-ws --bin dhtd
RELAYD_PORT=5901 ./target/release/relayd
RELAYD_WS_PORT=5902 ./target/release/relayd-ws
DHTD_BIND=0.0.0.0:7901 DHTD_ADVERTISE=<public-ip>:7901 ./target/release/dhtd
```

## NGINX reverse proxy (one host, one TLS cert)

`deploy/nginx/relay-streams.conf` fronts the whole stack behind NGINX `stream`
(UDP relay, UDP DHT, TLS'd WebSocket relay, optional TLS'd gRPC) and
`deploy/nginx/grpc-http2.conf` terminates daemon gRPC over HTTP/2. With one DNS
name + Let's Encrypt, peers configure:

```
TRANSFERD_RELAY_ADDR=relay.example.com:5901
TRANSFERD_RELAY_ADDR=wss://relay.example.com:5902      # second entry
TRANSFERD_DHT_BOOTSTRAP=relay.example.com:7901
```

## Tailscale / direct lanes (no relay for tailnet peers)

When a daemon binds its peer transport reachably (`TRANSFERD_BIND_ADDR=0.0.0.0`
or a LAN/Tailscale IP), it publishes `tcp://<ip>:<port>` **direct** addresses to
the DHT. Peers on the same tailnet or LAN discover those and connect directly —
no relay at all (see CONTEXT.md #29). The relay stack remains the fallback for
peers with no shared network.
