# Tailscale DERP + the direct lane

TransferDaemon peers that share a Tailscale tailnet (or a LAN) connect **directly** —
no relay, no server. This page explains how the Tailscale mesh (including its
**DERP** relay fallback) carries those direct lanes, and how to self-host your
own DERP for a robust tailnet.

## How the direct lane rides the mesh

- A daemon with `TRANSFERD_BIND_ADDR=0.0.0.0` (or a specific LAN/Tailscale IP)
  publishes **direct `tcp://<ip>:<port>`** addresses in its `PeerEndpoint`
  (CONTEXT.md #29). `reachable_ipv4()` includes Tailscale `100.64/10`
  addresses, so the peer's Tailscale IP is advertised.
- A peer that shares the tailnet **prefers the direct address over any relay**
  (`ensure_contact_session`), and the ATE ranks the direct TCP lane highest.
- **Tailscale handles the transport**: the TCP connection to the peer's
  100.x address goes over the mesh. If direct P2P (UDP + NAT traversal) works,
  the mesh routes it peer-to-peer. If it does not (restrictive NAT, blocked
  UDP), Tailscale transparently falls back to a **DERP relay** — an
  encrypted WebSocket relay on Tailscale's infrastructure (or your own).

So the direct lane "just works" on a tailnet: it uses the best path Tailscale
can find, and DERP is the guaranteed fallback. TransferDaemon's own
relayd/relayd-ws/Cloudflare Worker remain the fallback for peers NOT on a
shared tailnet.

## Self-hosting DERP (for a fully private mesh)

Tailscale's `derper` relays the mesh's encrypted packets. Run your own so no
peer traffic touches Tailscale's infrastructure:

```sh
# One-off, on the VPS: download derper (a single Go binary).
go install tailscale.com/cmd/derper@latest
# Run it (TLS on 443, WebSocket relay on 443).
derper --hostname=derp.example.com --stun-port=3478 --verify-clients
```

Point your tailnet at it from the admin console (Access Controls), or pass it
to a client:

```sh
tailscale up --operator=$USER
tailscale set --exit-node= --advertise-routes=   # keep defaults
# derp-map is configured in the tailnet ACL:
tailscale status
```

Once the tailnet uses your DERP, the direct lane is robust even on the worst
networks — TransferDaemon just connects to the peer's 100.x address and
Tailscale routes it (P2P or via your DERP).

## Config for a tailnet peer

**Desktop / server daemon:**

```sh
TRANSFERD_BIND_ADDR=0.0.0.0          # accept direct connections on the mesh
TRANSFERD_PORT=50051                 # transport listener on 50052
```

**Android app** (`<files>/TransferDaemon/daemon.config`):

```
TRANSFERD_BIND_ADDR=0.0.0.0
TRANSFERD_RELAY_ADDR=wss://transferd-relay.limpidluci.workers.dev:443
```

With these, the daemon publishes its Tailscale IP as a direct address and peers
on the tailnet connect straight to it (DERP fallback included). Peers NOT on
the tailnet use the relay.

## Verified

`desktop_sends_to_kindle_over_tailnet_direct_lane` (ignored test): the desktop
daemon connects to the real Kindle over the mesh (`inbound connection from
100.101.98.77` on the Kindle), and the message is delivered + acked with no
relay — the direct lane over the tailnet, DERP-ready.