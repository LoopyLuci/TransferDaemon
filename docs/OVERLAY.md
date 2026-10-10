# The overlay: paired devices reach each other's services, on any network

The overlay lets an application on one paired device reach a service on another, without:

- an open firewall port;
- a router port-forward;
- a VPN.

It works across a LAN, behind NAT or CGNAT, on IPv4 or IPv6, and with or without Tailscale.

Every node keeps only **outbound** connections:

- to a relay (`relayd`, which anyone can host);
- to a peer directly, when there is a path.

Traffic is end-to-end encrypted with TransferDaemon's hybrid post-quantum identity. The relay sees only ciphertext.

It runs inside the daemon (`transferd`) as one node per installation. Its operations are on the control hub (see
CONTROL.md), so `transferd-cli`, MCP clients and scripts all use it the same way. The wire format is in PROTOCOL.md.

## Using it

```
# on the machine that offers something
transferd-cli overlay invite                      # -> {"invite": "tdov1:..."}  (valid 15 minutes by default)
transferd-cli overlay expose web 127.0.0.1:8080   # only paired nodes; or list node ids instead

# on the machine that wants it
transferd-cli overlay accept tdov1:... laptop     # pair, and call it "laptop"
transferd-cli overlay connect <node-id> web       # -> {"local_addr": "127.0.0.1:50123", "route": "relay"}
curl http://127.0.0.1:50123/
```

**Pairing:**
- An invite is signed, carries the node's identity and how to reach it, and expires.
- Accepting one pairs both ways. The accepting node presents the invite's one-time nonce in its first hello, and the
  inviting node then knows the pairing is mutual.
- A node is paired only through an invite. Merely opening a session does not count, so `*paired` never includes a node
  that just happened to learn a node id.
- Trust on first use: a node that later presents a different key for the same id is refused.

**Services:**
- Nothing is exposed until `overlay.expose`.
- Each service has an access list: node ids, and/or `*paired`.
- An open from anyone else is refused before it reaches the local socket, and the refusal goes in the audit trail
  (`overlay.audit`).
- Each service is also rate-limited per node.

**Endpoints:**
- `overlay.connect` gives a stable local address for a peer's service: idempotent, and listening until
  `overlay.disconnect`.
- A target can be a node id, the name the node was paired under, a unique id prefix (8+ characters), or a service
  group (`overlay.group_set`). A group is spread over its members by route quality and the streams already open to each.

**Proxies:**
- `overlay.proxies_start` runs a local SOCKS5 proxy and an HTTP-CONNECT proxy.
- Any application can then reach `<service>.<node>.td` with no per-service setup. `<node>` is the paired name or an
  id prefix (a whole id is longer than a DNS label allows).
- Only CONNECT is proxied.

## How a path is found

1. **Direct.** The addresses a peer published (its listener, `TRANSFERD_OVERLAY_DIRECT`: LAN, tailnet, a public
   address) are dialled first, each with a short timeout.
2. **Relay.** Both nodes register an identity-derived token on the same relay. The relay forwards opaque datagrams
   between the mappings their own outbound registrations created, so nothing has to be opened anywhere. Registrations
   are renewed every 30 s, so a restarted relay gets its nodes back within a minute. A relay that is down at start is
   retried in the background.
3. Once a session is up on one kind of path, the node adds the other kind beside it. The session then has a second
   route to fail over to, and the cheaper one carries the traffic.
4. **Hole punch.** When the dialling node holds a session over the relay (and the peer is paired and speaks protocol
   version 3 or later), it asks the peer for a direct UDP path. The relay stays; the punch only adds a route.

**UDP hole punching.**

How it goes:
- Each node asks the relay (`Locate`) which address it sees for its registration socket. That is the NAT mapping a peer
  can be sure to find. The question goes out on the same socket the node registered with.
- A node also names its own address towards the relay, when that is not loopback, for a peer on the same network.
- The dialler sends its candidates over the existing session (frame CANDIDATE, see PROTOCOL.md section 8). The peer
  answers with its own. Both add a random nonce. The nonces never leave the encrypted session, so only the two nodes can
  derive the probe key.
- Both then send authenticated probes **from the registration socket** to every address the other named: ten rounds,
  200 ms apart, so about two seconds. A port-restricted cone NAT lets a probe in once the inside has sent to that
  address, which is exactly what the two nodes' own probes arrange.
- The first authenticated reply wins. The session gains a `holepunch` route (marked down until its first ping is
  answered, so nothing is sent into a hole that is one-way), and the cheaper route carries the traffic.

What keeps it safe:
- A probe is a 33-byte datagram with a MAC under the attempt's key. Anything else is dropped without an answer, from the
  wrong role, from an address the peer did not name, or after the attempt is over (two seconds).
- Probes go only to addresses the peer named, at most eight, and never to loopback, link-local, multicast or
  unspecified ones (loopback only when the relay itself is on loopback). A stranger who replays a captured probe from
  another address gets nothing back.
- Replies are rate-limited per address and per attempt. A request is accepted from a paired peer, at most once in
  three seconds.
- If it fails, nothing changes: the relay route is untouched, and the node logs a `route.change` event
  "holepunch failed".

What works and what does not:
- **Works:** two nodes behind cone NATs (tested with the strictest, port-restricted; full and restricted are more
  permissive), a node with a public address behind
  nothing, two nodes on the same network (the private candidate).
- **Does not:** a symmetric NAT on either side (it gives each destination a different port, so the address the relay
  saw is useless to the peer), a NAT or firewall that drops unsolicited UDP from a new address even after the inside
  sent to it, and a network that blocks UDP. These stay on the relay, which loses nothing.
- Not tried: guessing ports (birthday punching), IPv6 candidates, UPnP / NAT-PMP / PCP, or a punch toward a relay that
  is not on the node's first reachable relay. The punch is tried once, when the session comes up over the relay; it is
  not retried when a NAT mapping changes later (the session then keeps using the relay).
- A route that goes quiet stays alive by the session's own one-second pings, which also keep the NAT mapping open.
- `OverlayConfig::punch` turns it off. `OverlayConfig::udp_gateway` sends every datagram that is not for the relay
  through a UDP-aware proxy, wrapped with its real destination (a NAT emulator in the tests is one).

## Inside a session

- **One session per peer, many routes.** A new link to a peer joins its live session as another route.
- **Probing.** Every route is probed once a second for RTT, loss and throughput. A route is down after three missed
  probes in a row, and up again as soon as an authenticated frame arrives on it. A session never stops sending just
  because its only route looks down.
- **Streams.** Streams are multiplexed, flow-controlled with a per-stream window, and sequenced. Acknowledgements are
  cumulative. Unacknowledged data is resent on another route after 400 ms, so a route dying mid-stream does not break
  the TCP connection the application sees (a test cuts a LAN path under a live stream).
- **Control frames.** Hello, open, accept, window and close carry receipts and are resent until one comes back.
  Pings and route reports are best effort.
- **Loss.** A test runs streams through a relay path that drops 20% of datagrams each way, and every byte arrives in
  order.
- **Wake-ups.** Sessions are woken when a frame arrives, not on a timer: a DNS query over a relay on loopback takes
  about 2 ms.

## Mesh DNS

One node's names can be answered by a paired node's resolver, over the overlay:

```
app ── UDP/TCP ──► 127.0.0.1:53053 (mesh DNS forwarder) ══ overlay ══► the peer's resolver
```

**Setting it up:**
- **The node that shares a resolver** exposes it as the service `dns`:
  `transferd-cli overlay expose dns 127.0.0.1:53` (any resolver that speaks DNS over TCP, for example a filtering or
  validating one).
- **The node that uses it:** `transferd-cli overlay dns set <node-id|group ...>`. Or set `TRANSFERD_MESH_DNS` (and
  `TRANSFERD_MESH_DNS_LISTEN`) for the daemon.
- The setting is kept across restarts. `overlay dns off` turns it off.

**Behaviour:**
- **Failover.** Upstreams are tried in order. One that fails is set aside for 30 s, and when all fail the client gets
  SERVFAIL rather than silence.
- **Connections.** Each upstream gets one DNS-over-TCP connection with queries pipelined on it. Query ids are rewritten
  on the way out, so two clients that chose the same id never see each other's answers.
- **UDP clients.** A UDP client gets a truncated answer (TC set) when the response is too big for it, and asks again
  over TCP.
- **Counters.** `overlay.dns_status` reports, per upstream: health, queries, answers, NXDOMAIN, SERVFAIL, timeouts,
  errors, the average round trip, and *blocked*. Blocked counts answers whose addresses are all `0.0.0.0` or `::`,
  which is how filtering resolvers answer a name they block. It also shows which resolver this node shares.
- **TransferDaemon's own lookups** can go through it too: add `mesh` to `TRANSFERD_DNS`, for example
  `TRANSFERD_DNS=mesh,quad9,system` (address: `TRANSFERD_DNS_MESH`). It is not in the default order: a node must be
  able to reach its relays before the mesh exists.

Nothing in mesh DNS knows what the resolver at the other end is. The overlay carries DNS; that resolver decides the
answers.

## Settings (the daemon)

| Setting | Default | |
|---|---|---|
| `TRANSFERD_OVERLAY` | on | `off` leaves the overlay out |
| `TRANSFERD_OVERLAY_RELAYS` | the UDP entries of `TRANSFERD_RELAY_ADDR` | relays to register on, `host:port,...` |
| `TRANSFERD_OVERLAY_LISTEN` | none | a direct listener; nothing needs one to be reachable |
| `TRANSFERD_OVERLAY_DIRECT` | none | addresses to publish in invites |
| `TRANSFERD_OVERLAY_NAME` | the computer's name | how the node introduces itself |
| `TRANSFERD_MESH_DNS` | none | mesh DNS upstreams; when set, it wins over the stored setting at every start |
| `TRANSFERD_MESH_DNS_LISTEN` | `127.0.0.1:53053` | where mesh DNS answers |

**Where its files live** (all under the data folder's `overlay/`):
- The node's key is a 64-byte seed, kept like the recovery-phrase cache: DPAPI on Windows, an owner-only file elsewhere.
- Paired nodes, exposed services, groups, outstanding invites and the mesh DNS setting are in `state.json`
  (versioned, migrated on load).
- The audit trail is in `audit.jsonl`.

**A relay that carries overlay traffic:** relayd's per-source limit (`RELAYD_RATE_PER_30S`, default 300 datagrams per
30 s) is sized for messaging. A relay that carries overlay streams wants it raised. `RELAYD_BIND` puts relayd on one
address (for example loopback, for a test) instead of every interface.

## Measured

Debug builds, loopback, one machine: about 2 ms per mesh DNS query through a relay (median of 20), and every stream
intact through a relay path losing 20% of its datagrams each way. Release-build throughput and latency, direct and
relayed:

```
cargo test --release -p transferd-overlay --test bench -- --ignored --nocapture
```

Release build, Windows, one machine, loopback (2026-10). 64 MiB one way, then 200 one-byte round trips:

| Path | Throughput | Round trip p50 / p99 |
|---|---|---|
| direct (LAN listener) | 143 MB/s (1.1 Gbit/s) | 0.15 ms / 13.9 ms |
| relayed (relayd's logic, in process) | 96 MB/s (770 Mbit/s) | 0.23 ms / 0.41 ms |

The relayed figure depends on socket buffers. A stream sends a window (256 KiB) at once, and a 64 KiB default UDP
receive buffer drops most of it; then only the 400 ms resend timer moves the data, at about 1 MB/s. The relay client
and relayd ask for 4 MiB buffers. Loopback numbers are an upper bound: on a real network the path's own bandwidth
and RTT decide, and the overlay has no congestion control yet beyond the per-stream window.

## Tests

`cargo test -p transferd-overlay` covers the following, on real sockets:
- two and three nodes with no listener, reaching each other through a relay;
- a direct path preferred, and a stream surviving it being cut;
- the access list enforced and audited;
- SOCKS5 and HTTP CONNECT;
- a group spread over its members;
- older and newer peers agreeing on a version;
- a service exposed after the session came up;
- a 20%-loss relay path;
- hole punching through userspace NAT emulators: two port-restricted cone NATs give a punched route that carries a
  stream with the relay gone, a symmetric NAT fails cleanly and the relay carries the stream, and a stranger's replayed
  probe is ignored and never answered;
- mesh DNS: answers, blocked and NXDOMAIN counted, failover, SERVFAIL, the setting surviving a restart.
