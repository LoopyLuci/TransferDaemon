# The overlay in TransferDaemon

The overlay lets an application on one paired device reach a service on another, without an open firewall port, a router port-forward or a VPN. It works across a LAN, behind NAT or CGNAT, on IPv4 or IPv6, with or without Tailscale.

This page describes how the overlay runs in TransferDaemon: the commands, the settings, where its files live, what has been measured, and which tests cover it. What the overlay *is*, its pairing rules, path selection, stream semantics and wire format are specified in the protocol repository:

- [Transferd overlay semantics](https://github.com/LoopyLuci/Transferd/blob/main/docs/OVERLAY.md)
- [Transferd wire protocol](https://github.com/LoopyLuci/Transferd/blob/main/docs/PROTOCOL.md), in particular §8 for hole punching
- [How this build maps onto the protocol](PROTOCOL.md)

The daemon (`transferd`) runs one overlay node per installation. Its operations are on the control hub (see [CONTROL.md](CONTROL.md)), so `transferd-cli`, MCP clients and scripts all use it the same way.

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

**Pairing in this build:**
- Merely opening a session does not count as pairing, so `*paired` never includes a node that only learned a node id.
- Trust on first use is enforced: a node that later presents a different key for the same id is refused.

**Services in this build:**
- Nothing is exposed until `overlay.expose`.
- Refused opens are recorded in the audit trail (`overlay.audit`).
- Each service is also rate-limited per node.

**Endpoints:**
- `overlay.connect` gives a stable local address for a peer's service. It is idempotent and keeps listening until `overlay.disconnect`.
- A target can be a node id, the name the node was paired under, a unique id prefix (8+ characters), or a service group (`overlay.group_set`). A group is spread over its members by route quality and by the streams already open to each.

**Proxies:**
- `overlay.proxies_start` runs a local SOCKS5 proxy and an HTTP-CONNECT proxy.
- Any application can then reach `<service>.<node>.td` with no per-service setup. `<node>` is the paired name or an id prefix, since a whole id is longer than a DNS label allows.
- Only CONNECT is proxied.

## How a path is found, in this build

1. **Direct.** The addresses a peer published (its listener, set by `TRANSFERD_OVERLAY_DIRECT`: LAN, tailnet, or a public address) are dialed first, each with a short timeout.
2. **Relay.** The node registers on the relays in `TRANSFERD_OVERLAY_RELAYS`, renewing every 30 s, so a restarted relay gets its nodes back within a minute. A relay that is down at start is retried in the background.
3. Once a session is up on one kind of path, the node adds the other kind beside it, and the cheaper route carries the traffic.
4. **Hole punch.** Attempted once, when a session comes up over the relay, if the peer is paired and speaks protocol version 3 or later. It is not retried when a NAT mapping changes later, and the session keeps using the relay in that case. The exchange is in [PROTOCOL.md §8](https://github.com/LoopyLuci/Transferd/blob/main/docs/PROTOCOL.md#8-hole-punching) of the protocol repository.

### Hole punching results

What has been observed in tests and on real networks with this build:

- **Works:** two nodes behind cone NATs, tested with the strictest, port-restricted, and the more permissive full and restricted cone NATs as well; a node with a public address and no NAT; two nodes on the same network, through the private candidate.
- **Does not work:** a symmetric NAT on either side, since it gives each destination a different port and the address the relay saw is useless to the peer; a NAT or firewall that drops unsolicited UDP from a new address even after the inside has sent to it; a network that blocks UDP. These stay on the relay, which loses nothing.
- **Not implemented:** guessing ports (birthday punching), IPv6 candidates, UPnP, NAT-PMP or PCP, and a punch toward a relay that is not the node's first reachable relay.
- A route that goes quiet stays alive through the session's own one-second pings, which also keep the NAT mapping open.

**Switches:** `OverlayConfig::punch` turns hole punching off. `OverlayConfig::udp_gateway` sends every datagram that is not for the relay through a UDP-aware proxy, wrapped with its real destination. A NAT emulator in the tests is one such proxy.

## Inside a session, in this build

- **Probing.** Every route is probed once a second for RTT, loss and throughput.
- **Wake-ups.** Sessions are woken when a frame arrives rather than on a timer. A mesh DNS query over a relay on loopback takes about 2 ms.
- **Loss.** A test runs streams through a relay path that drops 20% of datagrams each way, and every byte arrives in order.
- **Route loss.** A test cuts a LAN path under a live stream, and the TCP connection the application sees survives.

## Mesh DNS

One node's names can be answered by a paired node's resolver, over the overlay:

```
app ── UDP/TCP ──► 127.0.0.1:53053 (mesh DNS forwarder) ══ overlay ══► the peer's resolver
```

**Setting it up:**
- **The node that shares a resolver** exposes it as the service `dns`:
  `transferd-cli overlay expose dns 127.0.0.1:53` (any resolver that speaks DNS over TCP, for example a filtering or validating one).
- **The node that uses it:** `transferd-cli overlay dns set <node-id|group ...>`, or set `TRANSFERD_MESH_DNS` (and `TRANSFERD_MESH_DNS_LISTEN`) for the daemon.
- The setting is kept across restarts. `overlay dns off` turns it off.

**Behaviour in this build:**
- **Failover.** Upstreams are tried in order. One that fails is set aside for 30 s. When all fail, the client gets SERVFAIL rather than silence.
- **Connections.** Each upstream gets one DNS-over-TCP connection, with queries pipelined on it. Query ids are rewritten on the way out.
- **UDP clients.** A UDP client gets a truncated answer (TC set) when the response is too big for it, and asks again over TCP.
- **Counters.** `overlay.dns_status` reports, per upstream: health, queries, answers, NXDOMAIN, SERVFAIL, timeouts, errors, the average round trip, and *blocked*. Blocked counts answers whose addresses are all `0.0.0.0` or `::`, which is how filtering resolvers answer a name they block. It also shows which resolver this node shares.
- **TransferDaemon's own lookups** can go through it too: add `mesh` to `TRANSFERD_DNS`, for example `TRANSFERD_DNS=mesh,quad9,system` (address: `TRANSFERD_DNS_MESH`). It is not in the default order, because a node must be able to reach its relays before the mesh exists.

Mesh DNS does not know what the resolver at the other end is. The overlay carries the queries; that resolver decides the answers.

## Settings

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
- Paired nodes, exposed services, groups, outstanding invites and the mesh DNS setting are in `state.json` (versioned, migrated on load).
- The audit trail is in `audit.jsonl`.

**A relay that carries overlay traffic.** `relayd`'s per-source limit (`RELAYD_RATE_PER_30S`, default 300 datagrams per 30 s) is sized for messaging. A relay that carries overlay streams needs it raised. `RELAYD_BIND` puts `relayd` on one address (for example loopback, for a test) instead of every interface.

## Measured

Debug builds, loopback, one machine: about 2 ms per mesh DNS query through a relay (median of 20), and every stream intact through a relay path losing 20% of its datagrams each way.

Release-build throughput and latency, direct and relayed, can be reproduced with:

```
cargo test --release -p transferd-overlay --test bench -- --ignored --nocapture
```

Release build, Windows, one machine, loopback (2026-10). 64 MiB one way, then 200 one-byte round trips:

| Path | Throughput | Round trip p50 / p99 |
|---|---|---|
| direct (LAN listener) | 143 MB/s (1.1 Gbit/s) | 0.15 ms / 13.9 ms |
| relayed (relayd's logic, in process) | 96 MB/s (770 Mbit/s) | 0.23 ms / 0.41 ms |

With per-route congestion control, the same bench, medians of 6 runs on the same machine: direct 128 MB/s, relayed 90 MB/s, against 134 MB/s and 84 MB/s for the previous build measured in the same session. Run-to-run spread is about 15%, so no regression shows. Loopback numbers are an upper bound: on a real network, the path's own bandwidth and RTT decide. The relay client and `relayd` ask for 4 MiB socket buffers.

### Congestion control in this build

Each route has its own state in `src/cc.rs`. The protocol recommends this approach; the parameters below are this build's choices.

- **RTO.** As in RFC 6298: `rto = srtt + max(4 * rttvar, 100 ms)`, clamped to 200 ms to 5 s, 400 ms before the first sample, doubled per timeout until a new sample arrives.
- **Window.** NewReno style: slow start from 10 full frames, one frame per round trip afterwards, cut to 0.7 on a loss and at most once per window of data. AIMD was chosen over CUBIC: frames are large, paths are short, and AIMD plus pacing is small enough to test exactly.
- **Pacing.** A window is spread over the smoothed round trip (twice as fast in slow start) instead of leaving as a burst.
- **SACK.** A gap reported by the receiver counts as a loss without waiting for the timer.
- `overlay.peers`, the probe output and the route report carry `cwnd`, `in_flight`, `srtt_ms`, `rto_ms`, `sent_bytes` and `retx_bytes` per route. Older peers omit them, and they default to 0.

Measured with `tests/congestion.rs`, a token-bucket link emulator with a drop-tail queue and a delay, through a relay, debug build: a 16 MiB transfer over 2 MB/s with 40 ms each way and a 96 KiB queue arrives intact at 76-78% of the link. It resends 1.3-1.5% of the bytes sent, and 0.6-0.7% of the bytes offered to the queue are dropped. The queue is nearly full for 1% of the bytes. With plenty of bandwidth, the RTO settles at about 220-270 ms for 40 ms each way, and about 700 ms for 300 ms each way.

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
- hole punching through userspace NAT emulators: two port-restricted cone NATs give a punched route that carries a stream with the relay gone; a symmetric NAT fails cleanly and the relay carries the stream; a stranger's replayed probe is ignored and never answered;
- mesh DNS: answers, blocked and NXDOMAIN counted, failover, SERVFAIL, and the setting surviving a restart.
