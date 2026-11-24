# The Transferd Overlay

The overlay lets an application on one paired node reach a service on another, without an open firewall port, a router port-forward, or a VPN. It works across a LAN, behind NAT or CGNAT, on IPv4 or IPv6.

Every node keeps only **outbound** connections:
- to a relay (any conforming blind relay; anyone can host one);
- to a peer directly, when there is a path.

Traffic is end-to-end encrypted with the node's hybrid post-quantum identity. The relay sees only ciphertext.

This document describes the overlay's semantics. The bytes are in [PROTOCOL.md](PROTOCOL.md). Keys and labels are in [CRYPTO.md](CRYPTO.md). Relay rules are in [RELAY.md](RELAY.md).

## Pairing

- An invite is signed by the node it names, carries that node's id, the fingerprint of its key and how to reach it, and expires. It is a few hundred bytes, so it fits a QR code. See [PROTOCOL.md](PROTOCOL.md) §6.
- Accepting an invite pairs both nodes. The accepting node presents the invite's one-time nonce in its first hello, and the inviting node then knows the pairing is mutual.
- A node MUST be paired only through an invite. Merely opening a session does not count as pairing.
- **First contact.** A node dialled from an invite MUST present the hybrid public key the invite fingerprinted. The check runs before any link is attached, so a node that does not match is never reached.
- **Trust on first use.** A node that later presents a different key for an id it already knows MUST be refused.

## Services and access

- Nothing is exposed until a node explicitly configures it.
- Each service has an access list: node ids, and/or the token `*paired`, meaning any node that is paired.
- An OPEN from anyone else MUST be refused before it reaches the local service.
- A node SHOULD rate-limit each service per peer.
- A node SHOULD record refused opens in an audit log.

## Naming

- A service is addressed by its node id, the name under which the node was paired, or a unique prefix of its id.
- A group of services MAY be addressed as one target. Its members are chosen by the caller's own criteria, such as route quality.

## How a path is found

1. **Direct.** Addresses a peer has published are dialed first, each with a short timeout.
2. **Relay.** Both nodes register an identity-derived token on the same relay (see [RELAY.md](RELAY.md)). The relay forwards opaque datagrams between the mappings their own outbound registrations created, so nothing has to be opened on either side.
3. **Adding a second kind of path.** Once a session is up on one kind of path, the node SHOULD add the other kind beside it. The session then has a second route to fail over to, and the cheaper one carries the traffic.
4. **Hole punch.** When the dialing node holds a session over the relay, and the peer is paired and speaks protocol version 3 or later, the node MAY ask the peer for a direct UDP path (see [PROTOCOL.md](PROTOCOL.md) §8). The relay stays. The punch only adds a route, and if it fails nothing else changes.

## Inside a session

- **One session per peer, many routes.** A new link to a peer joins its live session as another route. A session MUST NOT stop sending merely because its only route looks down.
- **Probing.** Every route is pinged once a second. A route is down after three missed pings in a row, and up again as soon as an authenticated frame arrives on it.
- **Streams.** Streams are multiplexed, flow-controlled with a per-stream window, and sequenced. Acknowledgements are cumulative, with SACK ranges for gaps. Unacknowledged data is resent on another route after the route's retransmission timeout, so a route dying mid-stream does not break the stream the application sees.
- **Control frames.** Hello, open, accept, window and close carry receipts and are resent until one comes back. Pings and route reports are best effort.
- **Loss.** A stream MUST survive loss and reordering on any route. Retransmission is what guarantees it, not the path.

### Recommended congestion control

These are recommendations, not wire requirements. A node MAY choose its own algorithm, as long as it stays within the frame and window rules in [PROTOCOL.md](PROTOCOL.md).

- **Per-route state.** Each route SHOULD keep its own SRTT, RTTVAR, RTO and congestion window, in the style of RFC 6298 and NewReno.
- **RTO.** The reference implementation starts the RTO at 400 ms and adapts it from measured round trips, clamped to a range of 200 ms to 5 s. An RTO SHOULD back off on timeout until a new sample arrives.
- **Window.** Slow start from a small initial window, additive increase per round trip, and multiplicative decrease on loss.
- **Pacing.** A window SHOULD be spread over the smoothed round trip rather than sent as a burst.
- **SACK.** A gap reported by SACK ranges SHOULD count as a loss without waiting for the timer.
- **Back-pressure.** A sender MUST wait when either the stream window or the route's window is full. Data MUST NOT be dropped to relieve pressure.

## Mesh DNS

One node's names can be answered by a paired node's resolver, over the overlay. The overlay only carries DNS queries and responses. The resolver at the far end decides the answers.

- A node MAY expose a resolver as a service. The resolver can be any DNS server that accepts queries over TCP.
- A node MAY use paired resolvers as upstreams. A node SHOULD fail over between upstreams in order, and SHOULD return SERVFAIL, not silence, when all of them fail.
- Query ids MUST be rewritten on the way out, so that two clients choosing the same id never see each other's answers.

## What this document does not specify

These are implementation concerns, and two conforming implementations MAY differ in them:
- configuration, command-line and control interfaces;
- where keys and state are stored;
- user interface;
- audit log format;
- relay rate limits and proof-of-work difficulty;
- route selection policy beyond "the cheapest live route".

## Compatibility

A node is a conforming overlay node if it speaks the frames in [PROTOCOL.md](PROTOCOL.md) correctly and honors the pairing and access-list rules in this document.
