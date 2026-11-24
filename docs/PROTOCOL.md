# Transferd Wire Protocol

This document is the canonical wire specification of Transferd. It defines what a conforming node may send, what it must accept, and how builds of different ages stay interoperable.

It describes bytes and required behavior only. The overlay semantics that use this wire format are in [OVERLAY.md](OVERLAY.md). Cryptographic constructions are in [CRYPTO.md](CRYPTO.md). The blind relay is in [RELAY.md](RELAY.md). Mapping to a concrete codebase is in [IMPLEMENTATION.md](IMPLEMENTATION.md).

The words MUST, MUST NOT, SHOULD and MAY are used in their usual specification sense.

```
 application stream bytes
 ── frames ─────────────  session: hello, streams (open / data / ack / window / close), pings, receipts
 ── tunnel ─────────────  per link: AES-256-GCM, a counter, a replay window
 ── link ───────────────  TCP (direct), relay datagrams, or any LinkTransport
```

**A note on names.** Some fixed strings used as cryptographic labels (for example `TransferDaemon-overlay-c2s-v1`) carry the name of the first implementation. They are wire-visible constants. They are kept unchanged so that every build derives the same keys. They do not name a requirement on the implementation.

## 1. Identity and the handshake

**Identity.**
- A node's identity is a hybrid signing key: Ed25519 and ML-DSA-87.
- Its **node id** is the hex encoding of the 32-byte Ed25519 public key (64 lowercase hex characters).
- A node MUST keep one identity for its lifetime. The identity is derived from a stored 64-byte seed.

**Handshake.** Every link MUST begin with an authenticated hybrid handshake (version 2 of the handshake):

| Flight | Contents |
|--------|----------|
| initiator (8568 bytes) | tag `0x11`, protocol version, ciphersuite, X25519 public key, ML-KEM-768 encapsulation key, the 2624-byte hybrid identity key, a BLAKE3 transcript of all of it, and an Ed25519 + ML-DSA-87 signature over the transcript |
| responder (8472 bytes) | tag `0x12`, the same layout with the ML-KEM ciphertext in place of the encapsulation key |

- Both flights MUST be verified. The dialer MUST also check that the responder's Ed25519 key is the node id it dialed.
- The shared secret is BLAKE3 over the X25519 and ML-KEM shared secrets. Breaking it requires both a classical and a post-quantum break.
- Ciphersuites are identified by a `u16`. `0x0002` is X25519 + ML-KEM-768 with Ed25519 + ML-DSA-87. A new suite is a new identifier, offered and verified the same way. An algorithm MUST NOT be changed under an existing identifier (crypto-agility rule).

**Over a direct TCP link**, each flight is sent as `len u32 BE ‖ bytes`.

**Over a relay**, each flight is a relay payload (§3): prefix `0x01` for the initiator flight and `0x03` for the responder's.
- The initiator resends its flight every 0.9 s until it is answered, or 5 s pass.
- A responder that receives a flight it has already answered (same bytes) MUST send the same answer again. It MUST NOT derive a second key for it.

## 2. The tunnel (per link)

From the shared secret each side derives two directional keys:

```
k_c2s = BLAKE3-derive_key("TransferDaemon-overlay-c2s-v1", secret)    // initiator → responder
k_s2c = BLAKE3-derive_key("TransferDaemon-overlay-s2c-v1", secret)    // responder → initiator
```

A tunnel frame:

```
tunnel_frame := len u32 BE | counter u64 BE | AES-256-GCM(key, nonce, plaintext, aad = len ‖ counter)
nonce        := key[0..4] ‖ counter u64 BE
```

- **The counter** starts at 0 and increases by one for every frame sealed with that key. A (key, nonce) pair MUST NOT be reused.
- **The length and the counter** are authenticated. A frame that is cut, extended or moved MUST be rejected.
- **Replay window.** The receiver keeps a window over the counter, 4096 wide, in the style of RFC 4303. A counter it has already accepted, or one older than the window, MUST be dropped.
- **Order of checks.** The window MUST be checked only after the frame authenticates, so a forged counter cannot move it.
- **Several links per peer.** Links of one session deliver in their own order. The window absorbs that.

The plaintext of a tunnel frame is one or more overlay frames (§4).

## 3. Relay encapsulation

The reference relay is `relayd` (see [RELAY.md](RELAY.md)).
- A node registers a 32-byte token, `BLAKE3-derive_key("transferd-overlay-relay-token-v1", node_id)`, with proof of work.
- A node sends `Forward{token, ciphertext}` to reach a token.
- The relay never sees more than the token and the padded ciphertext.

Inside `ciphertext`:

```
payload := len u32 LE | prefix u8 | sender_token [32] | body ,  zero-padded to a power of two (>= 64 bytes)
prefix  := 0x01 initiator flight | 0x03 responder flight | 0x02 a sealed tunnel frame
```

- **Padding** puts every payload on a size grid. The relay learns sizes only to within a factor of two.
- **Several links per peer.** A node MAY hold several links to one peer through one relay (each side dialed, or a route added later), up to four. A `0x02` payload carries no link id. It is delivered to the link whose keys authenticate it.
- **Early payloads.** A payload that arrives before its link is registered MAY be held briefly, up to 64 per peer.

**Registration and `Locate`.**
- Registration MUST be renewed every 30 s. A registration or keepalive MUST carry a sequence number newer than the last one the relay saw for that token. A client SHOULD start its sequence from the clock, so that a restarted node is not refused.
- `Locate` (tag `0x08`, a relay control message) asks the relay which address it sees for the asker and for another token. The relay MUST answer only for a token registered from the asking address.

## 4. Frames

```
frame := magic "TDOV" | version u8 | kind u8 | flags u16 LE | seq u64 LE | len u32 LE | body[len]
```

- **`version`**: the frame's protocol version.
- **`seq`**: counts every frame a session sends in one direction. It identifies control frames for their receipts (§5).
- **`flags`**: `0x1` MIRROR (sent on every route, used for resends) and `0x2` BULK (may be striped across routes).
- **`body`**: bincode, with the struct named by `kind`. `len` MUST be at most 60 KiB.

| kind | name | body | receipt |
|------|------|------|---------|
| 0x01 | HELLO | `{min_version, max_version, node_id, name, services, ext, nonce}` | yes |
| 0x02 | HELLO_ACK | `{version, node_id, name, services, nonce, reason, ext}` | yes |
| 0x03 | OPEN | `{stream, service, node_id}` | yes |
| 0x04 | OPEN_OK | `{stream, route}` | yes |
| 0x05 | OPEN_ERR | `{stream, code, reason}` (`no_such_service`, `denied`, `rate_limited`, `protocol`) | yes |
| 0x10 | DATA | `{stream, seq, fin, payload}` | via ACK |
| 0x11 | ACK | `{stream, seq, sack}`: every DATA frame of the stream below `seq` has arrived; `sack` lists `[from, to)` ranges beyond it that have too. `sack` is a trailing field: older builds ignore it, and an ACK without it reads as no ranges | no |
| 0x12 | WINDOW | `{stream, credit}`: the sender may send `credit` more bytes | yes |
| 0x13 | CLOSE | `{stream, code, reason}` | yes |
| 0x14 | CTRL_ACK | `{seq}`: the control frame with this frame `seq` arrived | no |
| 0x20 | PING | `{nonce, sent_us}` | no |
| 0x21 | PONG | `{nonce, sent_us}`, sent on the route the PING came in on | no |
| 0x30 | ROUTES | the sender's route measurements, informational | no |
| 0x40 | CANDIDATE | `{id, reply, nonce, candidates}`: one side of a hole-punch exchange (§8). Version 3 and later | yes |
| 0x7f | BYE | — | no |

## 5. The session

**Hello.**
- Each side MUST send HELLO first, with the version range it speaks and the services it exposes.
- HELLO carries a random `nonce`. HELLO_ACK echoes it, so the initiator knows the answer is not a replay.
- On a peer's HELLO, a node MUST check the claimed `node_id` against the identity the handshake proved, and answer with HELLO_ACK. The answer carries the highest version present in both ranges, or 0 and a `reason` when there is none.
- A session MUST NOT carry streams until the agreed version is known to both sides.
- A node MUST send HELLO again whenever the services it exposes change. The peer replaces its list.

**`ext` (HELLO and HELLO_ACK).**
- A bincode `HelloExt` with optional fields only. An empty or unreadable `ext` MUST be treated as an empty extension.
- Defined fields:
  - `pairing`, the nonce of an invite the sender accepted from the receiver. The inviting node uses it once to learn that the pairing is mutual.
  - `direct`, the addresses the sender can be dialled on directly. It is sent on every HELLO, so a peer that paired by issuing an invite learns them, and keeps them current when they change.

**Starting numbers.** A session's frame `seq` numbers start at a random point, as TCP picks its initial sequence number. Stream ids start from a random point too (31 bits, counted up in the node's half). A restarted peer therefore never reuses a number the other end still remembers from the process it replaced. Control frames are told apart by their `seq`, so a reused one would be taken for a resend.

**Control frames are reliable.**
- Frames marked "receipt" above MUST be kept by the sender until a CTRL_ACK with their frame `seq` comes back. They are resent every 300 ms.
- A node that gets no receipt for 60 s SHOULD end the session.
- The receiver MUST answer every copy with CTRL_ACK, and MUST act on each `seq` once (a 4096-wide window).

**Streams.**
- Stream ids are `u64`. The node with the lower node id allocates odd ids and the other allocates even ones, so ids never collide.
- An OPEN for an id from the opener's own half, or for an id already pending, MUST be refused with `protocol`.
- A stream carries bytes in both directions.
- Each DATA frame has a per-stream, per-direction `seq` starting at 0.
- The receiver MUST deliver in order. It MAY buffer out-of-order frames, up to 256.
- It acknowledges cumulatively and re-acknowledges duplicates, so a lost ACK is repaired by the resend it causes.
- Unacknowledged data MUST be resent after the route's retransmission timeout (RTO), on another live route if there is one. This is what makes a route failure invisible to the application's stream.
  - A sender SHOULD also resend a frame before its timeout when three acknowledgements in a row repeat the same cumulative point, or when a selective acknowledgement reports a gap ahead of it. Both are loss signals.
  - The RTO is kept per route and adapts to measured round trips, as in RFC 6298. [OVERLAY.md](OVERLAY.md) gives the reference values. A fixed resend interval is not part of this specification.
- DATA for a stream the receiver does not have MUST NOT be acknowledged.

**Flow control.** Every stream starts with a window of 256 KiB in each direction. The receiver grants more with WINDOW as the application reads. A sender with no credit MUST wait. It MUST NOT drop data.

**Routes.**
- Each route is pinged once a second.
- A route is down after three unanswered pings, and up again when an authenticated frame arrives on it.
- Interactive frames SHOULD use the cheapest live route. Bulk frames MAY be striped by measured throughput.
- With no route up, a session SHOULD still use the best route that is not closed.

## 6. Invites

```
invite := "tdov2:" base64url(JSON {version: 2, node_id, name, key_fingerprint, relays, direct, expires_at, nonce, signature})
```

- `node_id` is the inviting node's id (§1). `key_fingerprint` is 64 hex characters: BLAKE3 under the context `"TransferDaemon-overlay-key-fingerprint-v1"`, over the inviting node's 2624-byte hybrid public key. The key itself is not in the invite, which keeps the invite short.
- `nonce` is 32 hex characters. `signature` is 128 hex characters.
- The signature is Ed25519 by the key of `node_id`, checked with strict verification. It covers a BLAKE3 digest of every other field, under the context `"TransferDaemon-overlay-invite-v2"`. Each variable-length field is length-prefixed in the digest.
- An invite's lifetime MUST be between 30 s and 24 h. Its `nonce` is the one-time pairing secret described in §5.
- An invite is a few hundred bytes, short enough for a QR code. A node MUST refuse an invite larger than 4 KB.
- **First contact.** A node dialled from an invite MUST present a hybrid public key that hashes to `key_fingerprint`. The check is made on the direct path and on the relay path, in both directions, before any link is attached. A key that does not match closes the link, and the dialer moves on to the next route. On a relay, a flight that does not match gets no answer, so the dialer's handshake times out.
- **Trust.** The Ed25519 signature is classical, so an invite is only as trustworthy as the channel it arrives on. The fingerprint binds the post-quantum key: a dialled node MUST present the key the invite fingerprinted.
- An invite of version 1 (`tdov1:`) MUST be refused.

## 7. Compatibility and evolution

**Versions.**
- A build speaks a range of protocol versions, from `VERSION_MIN` to `VERSION_CURRENT`. The current range is 1 to 3.
- Two peers use the highest version both speak. A peer outside the range MUST be refused at HELLO with a reason, and MUST NOT be half-understood.
- Raising `VERSION_MIN` is the only way support for an old version ends. It is a decision taken in a release, never a side effect.

**What an older build does with new things:**
- **Unknown frame kinds** are skipped using `len`. A newer build may add kinds. An older build ignores them.
- **Unknown trailing fields** in a body are ignored. The decoder reads what it knows and leaves the rest.

**Adding a field.** bincode cannot fill in a field an older writer did not send, whatever default the reader declares. So a field a newer build *needs* MUST go either:
- behind a version bump (sent only when the agreed version has it); or
- in `HelloExt`, or in a new frame kind.

**Other rules:**
- **Transports** are plug-ins (`LinkTransport`: a scheme, `connect`, and links that send and receive whole frames). A new medium is a new transport. The frames on it do not change.
- **No central servers.** Every relay, address and resolver is configuration. Any conforming relay can be self-hosted, and a node needs nothing else.
- **Persistent state** carries a format version and is migrated on load. A file a build cannot read MUST be preserved (copied aside) before anything is written over it.

## 8. Hole punching

A relayed session can gain a direct UDP route. The nodes agree on the attempt over the session, then probe each other from the socket they registered on the relay with.

**Version.** CANDIDATE exists from protocol version 3 (`VERSION_PUNCH`). It carries a receipt, and an older build would never acknowledge it. A node MUST send it only when the session agreed on version 3 or later, and MUST NOT act on one otherwise. A peer at version 2 gets no punch and keeps its relay route.

**Exchange.** The body of CANDIDATE is a `PunchMsg`:

```
PunchMsg  := {id u64, reply bool, nonce [32], candidates [Candidate]}
Candidate := {addr "host:port", private bool}
```

1. The initiator (the node that dialed) sends `reply = false` with a fresh random `id` and `nonce`, and its candidates: the address the relay saw for its registration socket (`private = false`), and its own address towards the relay when that is not loopback (`private = true`).
2. The responder answers with `reply = true`, the same `id`, its own `nonce` and its own candidates, and starts probing.
3. The initiator starts probing when the answer arrives.

Only paired peers are served. A request SHOULD be accepted at most once in 3 s per peer. When both ends ask at once, the request from the lower node id goes ahead. At most 8 candidates are used.

**Keys.** `material := id (u64 BE) ‖ initiator nonce ‖ responder nonce`.

```
probe key := BLAKE3-derive_key("transferd-overlay-punch-probe-v1", material)
link key  := BLAKE3-derive_key("transferd-overlay-punch-link-v1",  material)
```

The nonces only travel inside the encrypted session, so no one else can derive either key.

**Probes.** Sent from the relay registration socket as plain datagrams. They are not relay payloads.

```
probe := "TDPB" | kind u8 | id u64 BE | seq u32 BE | mac [16]            (33 bytes)
kind  := 1 probe from the initiator   2 probe from the responder
         3 reply from the initiator   4 reply from the responder
mac   := BLAKE3-keyed(probe key, every byte before it)[..16]
```

- A probe is shorter than the smallest tunnel frame, so the two never look alike.
- Each side sends one probe per candidate every 200 ms for 10 rounds, with `seq` the round number.
- A valid probe from the other role, from an address in the peer's candidate list, is answered with a reply that echoes its `seq`. A node SHOULD limit replies to once per 40 ms per address and 64 per attempt. Anything else gets no answer.
- The first valid reply, from a named address and for a round already sent, wins: that address becomes the route.
- An attempt SHOULD keep answering probes for 2 s after it ends.

**The punched route.** Tunnel keys come from the link key exactly as in §2 (the initiator takes the `c2s` direction). Tunnel frames travel as bare datagrams between the two NAT mappings, one frame per datagram, with no relay prefix. The route is added to the session as `holepunch`, marked down until its first PING is answered, and is probed like every other route. A datagram from a punched address that does not open under the route's keys MUST be dropped.

**Failure.** If no reply authenticates, nothing changes: no route is added and the relay route is untouched.

**UDP gateway (local, optional).** A node MAY be configured with a local UDP gateway, a proxy that carries datagrams the node cannot send directly. The node sends every datagram that is not for the relay through it, and receives such datagrams from it, in an envelope:

```
wrapped := "TDGW" | family u8 (4 or 6) | ip octets | port u16 BE | datagram
```

The gateway sends `datagram` on to the address from its own socket, and wraps what comes back with the sender's address. The envelope exists only between a node and its own gateway. It never crosses the network to a peer, so it is not needed for interoperability.
