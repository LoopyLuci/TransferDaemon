# The overlay wire protocol

This is the wire format of `transferd-overlay`, from the bytes up. It covers:

- what a node may send;
- what it must accept;
- how two builds of different ages keep talking.

OVERLAY.md describes what the overlay does with it.

```
 application stream bytes
 ── frames ─────────────  session: hello, streams (open / data / ack / window / close), pings, receipts
 ── tunnel ─────────────  per link: AES-256-GCM, a counter, a replay window
 ── link ───────────────  TCP (direct), relay datagrams, or any LinkTransport
```

## 1. Identity and the handshake

**Identity.**
- A node's identity is TransferDaemon's hybrid signing key: Ed25519 and ML-DSA-87.
- Its **node id** is the hex of the 32-byte Ed25519 public key: 64 lowercase hex characters.
- A node keeps one identity for its whole life. It is derived from a stored 64-byte seed.

**Handshake.** Every link starts with TransferDaemon's authenticated hybrid handshake, `transferd_crypto::auth_handshake`,
protocol version 2:

| Flight | Contents |
|---|---|
| initiator (8568 bytes) | tag `0x11`, protocol version, ciphersuite, X25519 public key, ML-KEM-768 encapsulation key, the 2624-byte hybrid identity key, a BLAKE3 transcript of all of it, and an Ed25519 + ML-DSA-87 signature over the transcript |
| responder (8472 bytes) | tag `0x12`, the same layout with the ML-KEM ciphertext in place of the encapsulation key |

- Both flights are verified. The dialler also checks that the responder's Ed25519 key is the node id it dialled.
- The shared secret is BLAKE3 over the X25519 and ML-KEM shared secrets. Breaking it needs both a classical and a
  post-quantum break.
- Ciphersuites are identified by a `u16`: `0x0002` = X25519 + ML-KEM-768 with Ed25519 + ML-DSA-87. A new suite is a new
  identifier, offered and verified the same way. That is the crypto-agility rule: an algorithm is never changed under an
  existing identifier.

**Over a direct TCP link**, each flight is sent as `len u32 BE ‖ bytes`.

**Over a relay** they are relay payloads (§3): prefix `0x01` for the initiator flight and `0x03` for the responder's.
- The initiator resends its flight every 0.9 s until it is answered, or 5 s pass.
- A responder that receives a flight it already answered (same bytes) sends the same answer again. It never derives a
  second key for it.

## 2. The tunnel (per link)

From the shared secret each side derives two directional keys:

```
k_c2s = BLAKE3-derive_key("TransferDaemon-overlay-c2s-v1", secret)    initiator -> responder
k_s2c = BLAKE3-derive_key("TransferDaemon-overlay-s2c-v1", secret)    responder -> initiator
```

A tunnel frame:

```
tunnel_frame := len u32 BE | counter u64 BE | AES-256-GCM(key, nonce, plaintext, aad = len ‖ counter)
nonce        := key[0..4] ‖ counter u64 BE
```

- **The counter** starts at 0 and goes up by one for every frame sealed with that key, so no (key, nonce) pair is ever
  reused.
- **The length and the counter** are authenticated: a frame cannot be cut, extended or moved.
- **Replay window.** The receiver keeps a window over the counter, 4096 wide in the style of RFC 4303. A counter it
  already accepted, or one older than the window, is dropped.
- **Order of checks.** The window is checked only after the frame authenticates, so a forged counter cannot move it.
- **Several links per peer.** Links of one session deliver in their own order, and the window absorbs that.

The plaintext of a tunnel frame is one or more overlay frames (§4).

## 3. Relay encapsulation

The relay is `relayd`'s blind relay:
- A node registers a 32-byte token, `BLAKE3-derive_key("transferd-overlay-relay-token-v1", node_id)`, with proof of
  work.
- A node sends `Forward{token, ciphertext}` to reach a token.
- The relay never sees more than the token and the padded ciphertext.

Inside `ciphertext`:

```
payload := len u32 LE | prefix u8 | sender_token [32] | body ,  zero-padded to a power of two (>= 64 bytes)
prefix  := 0x01 initiator flight | 0x03 responder flight | 0x02 a sealed tunnel frame
```

- **Padding** puts every payload on a size grid. The relay learns sizes only to within a factor of two.
- **Several links per peer.** A node may hold several links to one peer through one relay (each side dialled, or a
  route added later), up to four. A `0x02` payload carries no link id. It is delivered to the link whose keys
  authenticate it.
- **Early payloads.** A payload that arrives before its link is registered is held briefly, up to 64 per peer.

**Registration and `Locate`.**
- Registration is renewed every 30 s. A registration or keepalive must carry a sequence number newer than the last one
  the relay saw for that token. A client starts its sequence from the clock, so a restarted node is not refused.
- `Locate` (tag `0x08`, relayd's protocol) asks the relay which address it sees for the asker and for another token. It
  is answered only for a token registered from the asking address.

## 4. Frames

```
frame := magic "TDOV" | version u8 | kind u8 | flags u16 LE | seq u64 LE | len u32 LE | body[len]
```

- **`version`**: the frame's protocol version.
- **`seq`**: counts every frame a session sends in one direction. It identifies control frames for their receipts
  (§5).
- **`flags`**: `0x1` MIRROR (sent on every route, used for resends) and `0x2` BULK (may be striped across routes).
- **`body`**: bincode, with the struct named by `kind`. `len` is at most 60 KiB.

| kind | name | body | receipt |
|---|---|---|---|
| 0x01 | HELLO | `{min_version, max_version, node_id, name, services, ext, nonce}` | yes |
| 0x02 | HELLO_ACK | `{version, node_id, name, services, nonce, reason, ext}` | yes |
| 0x03 | OPEN | `{stream, service, node_id}` | yes |
| 0x04 | OPEN_OK | `{stream, route}` | yes |
| 0x05 | OPEN_ERR | `{stream, code, reason}` (`no_such_service`, `denied`, `rate_limited`, `protocol`) | yes |
| 0x10 | DATA | `{stream, seq, fin, payload}` | via ACK |
| 0x11 | ACK | `{stream, seq}`: every DATA frame of the stream below `seq` has arrived | no |
| 0x12 | WINDOW | `{stream, credit}`: the sender may send `credit` more bytes | yes |
| 0x13 | CLOSE | `{stream, code, reason}` | yes |
| 0x14 | CTRL_ACK | `{seq}`: the control frame with this frame `seq` arrived | no |
| 0x20 | PING | `{nonce, sent_us}` | no |
| 0x21 | PONG | `{nonce, sent_us}`, sent on the route the PING came in on | no |
| 0x30 | ROUTES | the sender's route measurements, informational | no |
| 0x40 | CANDIDATE | `{id, reply, nonce, candidates}`: one side of a hole-punch exchange (§8); version 3 and later | yes |
| 0x7f | BYE | — | no |

## 5. The session

**Hello.**
- Each side sends HELLO first, with the version range it speaks and the services it exposes.
- On a peer's HELLO, a node checks the claimed `node_id` against the identity the handshake proved, and answers
  HELLO_ACK. That answer carries `negotiate(...)`: the highest version in both ranges, or 0 and a `reason` when there
  is none.
- A session carries streams once either side has the agreed version.
- A node sends HELLO again whenever the services it exposes change. The peer replaces its list.

**`ext` (HELLO and HELLO_ACK).**
- A bincode `HelloExt` with optional fields only; an empty or unreadable `ext` is an empty extension.
- Today: `pairing`, the nonce of an invite the sender accepted from the receiver. The inviting node uses it once to
  learn that the pairing is mutual.

**Control frames are reliable.**
- The kinds marked "receipt" above are kept by the sender until a CTRL_ACK with their frame `seq` comes back. They are
  resent every 300 ms.
- A node that gets no receipt for 60 s ends the session.
- The receiver answers every copy with CTRL_ACK, and acts on each `seq` once (a 4096-wide window).

**Streams.**
- Stream ids are `u64`. The node with the lower node id allocates odd ids, the other even ones, so ids never collide.
- An OPEN for an id from the opener's own half, or for one already pending, is refused with `protocol`.
- A stream carries bytes both ways.
- Each DATA frame has a per-stream, per-direction `seq` from 0.
- The receiver delivers in order and buffers out-of-order frames, up to 256.
- It acknowledges cumulatively, re-acknowledging duplicates, so a lost ACK is repaired by the resend it causes.
- Unacknowledged data is resent after 400 ms on another live route if there is one. This is what makes a route
  failure invisible to the application's stream.
- DATA for a stream the receiver does not have is not acknowledged.

**Flow control.** Every stream starts with a window of 256 KiB in each direction. The receiver grants more with WINDOW
as the application reads. A sender with no credit waits; it never drops data.

**Routes.**
- Each route is pinged once a second.
- A route is down after three unanswered pings, and up again when an authenticated frame arrives on it.
- Interactive frames go on the cheapest live route. Bulk frames may be striped by measured throughput.
- With no route up, a session still uses the best route that is not closed.

## 6. Invites

```
invite := "tdov1:" base64url(JSON {version: 1, node_id, name, hybrid_public_key, relays, direct, expires_at, nonce, signature})
```

- The signature (Ed25519 + ML-DSA-87) covers a BLAKE3 hash of every other field, under the context
  `"TransferDaemon-overlay-invite-v1"`.
- An invite lives 30 s to 24 h.
- Its `nonce` is the one-time pairing secret described in §5.

## 7. Compatibility and evolution

**Versions.**
- A build speaks a range of protocol versions, from `VERSION_MIN` to `VERSION_CURRENT` (today 1 to 3).
- Two peers use the highest version both speak. A peer outside the range is refused at HELLO with a reason, never
  half-understood.
- **Raising `VERSION_MIN`** is the only way support for an old version ends. It is a decision taken in a release, never
  a side effect.

**What an older build does with new things:**
- **Unknown frame kinds** are skipped using `len`. A newer build may add kinds; an older one ignores them.
- **Unknown fields** at the end of a body are ignored: bincode reads what it knows and leaves the rest.

**Adding a field.** bincode cannot fill in a field an older writer did not send, whatever `#[serde(default)]` says.
So a field a newer build *needs* goes either:
- behind a version bump (sent only when the agreed version has it); or
- in `HelloExt`, or a new frame kind.

**Other rules:**
- **Transports** are plug-ins (`LinkTransport`: a scheme, `connect`, links that send and receive whole frames). A new
  medium is a new transport. The frames on it do not change.
- **No central servers.** Every relay, address and resolver is configuration. `relayd` is self-hostable, and a node
  needs nothing else.
- **Stored state** (`state.json`) carries a format version and is migrated on load. A file a build cannot read is copied
  aside (`state.json.unreadable`) before anything is saved over it.
- **Tests.** The tests include a current peer talking to an older one (`max_version = 1`) and to a newer one, each
  agreeing on the highest common version.

## 8. Hole punching

A relayed session can gain a direct UDP route. The nodes agree on the attempt over the session, then probe each other
from the socket they registered on the relay with.

**Version.** CANDIDATE exists from protocol version 3 (`VERSION_PUNCH`). It is reliable (it carries a receipt), and an
older build would never acknowledge it, so a node sends it only when the session agreed on version 3 or later. A node
that agreed on less never acts on one either. A peer at version 2 simply gets no punch and keeps its relay route.

**Exchange.** The body of CANDIDATE is a `PunchMsg`:

```
PunchMsg  := {id u64, reply bool, nonce [32], candidates [Candidate]}
Candidate := {addr "host:port", private bool}
```

1. The initiator (the node that dialled) sends `reply = false` with a fresh random `id` and `nonce`, and its candidates:
   the address the relay saw for its registration socket (`private = false`), and its own address towards the relay when
   that is not loopback (`private = true`).
2. The responder answers `reply = true` with the same `id`, its own `nonce` and its own candidates, and starts probing.
3. The initiator starts probing when the answer arrives.

Only paired peers are served. A request is accepted at most once in 3 s per peer. When both ends ask at once, the lower
node id's request goes ahead. At most 8 candidates are used.

**Keys.** `material := id (u64 BE) ‖ initiator nonce ‖ responder nonce`.

```
probe key := BLAKE3-derive_key("transferd-overlay-punch-probe-v1", material)
link key  := BLAKE3-derive_key("transferd-overlay-punch-link-v1",  material)
```

The nonces only travel inside the encrypted session, so nobody else can derive either key.

**Probes.** Sent from the relay registration socket as plain datagrams (they are not relay payloads):

```
probe := "TDPB" | kind u8 | id u64 BE | seq u32 BE | mac [16]            (33 bytes)
kind  := 1 probe from the initiator   2 probe from the responder
         3 reply from the initiator   4 reply from the responder
mac   := BLAKE3-keyed(probe key, every byte before it)[..16]
```

- A probe is shorter than the smallest tunnel frame, so the two never look alike.
- Each side sends one probe per candidate every 200 ms for 10 rounds, with `seq` the round number.
- A valid probe from the other role, from an address in the peer's candidate list, is answered with a reply that echoes
  its `seq` (at most once per 40 ms per address and 64 per attempt). Anything else gets no answer.
- The first valid reply, from a named address and for a round already sent, wins: that address becomes the route.
- An attempt keeps answering probes for 2 s after it ends.

**The punched route.** Tunnel keys come from the link key exactly as in §2 (the initiator takes the `c2s` direction).
Tunnel frames travel as bare datagrams between the two NAT mappings, one frame per datagram, with no relay prefix. The
route is added to the session as `holepunch`, marked down until its first PING is answered, and is probed like every
other route. A datagram from a punched address that does not open under the route's keys is dropped.

**Failure.** If no reply authenticates, nothing changes: no route is added and the relay route is untouched.

**UDP gateway (optional).** A node configured with a gateway sends every datagram that is not for the relay through it,
and receives such datagrams from it, in an envelope: `"TDGW" | family u8 (4 or 6) | ip octets | port u16 BE | datagram`.
The gateway sends `datagram` on to the address from its own socket, and wraps what comes back with the sender's address.
It exists for nodes behind a UDP-aware proxy, and for tests that put a NAT emulator in front of a node on loopback.
