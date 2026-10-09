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
| 0x40 | CANDIDATE | an address for a hole punch (reserved; see OVERLAY.md) | no |
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
- A build speaks a range of protocol versions, from `VERSION_MIN` to `VERSION_CURRENT` (today 1 to 2).
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
