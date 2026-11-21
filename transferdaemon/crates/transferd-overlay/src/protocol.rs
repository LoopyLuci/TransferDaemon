//! The overlay's wire protocol.
//!
//! # Framing
//!
//! Every overlay message is a self-describing frame so a future peer can be
//! understood (or skipped) by an older one:
//!
//! ```text
//! frame := magic "TDOV" | version u8 | kind u8 | flags u16 | seq u64 | len u32 | body
//! ```
//!
//! * `magic` — `TDOV`; anything else is not ours and is discarded.
//! * `version` — the frame's protocol version (see [`VERSION_MIN`], [`VERSION_CURRENT`]).
//! * `kind` — one byte from [`kind`]. **An unknown kind is skipped, using `len`.** This is
//!   the extension rule: a newer peer may add frame kinds without breaking an older one.
//! * `seq` — a per-session, per-direction counter. It gives replay protection
//!   ([`ReplayWindow`]) and lets a receiver order frames that arrived out of order.
//! * `body` — `len` bytes of bincode, decoded into the struct for `kind`. **New fields must be
//!   appended and marked `#[serde(default)]`**, so an old body still decodes (this is why
//!   `skip_serializing_if` is banned on these types: it silently breaks bincode's layout).
//!
//! # Version negotiation
//!
//! The first frame of a session is [`kind::HELLO`], which advertises the range
//! `[min_version, max_version]`. The responder answers [`kind::HELLO_ACK`] with the single
//! version both sides support, chosen by [`negotiate`]. A session that cannot agree never
//! carries traffic.
//!
//! # Cryptography
//!
//! Session keys come from TransferDaemon's authenticated hybrid handshake
//! (`transferd_crypto::auth_handshake`: X25519 + ML-KEM-768 key exchange, Ed25519 + ML-DSA-87
//! identity). Each link derives a *directional* AES-256-GCM key pair from the handshake secret,
//! so the two directions never share a key, and every frame is authenticated with its `seq` as
//! associated data — so a frame cannot be replayed, reordered or moved between links.

use serde::{Deserialize, Serialize};

/// Frame magic. Anything else on the wire is not an overlay frame.
pub const MAGIC: [u8; 4] = *b"TDOV";

/// The oldest protocol version this build understands.
pub const VERSION_MIN: u16 = 1;

/// The version this build speaks when the peer allows a choice.
pub const VERSION_CURRENT: u16 = 3;

/// The first version that carries [`kind::CANDIDATE`] (the hole-punch coordination). A session
/// that agreed on a lower one never gets the frame: an older build would not acknowledge it.
pub const VERSION_PUNCH: u16 = 3;

/// Bytes before the body: magic(4) version(1) kind(1) flags(2) seq(8) len(4).
pub const HEADER_LEN: usize = 20;

/// Largest body accepted. Keeps a frame inside one UDP datagram on the relay path.
pub const MAX_BODY: usize = 60 * 1024;

/// Frame kinds. Unknown kinds are skipped, never fatal.
pub mod kind {
    pub const HELLO: u8 = 0x01;
    pub const HELLO_ACK: u8 = 0x02;
    /// Open a stream to a service the peer exposes.
    pub const OPEN: u8 = 0x03;
    pub const OPEN_OK: u8 = 0x04;
    pub const OPEN_ERR: u8 = 0x05;
    /// Stream payload.
    pub const DATA: u8 = 0x10;
    /// Cumulative acknowledgement of a stream's data.
    pub const ACK: u8 = 0x11;
    /// Flow-control credit for a stream (bytes the sender may transmit).
    pub const WINDOW: u8 = 0x12;
    pub const CLOSE: u8 = 0x13;
    /// "Your control frame with this `seq` arrived": the receipt that stops its resending.
    pub const CTRL_ACK: u8 = 0x14;
    /// Liveness / RTT probe.
    pub const PING: u8 = 0x20;
    pub const PONG: u8 = 0x21;
    /// Report this node's routes, so the peer knows what it can use.
    pub const ROUTES: u8 = 0x30;
    /// Hole-punch coordination: a `PunchMsg` (version 3 and later).
    pub const CANDIDATE: u8 = 0x40;
    /// Close the session cleanly.
    pub const BYE: u8 = 0x7f;
}

/// Flag bits carried in the frame header.
pub mod flags {
    /// This frame must also go out over every other live link (redundant delivery).
    pub const MIRROR: u16 = 1 << 0;
    /// The body is part of a bulk flow: prefer striping it across links.
    pub const BULK: u16 = 1 << 1;
}

// ---------------------------------------------------------------------------
// Bodies
// ---------------------------------------------------------------------------

/// A service this node offers to paired peers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceInfo {
    /// The service name, as used by `overlay.connect` and `<service>.<node>.td`.
    pub name: String,
    /// A hint for humans and UIs (what the service is), never used for routing.
    #[serde(default)]
    pub description: String,
}

/// The first frame of every session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hello {
    /// Lowest protocol version the sender speaks.
    pub min_version: u16,
    /// Highest protocol version the sender speaks.
    pub max_version: u16,
    /// The sender's node id (hex Ed25519 public key).
    pub node_id: String,
    /// A human-readable name.
    #[serde(default)]
    pub name: String,
    /// Services the sender currently exposes.
    #[serde(default)]
    pub services: Vec<ServiceInfo>,
    /// Opaque extension bytes. A peer that does not understand them ignores them.
    #[serde(default)]
    pub ext: Vec<u8>,
    /// Random value echoed in [`HelloAck`], to bind the answer to this hello.
    pub nonce: [u8; 16],
}

impl Hello {
    /// The version range as a string, for error messages.
    pub fn range(&self) -> String {
        format!("{}-{}", self.min_version, self.max_version)
    }
}

/// What a hello's `ext` carries (bincode). Optional fields only, so an empty `ext` is a valid,
/// empty extension.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HelloExt {
    /// The nonce of an invite this node accepted from the peer: presented once, it tells the
    /// peer that the pairing is mutual.
    #[serde(default)]
    pub pairing: Option<[u8; 16]>,
    /// The addresses the sender can be dialled on directly. Sent on every hello, so a peer that
    /// paired by issuing the invite (and so never saw the other side's invite) learns them, and
    /// keeps them current when they change.
    #[serde(default)]
    pub direct: Vec<String>,
}

/// The extension as nodes before `direct` sent it. bincode is not self-describing, so an older
/// extension has to be read with the older layout.
#[derive(Deserialize)]
struct HelloExtV1 {
    pairing: Option<[u8; 16]>,
}

impl HelloExt {
    /// Decode an `ext`, treating anything unreadable as empty (an extension is never fatal).
    /// Older nodes send only `pairing`; newer fields after it are ignored by them (bincode reads
    /// a prefix), and read here when present.
    pub fn decode(ext: &[u8]) -> Self {
        if ext.is_empty() {
            return Self::default();
        }
        bincode::deserialize::<HelloExt>(ext)
            .or_else(|_| {
                bincode::deserialize::<HelloExtV1>(ext).map(|v1| HelloExt {
                    pairing: v1.pairing,
                    direct: Vec::new(),
                })
            })
            .unwrap_or_default()
    }
}

/// The responder's answer: the single agreed version, or a refusal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloAck {
    /// The agreed version, or `0` when the responder refuses (see `reason`).
    pub version: u16,
    /// The responder's node id.
    pub node_id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub services: Vec<ServiceInfo>,
    /// Echo of [`Hello::nonce`], so the initiator knows the answer is not replayed.
    pub nonce: [u8; 16],
    /// Why the session was refused (empty on success).
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub ext: Vec<u8>,
}

/// Ask the peer for a stream to one of its services.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Open {
    /// Stream id chosen by the initiator.
    pub stream: u64,
    /// The service name to reach.
    pub service: String,
    /// The initiator's node id (redundant with the session, checked against it).
    #[serde(default)]
    pub node_id: String,
}

/// The peer accepted the stream; `remote` is the address it will talk to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenOk {
    pub stream: u64,
    /// Which link kind the peer will use for this stream (a hint, not a promise).
    #[serde(default)]
    pub route: String,
}

/// The peer refused the stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenErr {
    pub stream: u64,
    /// An [`OverlayError::code`](crate::error::OverlayError::code).
    pub code: String,
    pub reason: String,
}

/// Stream payload. `seq` is per stream, so a receiver can drop duplicates and reorder.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Data {
    pub stream: u64,
    pub seq: u64,
    #[serde(default)]
    pub fin: bool,
    pub payload: Vec<u8>,
}

/// Cumulative acknowledgement: everything up to `seq` was received, plus which frames beyond
/// the first gap have arrived.
///
/// The `sack` list trails the body, so a build that only knows [`AckBase`] reads the first two
/// fields and ignores the rest, and a build that knows this one reads an `AckBase` (no ranges)
/// from an older peer: see [`Ack::parse`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ack {
    pub stream: u64,
    /// Cumulative: every frame of the stream below `seq` has arrived (the receiver's next
    /// expected sequence number). Not the sequence number of the frame that triggered it, so a
    /// frame lost before it is still resent.
    pub seq: u64,
    /// Ranges `[from, to)` of frames beyond `seq` that have arrived, lowest first.
    #[serde(default)]
    pub sack: Vec<(u64, u64)>,
}

/// An acknowledgement as older builds send it: the cumulative part only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AckBase {
    pub stream: u64,
    pub seq: u64,
}

impl Ack {
    /// Read an acknowledgement from either generation of sender.
    pub fn parse(frame: &Frame) -> Option<Ack> {
        frame.decode::<Ack>().ok().or_else(|| {
            frame.decode::<AckBase>().ok().map(|a| Ack {
                stream: a.stream,
                seq: a.seq,
                sack: Vec::new(),
            })
        })
    }
}

/// The receipt for one control frame (see [`is_reliable`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtrlAck {
    /// The frame header `seq` of the control frame that arrived.
    pub seq: u64,
}

/// Control frames whose loss would leave a stream or a session stuck: they are resent until
/// the peer sends a [`kind::CTRL_ACK`] for them, and a receiver acts on each one once (by its
/// frame `seq`). Data has its own acknowledgements; pings and route reports are best effort.
pub fn is_reliable(kind: u8) -> bool {
    matches!(
        kind,
        kind::HELLO
            | kind::HELLO_ACK
            | kind::OPEN
            | kind::OPEN_OK
            | kind::OPEN_ERR
            | kind::WINDOW
            | kind::CLOSE
            | kind::CANDIDATE
    )
}

/// Flow-control credit: the sender may transmit up to `credit` bytes past what it has sent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Window {
    pub stream: u64,
    pub credit: u64,
}

/// Either side may close a stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Close {
    pub stream: u64,
    pub code: String,
    #[serde(default)]
    pub reason: String,
}

/// A liveness probe. The peer answers with [`Pong`] carrying the same nonce.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ping {
    pub nonce: u64,
    /// Sender's monotonic microseconds, so the answer can measure the round trip.
    pub sent_us: u64,
}

/// The answer to a [`Ping`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pong {
    pub nonce: u64,
    /// Echo of [`Ping::sent_us`].
    pub sent_us: u64,
}

/// One measured route, reported to the peer so it can pick the better side.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteReport {
    pub kind: String,
    pub rtt_ms: f64,
    pub loss: f64,
    pub mbps: f64,
    pub active: bool,
    /// The congestion window in bytes, and the bytes in flight against it.
    #[serde(default)]
    pub cwnd: u64,
    #[serde(default)]
    pub in_flight: u64,
    /// The smoothed round trip of this route's data, and the retransmission timeout it implies.
    #[serde(default)]
    pub srtt_ms: f64,
    #[serde(default)]
    pub rto_ms: f64,
    /// Payload bytes sent on this route, and how many of them were resends.
    #[serde(default)]
    pub sent_bytes: u64,
    #[serde(default)]
    pub retx_bytes: u64,
}

/// All of this node's routes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Routes {
    pub routes: Vec<RouteReport>,
}

/// One side of a hole-punch exchange, carried by [`kind::CANDIDATE`] (reliable, and sent only
/// when the session agreed on [`VERSION_PUNCH`] or later).
///
/// The initiator sends `reply: false` with its candidates and a fresh `nonce`; the responder
/// answers with `reply: true`, the same `id`, its own `nonce` and its own candidates. Both
/// nonces travel inside the encrypted session, so only the two nodes know the probe key
/// derived from them (see `punch.rs`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PunchMsg {
    /// Chosen by the initiator; ties a reply (and every probe) to one attempt.
    pub id: u64,
    /// False for the request, true for the answer.
    pub reply: bool,
    /// The sender's secret contribution to the probe key.
    pub nonce: [u8; 32],
    /// Where the sender may be reached from outside its NAT, and on its own network.
    pub candidates: Vec<Candidate>,
}

/// A NAT candidate for a hole punch: where to send punch packets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Candidate {
    /// A `host:port` the peer may reach us on.
    pub addr: String,
    /// True when `addr` is a private address we learned ourselves.
    #[serde(default)]
    pub private: bool,
}

// ---------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------

/// One framed overlay message: header fields plus an encoded body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub version: u8,
    pub kind: u8,
    pub flags: u16,
    pub seq: u64,
    pub body: Vec<u8>,
}

impl Frame {
    /// Build a frame with an empty body (for kinds that carry one in the header).
    pub fn bare(version: u8, kind: u8, seq: u64) -> Self {
        Self {
            version,
            kind,
            flags: 0,
            seq,
            body: Vec::new(),
        }
    }

    /// Build a frame carrying a bincode body.
    pub fn new<T: Serialize>(
        version: u8,
        kind: u8,
        seq: u64,
        value: &T,
    ) -> Result<Self, bincode::Error> {
        Ok(Self {
            version,
            kind,
            flags: 0,
            seq,
            body: bincode::serialize(value)?,
        })
    }

    /// Decode the body.
    pub fn decode<T: for<'de> Deserialize<'de>>(&self) -> Result<T, bincode::Error> {
        bincode::deserialize(&self.body)
    }

    /// Mark the frame for redundant delivery over every live link.
    pub fn mirrored(mut self) -> Self {
        self.flags |= flags::MIRROR;
        self
    }

    /// Mark the frame as belonging to a bulk flow (striping candidate).
    pub fn bulk(mut self) -> Self {
        self.flags |= flags::BULK;
        self
    }

    /// True when the frame should also go out over the other links.
    pub fn is_mirrored(&self) -> bool {
        self.flags & flags::MIRROR != 0
    }

    /// True when the frame belongs to a bulk flow.
    pub fn is_bulk(&self) -> bool {
        self.flags & flags::BULK != 0
    }

    /// Serialize to the wire.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.body.len());
        out.extend_from_slice(&MAGIC);
        out.push(self.version);
        out.push(self.kind);
        out.extend_from_slice(&self.flags.to_le_bytes());
        out.extend_from_slice(&self.seq.to_le_bytes());
        out.extend_from_slice(&(self.body.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.body);
        out
    }
}

/// Why a frame could not be read.
#[derive(Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// Not enough bytes yet (the caller should read more and retry).
    Incomplete,
    /// Not an overlay frame at all.
    NotOurs,
    /// The frame declares a body longer than we accept.
    TooLarge(usize),
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Incomplete => write!(f, "incomplete frame"),
            Self::NotOurs => write!(f, "not a TransferDaemon overlay frame"),
            Self::TooLarge(n) => write!(f, "frame body of {n} bytes is over the limit"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Read one frame from the front of `buf`.
///
/// Returns the frame and how many bytes it consumed. `DecodeError::Incomplete` means the
/// buffer does not hold a whole frame yet.
pub fn decode(buf: &[u8]) -> Result<(Frame, usize), DecodeError> {
    if buf.len() < HEADER_LEN {
        return Err(DecodeError::Incomplete);
    }
    if buf[..4] != MAGIC {
        return Err(DecodeError::NotOurs);
    }
    let len = u32::from_le_bytes(buf[16..20].try_into().expect("4 bytes")) as usize;
    if len > MAX_BODY {
        return Err(DecodeError::TooLarge(len));
    }
    if buf.len() < HEADER_LEN + len {
        return Err(DecodeError::Incomplete);
    }
    let frame = Frame {
        version: buf[4],
        kind: buf[5],
        flags: u16::from_le_bytes(buf[6..8].try_into().expect("2 bytes")),
        seq: u64::from_le_bytes(buf[8..16].try_into().expect("8 bytes")),
        body: buf[HEADER_LEN..HEADER_LEN + len].to_vec(),
    };
    Ok((frame, HEADER_LEN + len))
}

/// Pick the version both peers speak, or `None` when the ranges do not overlap.
///
/// Policy: the highest version the responder supports that is also within the
/// initiator's range, but never below the responder's own minimum.
pub fn negotiate(peer_min: u16, peer_max: u16, our_min: u16, our_max: u16) -> Option<u16> {
    let hi = peer_max.min(our_max);
    let lo = peer_min.max(our_min);
    (lo <= hi).then_some(hi)
}

// ---------------------------------------------------------------------------
// Replay protection
// ---------------------------------------------------------------------------

/// A sliding replay window over a per-direction frame counter.
///
/// The sender increments `seq` for every frame; the receiver accepts anything above
/// `highest` and anything inside the window it has not seen. A replayed or reordered
/// frame outside the window is refused, so an attacker cannot re-inject an old frame even
/// if they can copy ciphertext off the wire.
#[derive(Debug)]
pub struct ReplayWindow {
    highest: Option<u64>,
    /// Bit `i` set = frame `highest - i` was already accepted.
    seen: u64,
    /// How far below `highest` a frame may still be accepted.
    span: u64,
}

impl ReplayWindow {
    /// A window that accepts the last `span` sequence numbers, at most 64 (one `u64` of bits).
    pub fn new(span: u64) -> Self {
        Self {
            highest: None,
            seen: 0,
            span: span.max(1),
        }
    }

    /// Accept `seq`, or refuse it as a replay.
    pub fn accept(&mut self, seq: u64) -> bool {
        let Some(highest) = self.highest else {
            self.highest = Some(seq);
            self.seen = 1; // the new highest counts as seen
            return true;
        };
        if seq > highest {
            let shift = seq - highest;
            self.seen = if shift >= 64 {
                1
            } else {
                (self.seen << shift) | 1
            };
            self.highest = Some(seq);
            return true;
        }
        let back = highest - seq;
        if back >= self.span || back >= 64 {
            return false; // too old to be inside the window
        }
        let bit = 1u64 << back;
        if self.seen & bit != 0 {
            return false; // already accepted: a replay
        }
        self.seen |= bit;
        true
    }

    /// The highest sequence number accepted so far.
    pub fn highest(&self) -> Option<u64> {
        self.highest
    }
}

/// Whether this build knows what to do with a frame kind.
///
/// The extension rule: a kind this build does not know is **skipped**, using the frame's
/// length, so a newer peer may add frame kinds without breaking an older one.
pub fn is_known_kind(kind: u8) -> bool {
    matches!(
        kind,
        kind::HELLO
            | kind::HELLO_ACK
            | kind::OPEN
            | kind::OPEN_OK
            | kind::OPEN_ERR
            | kind::DATA
            | kind::ACK
            | kind::WINDOW
            | kind::CLOSE
            | kind::CTRL_ACK
            | kind::PING
            | kind::PONG
            | kind::ROUTES
            | kind::CANDIDATE
            | kind::BYE
    )
}

// ---------------------------------------------------------------------------
// Buffering
// ---------------------------------------------------------------------------

/// Reassembles frames from a byte stream, dropping what it cannot use.
#[derive(Debug, Default)]
pub struct FrameReader {
    buf: Vec<u8>,
}

impl FrameReader {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed bytes and take every whole frame whose kind this build understands.
    ///
    /// A frame of an unknown kind is **skipped**, not an error: that is the extension rule, and
    /// it is enforced here so no caller has to remember it. A frame that is not ours, or whose
    /// declared length is impossible, drops the buffer: the link is unusable.
    pub fn push(&mut self, bytes: &[u8]) -> Vec<Frame> {
        self.buf.extend_from_slice(bytes);
        let mut out = Vec::new();
        loop {
            match decode(&self.buf) {
                Ok((frame, used)) => {
                    self.buf.drain(..used);
                    if is_known_kind(frame.kind) {
                        out.push(frame);
                    }
                }
                Err(DecodeError::Incomplete) => break,
                Err(DecodeError::TooLarge(_)) | Err(DecodeError::NotOurs) => {
                    self.buf.clear();
                    break;
                }
            }
        }
        out
    }

    /// Bytes buffered but not yet part of a frame.
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_frame_round_trips_through_the_wire_format() {
        let hello = Hello {
            min_version: 1,
            max_version: 2,
            node_id: "aa".repeat(32),
            name: "laptop".into(),
            services: vec![ServiceInfo {
                name: "http".into(),
                description: "web".into(),
            }],
            ext: b"future".to_vec(),
            nonce: [7; 16],
        };
        let frame = Frame::new(2, kind::HELLO, 42, &hello).expect("encode");
        let wire = frame.encode();
        let (back, used) = decode(&wire).expect("decode");
        assert_eq!(used, wire.len());
        assert_eq!(back, frame);
        let back: Hello = back.decode().expect("body");
        assert_eq!(back.node_id, hello.node_id);
        assert_eq!(back.ext, hello.ext);
    }

    #[test]
    fn frames_are_split_across_reads() {
        let frame = Frame::new(
            2,
            kind::PING,
            1,
            &Ping {
                nonce: 5,
                sent_us: 9,
            },
        )
        .expect("encode");
        let wire = frame.encode();
        let mut reader = FrameReader::new();
        assert!(reader.push(&wire[..7]).is_empty());
        assert!(reader.push(&wire[7..HEADER_LEN + 3]).is_empty());
        let got = reader.push(&wire[HEADER_LEN + 3..]);
        assert_eq!(got, vec![frame]);
        assert_eq!(reader.buffered(), 0);
    }

    #[test]
    fn an_unknown_frame_kind_is_skipped_not_fatal() {
        let known = Frame::new(
            2,
            kind::PING,
            1,
            &Ping {
                nonce: 1,
                sent_us: 1,
            },
        )
        .expect("encode");
        let future = Frame::new(3, 0xEE, 2, &vec![1u8, 2, 3]).expect("encode");
        let mut wire = future.encode();
        wire.extend_from_slice(&known.encode());

        let mut reader = FrameReader::new();
        let got = reader.push(&wire);
        assert_eq!(
            got,
            vec![known],
            "the unknown kind is skipped, the frame after it survives"
        );
    }

    #[test]
    fn a_new_field_at_the_end_still_decodes_for_an_old_reader() {
        // What a v1 peer wrote: no `ext`, no `services`.
        let old = bincode::serialize(&Hello {
            min_version: 1,
            max_version: 1,
            node_id: "bb".repeat(32),
            name: String::new(),
            services: Vec::new(),
            ext: Vec::new(),
            nonce: [1; 16],
        })
        .expect("encode");
        // What a v2 peer writes: the same frame plus the fields appended after `name`.
        #[derive(Serialize)]
        struct NewHello {
            min_version: u16,
            max_version: u16,
            node_id: String,
            name: String,
            services: Vec<ServiceInfo>,
            ext: Vec<u8>,
            nonce: [u8; 16],
        }
        let new = bincode::serialize(&NewHello {
            min_version: 2,
            max_version: 2,
            node_id: "bb".repeat(32),
            name: "phone".into(),
            services: vec![ServiceInfo {
                name: "ssh".into(),
                description: String::new(),
            }],
            ext: b"x".to_vec(),
            nonce: [1; 16],
        })
        .expect("encode");
        let back: Hello = bincode::deserialize(&new).expect("a defaulted tail decodes");
        assert_eq!(back.name, "phone");
        assert_eq!(back.services.len(), 1);
        // And the old body still decodes (the tail is simply absent).
        let back: Hello = bincode::deserialize(&old).expect("old body decodes");
        assert!(back.services.is_empty());
        assert!(back.ext.is_empty());
    }

    #[test]
    fn version_negotiation_picks_the_highest_common_version() {
        // A peer that only speaks v1: we drop to v1.
        assert_eq!(negotiate(1, 1, VERSION_MIN, VERSION_CURRENT), Some(1));
        // A future peer that speaks 2..9: we take our maximum.
        assert_eq!(
            negotiate(2, 9, VERSION_MIN, VERSION_CURRENT),
            Some(VERSION_CURRENT)
        );
        // A peer that stops at 2 (before hole punching): we agree on 2, and never send it a punch frame.
        assert_eq!(negotiate(1, 2, VERSION_MIN, VERSION_CURRENT), Some(2));
        // A peer far in the future, with nothing we speak: refused.
        assert_eq!(negotiate(9, 12, VERSION_MIN, VERSION_CURRENT), None);
        // A peer that only speaks v0 (pre-history): refused.
        assert_eq!(negotiate(0, 0, VERSION_MIN, VERSION_CURRENT), None);
    }

    #[test]
    fn the_replay_window_refuses_a_replayed_frame() {
        let mut w = ReplayWindow::new(64);
        assert!(w.accept(0));
        assert!(!w.accept(0), "the same seq twice is a replay");
        assert!(w.accept(1));
        assert!(w.accept(5));
        assert!(w.accept(4), "a gap inside the window fills in");
        assert!(!w.accept(5), "and is then a replay");
        assert!(w.accept(3), "3 was never accepted");
        assert!(!w.accept(3));
        assert_eq!(w.highest(), Some(5));
    }

    #[test]
    fn the_replay_window_tolerates_reordering_inside_the_window() {
        let mut w = ReplayWindow::new(64);
        assert!(w.accept(10), "seq 10 is inside the window");
        assert!(w.accept(12));
        assert!(w.accept(11), "11 arrived late but inside the window");
        assert!(w.accept(9));
        for s in [12, 11, 10, 9] {
            assert!(!w.accept(s), "seq {s} is now a replay");
        }
    }

    #[test]
    fn a_sequence_far_below_the_window_is_refused() {
        let mut w = ReplayWindow::new(64);
        for s in 0..1000u64 {
            assert!(w.accept(s));
        }
        // The window only reaches 64 frames back, so anything older is refused outright —
        // even though its ciphertext would still authenticate.
        assert!(!w.accept(900), "900 is more than a window behind 999");
        assert!(!w.accept(999), "and the newest is a replay");
    }

    #[test]
    fn an_oversized_frame_is_refused_without_allocating_it() {
        let mut wire = MAGIC.to_vec();
        wire.extend_from_slice(&[2, kind::DATA]);
        wire.extend_from_slice(&0u16.to_le_bytes());
        wire.extend_from_slice(&1u64.to_le_bytes());
        wire.extend_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(decode(&wire), Err(DecodeError::TooLarge(u32::MAX as usize)));
    }

    #[test]
    fn hello_ext_carries_direct_and_reads_the_older_layout() {
        let pairing = Some([7u8; 16]);
        let new = bincode::serialize(&HelloExt { pairing, direct: vec!["192.168.1.5:7801".into()] }).unwrap();
        let got = HelloExt::decode(&new);
        assert_eq!(got.pairing, pairing);
        assert_eq!(got.direct, vec!["192.168.1.5:7801".to_string()]);

        #[derive(Serialize, Deserialize)]
        struct Old {
            pairing: Option<[u8; 16]>,
        }
        // What an older node sends: read without losing the pairing nonce.
        let old = bincode::serialize(&Old { pairing }).unwrap();
        let got = HelloExt::decode(&old);
        assert_eq!(got.pairing, pairing);
        assert!(got.direct.is_empty());
        // What an older node reads from a newer one: its prefix, the pairing nonce.
        let read: Old = bincode::deserialize(&new).unwrap();
        assert_eq!(read.pairing, pairing);
    }
}
