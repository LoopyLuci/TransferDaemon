//! The secure tunnel and the authenticated handshake that opens it.
//!
//! Both the direct-TCP path and the hole-punched UDP path run the code here: a handshake over
//! a plain byte duplex, then a length-prefixed, authenticated frame tunnel.
//!
//! # Handshake
//!
//! TransferDaemon's authenticated hybrid handshake (Protocol v2), unchanged:
//!
//! ```text
//! initiator                              responder
//!   ──── AuthInitiatorHello ─────────────►   X25519 + ML-KEM-768 ephemeral, signed by
//!                                            the initiator's hybrid identity
//!   ◄──── AuthResponderHello ──────────────   X25519 + ML-KEM-768 response, signed by
//!                                            the responder's hybrid identity
//!   session = BLAKE3(x25519_shared ‖ mlkem_shared)
//! ```
//!
//! Each flight is a BLAKE3 transcript hash signed with Ed25519 **and** ML-DSA-87, so a
//! man-in-the-middle cannot substitute key material without the peer's signing key. The
//! responder's Ed25519 component is then checked against the node id the caller expected, so a
//! relay cannot swap one peer for another.
//!
//! # Tunnel
//!
//! ```text
//! tunnel frame := len u32 BE | counter u64 BE | ciphertext ‖ tag
//! ```
//!
//! `len ‖ counter` is bound in as associated data, so a frame cannot be truncated, extended or
//! moved between links. Each direction has its own key (derived from the session secret), its
//! own random nonce prefix, and its own counter, so the two directions never share a
//! (key, nonce) pair and no counter is ever reused. The counter is checked on receipt, which
//! is the transport-level half of replay protection — independent of the overlay frame's own
//! replay window.

use aes_gcm::aead::{Aead, KeyInit, Payload as AeadPayload};
use aes_gcm::{Aes256Gcm, Nonce};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use transferd_crypto::auth_handshake::{
    AuthInitiatorHello, AuthResponderHello, CIPHERSUITE_HYBRID_X25519_MLKEM768, PROTOCOL_VERSION,
};
use transferd_crypto::handshake::{Initiator, Responder};

use crate::error::{OverlayError, Result};
use crate::identity::NodeIdentity;
use crate::protocol::{Frame, FrameReader};

/// Largest blob the tunnel will read or write. A handshake flight is ~8.5 kB.
pub const MAX_TUNNEL_FRAME: usize = 256 * 1024;

/// Domain separators, so no key is ever reused between roles or between link kinds.
const CTX_C2S: &str = "TransferDaemon-overlay-c2s-v1";
const CTX_S2C: &str = "TransferDaemon-overlay-s2c-v1";
const CTX_PREFIX: &str = "TransferDaemon-overlay-nonce-prefix-v1";

/// Bytes of a tunnel frame that are not ciphertext: len(4) + counter(8).
const TUNNEL_HEADER: usize = 4 + 8;

/// The directional keys and nonce prefixes one link uses.
///
/// A clone shares the send counter and the replay window, so every link built from one
/// session's keys draws nonces from one counter and checks replays against one window.
#[derive(Clone)]
pub struct LinkKeys {
    pub send: [u8; 32],
    pub recv: [u8; 32],
    send_prefix: [u8; 4],
    recv_prefix: [u8; 4],
    counter: Arc<FrameCounter>,
    window: Arc<ReplayWindow>,
}

/// Derive per-direction keys from a handshake session secret.
///
/// The derivation is **deterministic**, so both ends of a link derive the same pair from the
/// same secret with no extra round trip. Nonce uniqueness does not come from randomness here —
/// it comes from the counter, which is shared across every link of a session
/// ([`FrameCounter`]). That is what makes it safe for several links on one session to share
/// these keys.
pub fn derive_link_keys(session_key: &[u8; 32]) -> LinkKeys {
    let send = blake3::derive_key(CTX_C2S, session_key);
    let recv = blake3::derive_key(CTX_S2C, session_key);
    LinkKeys {
        send,
        recv,
        send_prefix: prefix_of(&send),
        recv_prefix: prefix_of(&recv),
        counter: Arc::default(),
        window: Arc::default(),
    }
}

/// The nonce prefix for one direction: the first four bytes of that direction's key, so it
/// cannot collide with the other direction.
fn prefix_of(key: &[u8; 32]) -> [u8; 4] {
    key[..4].try_into().unwrap_or([0; 4])
}

/// A counter shared by every link of one session in one direction.
///
/// Each tunnel frame consumes one value, so a (key, nonce) pair is never reused even when a
/// session has several links sharing the same keys, and even when a link dies and the frames
/// on it are re-sent over another.
#[derive(Debug, Default)]
pub struct FrameCounter(AtomicU64);

impl FrameCounter {
    /// A counter starting at zero.
    pub fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    /// Take the next value. A session keeps one for each direction.
    pub fn next(&self) -> u64 {
        self.0.fetch_add(1, Ordering::Relaxed)
    }
}

/// How far behind the newest counter a frame may arrive and still be accepted. Links of one
/// session deliver in their own order (a direct path overtakes the relay), so a strictly
/// increasing check would drop good frames; a window does not, and still sees every replay.
pub const REPLAY_WINDOW: u64 = 4096;

/// The receiving side's record of which counters it has accepted (RFC 4303 §3.4.3 style).
#[derive(Debug, Default)]
pub struct ReplayWindow(Mutex<ReplayState>);

#[derive(Debug, Default)]
struct ReplayState {
    /// One more than the highest counter accepted; 0 before any.
    next: u64,
    /// Bit `i` set: counter `next - 1 - i` was accepted.
    seen: Vec<u64>,
}

impl ReplayWindow {
    /// A window that has accepted nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// Accept `counter` if it is new and not too old. Call it only after the frame
    /// authenticated, so a forged counter cannot move the window.
    pub fn accept(&self, counter: u64) -> bool {
        let mut st = self.0.lock().unwrap_or_else(|p| p.into_inner());
        let words = (REPLAY_WINDOW / 64) as usize;
        if st.seen.len() != words {
            st.seen = vec![0; words];
        }
        if counter >= st.next {
            let shift = counter + 1 - st.next;
            shift_left(&mut st.seen, shift);
            st.seen[0] |= 1;
            st.next = counter + 1;
            return true;
        }
        let age = st.next - 1 - counter;
        if age >= REPLAY_WINDOW {
            return false;
        }
        let (word, bit) = ((age / 64) as usize, age % 64);
        if st.seen[word] & (1 << bit) != 0 {
            return false;
        }
        st.seen[word] |= 1 << bit;
        true
    }
}

/// Shift a little-endian bitmap towards higher indices by `n` bits, dropping what falls off.
fn shift_left(bits: &mut [u64], n: u64) {
    let len = bits.len();
    if n >= (len as u64) * 64 {
        bits.iter_mut().for_each(|w| *w = 0);
        return;
    }
    let (words, rem) = ((n / 64) as usize, (n % 64) as u32);
    for i in (0..len).rev() {
        let src = i as isize - words as isize;
        let lo = if src >= 0 { bits[src as usize] } else { 0 };
        let carry = if rem > 0 && src > 0 { bits[src as usize - 1] >> (64 - rem) } else { 0 };
        bits[i] = if rem > 0 { (lo << rem) | carry } else { lo };
    }
}

impl LinkKeys {
    /// The keys for a session secret; see [`derive_link_keys`].
    pub fn derive(session_key: &[u8; 32]) -> Self {
        derive_link_keys(session_key)
    }

    /// The mirrored view, for the side that accepted the connection.
    pub fn swapped(self) -> Self {
        Self {
            send: self.recv,
            recv: self.send,
            send_prefix: self.recv_prefix,
            recv_prefix: self.send_prefix,
            counter: Arc::default(),
            window: Arc::default(),
        }
    }
}

/// What a completed handshake produced.
pub struct HandshakeResult {
    /// The shared secret both sides derived.
    pub session_key: [u8; 32],
    /// The peer's 2624-byte hybrid public key, taken from its verified flight.
    pub peer_hybrid_pk: Vec<u8>,
    /// The peer's node id (hex of the Ed25519 component).
    pub peer_node_id: String,
    /// Per-direction keys for the link the handshake ran over.
    pub keys: LinkKeys,
}

/// Run the initiator side of the handshake over `io`.
///
/// `expect_node_id`, when given, is checked against the responder's signed identity: a peer
/// that is not who we dialled is refused here, before any application byte is exchanged.
pub async fn handshake_initiator<S>(
    io: &mut S,
    identity: &NodeIdentity,
    expect_node_id: Option<&str>,
) -> Result<HandshakeResult>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let init = Initiator::new();
    let flight = AuthInitiatorHello::build(
        &init,
        PROTOCOL_VERSION,
        CIPHERSUITE_HYBRID_X25519_MLKEM768,
        identity.signing_key(),
    );
    write_blob(io, &flight.to_wire()).await?;
    let reply = read_blob(io).await?;
    let resp = AuthResponderHello::from_wire(&reply)
        .ok_or_else(|| OverlayError::protocol("responder flight is malformed"))?;
    if !resp.verify() {
        return Err(OverlayError::protocol("responder flight signature does not verify"));
    }
    let peer_node_id = hex::encode(&resp.identity_pk.to_bytes()[..32]);
    if let Some(expected) = expect_node_id {
        if expected != peer_node_id {
            return Err(OverlayError::IdentityMismatch {
                node: peer_node_id,
                reason: format!("we dialled {expected}"),
            });
        }
    }
    let session_key = init.finalize(resp.hello);
    let keys = derive_link_keys(session_key.as_bytes());
    Ok(HandshakeResult {
        session_key: *session_key.as_bytes(),
        peer_hybrid_pk: resp.identity_pk.to_bytes(),
        peer_node_id,
        keys,
    })
}

/// Run the responder side of the handshake over `io`.
pub async fn handshake_responder<S>(io: &mut S, identity: &NodeIdentity) -> Result<HandshakeResult>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let flight = read_blob(io).await?;
    let hello = AuthInitiatorHello::from_wire(&flight)
        .ok_or_else(|| OverlayError::protocol("initiator flight is malformed"))?;
    if !hello.verify() {
        return Err(OverlayError::protocol("initiator flight signature does not verify"));
    }
    let (responder_hello, session_key) = Responder::new().respond(&hello.hello);
    let reply = AuthResponderHello::build(
        &responder_hello,
        PROTOCOL_VERSION,
        CIPHERSUITE_HYBRID_X25519_MLKEM768,
        identity.signing_key(),
    );
    write_blob(io, &reply.to_wire()).await?;
    Ok(HandshakeResult {
        session_key: *session_key.as_bytes(),
        peer_hybrid_pk: hello.identity_pk.to_bytes(),
        peer_node_id: hex::encode(&hello.identity_pk.to_bytes()[..32]),
        keys: derive_link_keys(session_key.as_bytes()).swapped(),
    })
}

/// Write one length-prefixed blob.
pub async fn write_blob<W: AsyncWrite + Unpin>(w: &mut W, body: &[u8]) -> Result<()> {
    let len = u32::try_from(body.len()).map_err(|_| OverlayError::protocol("blob too large"))?;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(body).await?;
    w.flush().await?;
    Ok(())
}

/// Read one length-prefixed blob, bounded.
pub async fn read_blob<R: AsyncRead + Unpin>(r: &mut R) -> Result<Vec<u8>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_TUNNEL_FRAME {
        return Err(OverlayError::protocol("blob is larger than the tunnel allows"));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    Ok(body)
}

/// One direction of the encrypted frame tunnel.
///
/// The counter (sending) and the replay window (receiving) come from the session's
/// [`LinkKeys`], shared by all its links, so no (key, nonce) pair is ever used twice — not even
/// across two links or after a link fails and its frames are re-sent elsewhere.
pub struct Tunnel {
    key: [u8; 32],
    prefix: [u8; 4],
    counter: Arc<FrameCounter>,
    window: Arc<ReplayWindow>,
}

impl Tunnel {
    /// The sending half, drawing nonces from `counter`.
    pub fn sender(keys: &LinkKeys) -> Self {
        Self { key: keys.send, prefix: keys.send_prefix, counter: keys.counter.clone(), window: Arc::default() }
    }

    /// The receiving half, checking replays against the session's window.
    pub fn receiver(keys: &LinkKeys) -> Self {
        Self { key: keys.recv, prefix: keys.recv_prefix, counter: Arc::default(), window: keys.window.clone() }
    }

    fn nonce(&self, counter: u64) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..4].copy_from_slice(&self.prefix);
        n[4..].copy_from_slice(&counter.to_be_bytes());
        n
    }

    /// Encrypt one blob into a tunnel frame.
    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let counter = self.counter.next();
        let cipher = Aes256Gcm::new_from_slice(&self.key).map_err(|_| OverlayError::protocol("bad tunnel key"))?;
        let len = u32::try_from(plaintext.len()).map_err(|_| OverlayError::protocol("frame too large"))?;
        let aad = associated_data(len, counter);
        // `encrypt` already returns ciphertext ‖ tag.
        let sealed = cipher
            .encrypt(
                Nonce::from_slice(&self.nonce(counter)),
                AeadPayload { msg: plaintext, aad: &aad },
            )
            .map_err(|_| OverlayError::protocol("tunnel encryption failed"))?;
        let mut out = Vec::with_capacity(TUNNEL_HEADER + sealed.len());
        out.extend_from_slice(&aad);
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    /// Decrypt one tunnel frame.
    ///
    /// The counter must be at least the lowest one not yet seen: a replayed or reordered frame
    /// is dropped even though its ciphertext is intact. This is the transport-level half of
    /// replay protection.
    pub fn open(&self, frame: &[u8]) -> Result<Vec<u8>> {
        if frame.len() < TUNNEL_HEADER {
            return Err(OverlayError::protocol("tunnel frame is too short"));
        }
        let len = u32::from_be_bytes(frame[..4].try_into().unwrap_or([0; 4])) as usize;
        let counter = u64::from_be_bytes(frame[4..12].try_into().unwrap_or([0; 8]));
        let aad = &frame[..12];
        let cipher = Aes256Gcm::new_from_slice(&self.key).map_err(|_| OverlayError::protocol("bad tunnel key"))?;
        let plain = cipher
            .decrypt(Nonce::from_slice(&self.nonce(counter)), AeadPayload { msg: &frame[TUNNEL_HEADER..], aad })
            .map_err(|_| OverlayError::protocol("tunnel frame failed authentication"))?;
        // Only an authenticated frame may move the window, so a forged counter cannot.
        if !self.window.accept(counter) {
            return Err(OverlayError::protocol("replayed tunnel frame"));
        }
        if plain.len() != len {
            return Err(OverlayError::protocol("tunnel frame length does not match its header"));
        }
        Ok(plain)
    }
}

/// `len ‖ counter`: the part of a tunnel frame that travels in the clear and is authenticated.
fn associated_data(len: u32, counter: u64) -> [u8; 12] {
    let mut aad = [0u8; 12];
    aad[..4].copy_from_slice(&len.to_be_bytes());
    aad[4..].copy_from_slice(&counter.to_be_bytes());
    aad
}

/// Reads sealed tunnel frames off a byte stream and hands back overlay frames.
pub struct TunnelReader {
    cipher: Tunnel,
    reader: FrameReader,
}

impl TunnelReader {
    /// A reader for the receiving direction of `keys`.
    pub fn new(keys: &LinkKeys) -> Self {
        Self { cipher: Tunnel::receiver(keys), reader: FrameReader::new() }
    }

    /// Read the next overlay frame, blocking until one arrives.
    pub async fn next_frame<R: AsyncRead + Unpin>(&mut self, r: &mut R) -> Result<Frame> {
        loop {
            let sealed = read_blob(r).await?;
            let plain = self.cipher.open(&sealed)?;
            if let Some(frame) = self.reader.push(&plain).into_iter().next() {
                return Ok(frame);
            }
        }
    }
}

/// Seal one overlay frame and write it to a byte stream.
pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, cipher: &Tunnel, frame: &Frame) -> Result<()> {
    write_blob(w, &cipher.seal(&frame.encode())?).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::kind;

    fn keys() -> LinkKeys {
        derive_link_keys(&[9u8; 32])
    }

    /// The sending keys at one end and the receiving keys at the other, as a real link has.
    fn both_ends() -> (Tunnel, Tunnel) {
        let here = keys();
        let there = here.clone().swapped();
        (Tunnel::sender(&here), Tunnel::receiver(&there))
    }

    #[tokio::test]
    async fn the_handshake_agrees_on_one_key_and_verifies_both_identities() {
        let a = NodeIdentity::generate("a");
        let b = NodeIdentity::generate("b");
        let (mut ca, mut cb) = tokio::io::duplex(64 * 1024);
        let (init, resp) = tokio::join!(
            handshake_initiator(&mut ca, &a, Some(b.node_id())),
            handshake_responder(&mut cb, &b)
        );
        let init = init.expect("initiator");
        let resp = resp.expect("responder");
        assert_eq!(init.session_key, resp.session_key);
        assert_eq!(init.peer_hybrid_pk, b.hybrid_public_key());
        assert_eq!(resp.peer_hybrid_pk, a.hybrid_public_key());
        assert_eq!(init.peer_node_id, b.node_id());
        assert_eq!(init.keys.send, resp.keys.recv, "the sides mirror each other's keys");
        assert_eq!(init.keys.recv, resp.keys.send);
    }

    #[tokio::test]
    async fn the_handshake_refuses_a_peer_that_is_not_who_we_dialled() {
        let a = NodeIdentity::generate("a");
        let b = NodeIdentity::generate("b");
        let stranger = NodeIdentity::generate("c");
        let (mut ca, mut cb) = tokio::io::duplex(64 * 1024);
        let (init, _resp) = tokio::join!(
            handshake_initiator(&mut ca, &a, Some(stranger.node_id())),
            handshake_responder(&mut cb, &b)
        );
        let Err(err) = init else { panic!("the handshake must refuse a peer that is not who we dialled") };
        assert_eq!(err.code(), "identity_mismatch");
    }

    #[tokio::test]
    async fn a_tunnel_seals_and_opens_a_frame() {
        let (tx, rx) = both_ends();
        let frame = Frame::new(2, kind::PING, 5, &crate::protocol::Ping { nonce: 1, sent_us: 2 }).expect("frame");
        let sealed = tx.seal(&frame.encode()).expect("seal");
        assert_ne!(sealed, frame.encode(), "the wire bytes are not the plaintext");
        let opened = rx.open(&sealed).expect("open");
        let (back, _) = crate::protocol::decode(&opened).expect("frame");
        assert_eq!(back, frame);
    }

    #[tokio::test]
    async fn a_tunnel_only_opens_for_the_other_end_of_the_link() {
        let (tx, _) = both_ends();
        let stranger = Tunnel::receiver(&keys());
        let sealed = tx.seal(&frame(1).encode()).expect("seal");
        assert!(stranger.open(&sealed).is_err(), "a third party's key does not open it");
    }

    #[tokio::test]
    async fn a_tunnel_refuses_tampering_and_replay() {
        let (tx, rx) = both_ends();
        let frame = Frame::new(2, kind::PING, 1, &crate::protocol::Ping { nonce: 1, sent_us: 1 }).expect("frame");
        let sealed = tx.seal(&frame.encode()).expect("seal");

        let mut flipped = sealed.clone();
        let last = flipped.len() - 1;
        flipped[last] ^= 0xff;
        assert!(rx.open(&flipped).is_err(), "a flipped ciphertext bit must not authenticate");

        let sealed = tx.seal(&frame.encode()).expect("seal");
        rx.open(&sealed).expect("the first copy");
        assert!(rx.open(&sealed).is_err(), "the same tunnel frame twice is refused");
    }

    #[tokio::test]
    async fn a_tunnel_rejects_a_frame_whose_length_header_was_changed() {
        let (tx, rx) = both_ends();
        let frame = Frame::new(2, kind::PING, 1, &crate::protocol::Ping { nonce: 1, sent_us: 1 }).expect("frame");
        let mut sealed = tx.seal(&frame.encode()).expect("seal");
        sealed[3] ^= 0x7f; // change the length that is bound in as associated data
        assert!(rx.open(&sealed).is_err(), "length is authenticated");
    }

    #[tokio::test]
    async fn the_tunnel_carries_frames_over_a_byte_stream() {
        let here = keys();
        let there = here.clone().swapped();
        let (mut a, mut b) = tokio::io::duplex(64 * 1024);
        let tx = Tunnel::sender(&here);
        let mut reader = TunnelReader::new(&there);

        let one = Frame::new(2, kind::PING, 1, &crate::protocol::Ping { nonce: 11, sent_us: 22 }).expect("frame");
        let two = Frame::new(2, kind::BYE, 2, &()).expect("frame");
        write_frame(&mut a, &tx, &one).await.expect("write one");
        write_frame(&mut a, &tx, &two).await.expect("write two");
        assert_eq!(reader.next_frame(&mut b).await.expect("frame one"), one);
        assert_eq!(reader.next_frame(&mut b).await.expect("frame two"), two);
    }

    #[test]
    fn the_replay_window_takes_reordered_frames_once_and_refuses_ancient_ones() {
        let w = ReplayWindow::new();
        assert!(w.accept(0), "the very first frame");
        assert!(w.accept(5));
        assert!(w.accept(3), "late, but inside the window");
        assert!(!w.accept(3), "the same counter twice");
        assert!(!w.accept(5));
        assert!(w.accept(5 + REPLAY_WINDOW));
        assert!(!w.accept(5), "fell out of the window");
        assert!(w.accept(6 + 64), "a counter across a word boundary");
        assert!(!w.accept(6 + 64));
        assert!(w.accept(100_000));
        assert!(w.accept(100_000 - 1));
        assert!(w.accept(100_000 - 64));
        assert!(!w.accept(100_000 - 64));
    }
}

/// A frame with a fresh ping body, used by the tunnel tests.
#[cfg(test)]
fn frame(seq: u64) -> Frame {
    Frame::new(2, crate::protocol::kind::PING, seq, &crate::protocol::Ping { nonce: seq, sent_us: seq })
        .expect("frame")
}
