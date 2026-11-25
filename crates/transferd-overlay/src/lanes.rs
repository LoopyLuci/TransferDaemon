//! The concrete transports: direct TCP, and the blind UDP relay (the hole-punched UDP route is
//! in `punch.rs`).
//!
//! All of them produce the same [`Link`], because the overlay frames and the tunnel are identical
//! on every medium. That is what lets the router treat a relay and a LAN path as
//! interchangeable, and what makes a new medium a plug-in rather than a protocol change.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;

use relayd::protocol::{encode, split, DeliveredMsg, ForwardMsg, Tag};
use transferd_core::lanes::relay_client::RelayClient;

use crate::error::{OverlayError, Result};
use crate::identity::relay_token_for;
use crate::link::{Link, RouteKind, RouteStats};
use crate::protocol::{Frame, FrameReader};
use crate::wire::{read_blob, write_blob, LinkKeys, Tunnel};

/// The marker byte that says "this payload belongs to the overlay".
pub const PREFIX_OVERLAY: u8 = 0x03;

/// How many sealed bulk frames may be queued for a socket before the route is called congested.
const SEND_QUEUE: usize = 256;

/// How many sealed control and interactive frames may be queued. They have their own queue, drained first, so a
/// backlog of bulk data never keeps a control frame (a window update, a stream open) waiting behind it.
const CONTROL_QUEUE: usize = 512;

/// How many inbound overlay frames a link buffers before the reader stops taking more.
const RECV_QUEUE: usize = 1024;

// ---------------------------------------------------------------------------
// FramePipe
// ---------------------------------------------------------------------------

/// A [`Link`] over any transport that moves whole frames: a sink that takes bytes and a
/// source that produces them.
///
/// Reads and writes never block the caller: the write side queues into a bounded channel that
/// a task drains, and the read side is filled by a task that reads from the transport. When the
/// queue is full the route reports congestion and the router picks another one, which is
/// backpressure across routes rather than a stall.
pub struct FramePipe {
    id: u32,
    kind: RouteKind,
    describe: String,
    stats: Arc<RouteStats>,
    sender: Tunnel,
    /// Bulk frames (see [`Frame::is_bulk`]), drained after the control queue.
    out: mpsc::Sender<Vec<u8>>,
    /// Control and interactive frames, drained first.
    control: mpsc::Sender<Vec<u8>>,
    inbox: Mutex<VecDeque<Frame>>,
    closed: Arc<AtomicBool>,
    /// The session's wake-up, set when a session adopts the link.
    waker: Mutex<Option<Arc<tokio::sync::Notify>>>,
}

impl std::fmt::Debug for FramePipe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FramePipe")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .finish()
    }
}

impl FramePipe {
    /// Build a link. The caller supplies the byte sink and starts the byte source with
    /// [`FramePipe::feed`].
    ///
    /// Returns the link and the queues a writer task drains onto its socket, control first.
    pub fn new(
        id: u32,
        kind: RouteKind,
        describe: impl Into<String>,
        keys: &LinkKeys,
    ) -> (Arc<Self>, Outbound) {
        let (tx, rx) = mpsc::channel(SEND_QUEUE);
        let (control, control_rx) = mpsc::channel(CONTROL_QUEUE);
        let link = Arc::new(Self {
            id,
            kind,
            describe: describe.into(),
            stats: Arc::new(RouteStats::new(kind)),
            sender: Tunnel::sender(keys),
            out: tx,
            control,
            inbox: Mutex::new(VecDeque::new()),
            closed: Arc::new(AtomicBool::new(false)),
            waker: Mutex::new(None),
        });
        (
            link,
            Outbound {
                control: control_rx,
                data: rx,
            },
        )
    }

    /// The receiving half's cipher and frame reader, for the task that reads the transport.
    pub fn receiver(keys: &LinkKeys) -> (Tunnel, FrameReader) {
        (Tunnel::receiver(keys), FrameReader::new())
    }

    /// Whether the inbox has room for another blob. The reader waits until it does before it takes
    /// the next blob from the transport, so a slow session slows the peer down instead of losing
    /// frames.
    pub fn has_room(&self) -> bool {
        self.inbox.lock().unwrap_or_else(|e| e.into_inner()).len() < RECV_QUEUE
    }

    /// Feed a sealed blob read from the transport into the link's inbox.
    ///
    /// Returns false when the blob failed authentication or was a replay (the tunnel's window
    /// refuses it). Such a blob says nothing about the route (anyone can throw a bad datagram at a
    /// socket), so it never marks the route down; an authenticated one is what proves the route
    /// works. Every frame in an authenticated blob is kept, because the reader only takes a blob
    /// once `has_room` says there is space for it.
    pub fn feed(&self, tunnel: &Tunnel, reader: &mut FrameReader, sealed: &[u8]) -> bool {
        let Ok(plain) = tunnel.open(sealed) else {
            return false;
        };
        self.stats.mark_up();
        let mut inbox = self.inbox.lock().unwrap_or_else(|e| e.into_inner());
        inbox.extend(reader.push(&plain));
        drop(inbox);
        self.wake();
        true
    }

    fn wake(&self) {
        if let Some(waker) = self
            .waker
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            waker.notify_one();
        }
    }

    /// Whether the link has not been closed (it may still be down for now).
    pub fn is_open(&self) -> bool {
        !self.closed.load(Ordering::Relaxed)
    }

    /// Mark the link closed.
    pub fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        self.stats.mark_down();
    }

    /// Put an already-decoded frame into the inbox (used by the relay demultiplexer, which
    /// shares one socket between every peer).
    pub fn push_frame(&self, frame: Frame) {
        self.stats.mark_up();
        let mut inbox = self.inbox.lock().unwrap_or_else(|e| e.into_inner());
        if inbox.len() < RECV_QUEUE {
            inbox.push_back(frame);
        }
        drop(inbox);
        self.wake();
    }
}

impl Link for FramePipe {
    fn kind(&self) -> RouteKind {
        self.kind
    }

    fn id(&self) -> u32 {
        self.id
    }

    fn stats(&self) -> &Arc<RouteStats> {
        &self.stats
    }

    fn send(&self, frame: &Frame) -> Result<()> {
        let sealed = self.sender.seal(&frame.encode())?;
        // Control and interactive frames go on their own queue, so bulk data never holds them up.
        let queue = if frame.is_bulk() { &self.out } else { &self.control };
        match queue.try_send(sealed) {
            Ok(()) => {
                self.stats.record_sent(frame.body.len() as u64);
                Ok(())
            }
            Err(_) => Err(OverlayError::protocol("route is congested")),
        }
    }

    fn try_recv(&self) -> Option<Frame> {
        self.inbox
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pop_front()
    }

    fn is_up(&self) -> bool {
        !self.closed.load(Ordering::Relaxed) && self.stats.metrics().up
    }

    fn mark_down(&self) {
        self.stats.mark_down();
    }

    fn describe(&self) -> String {
        self.describe.clone()
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    fn set_waker(&self, waker: Arc<tokio::sync::Notify>) {
        *self.waker.lock().unwrap_or_else(|e| e.into_inner()) = Some(waker.clone());
        // Anything that arrived before the session was listening is read now.
        if !self
            .inbox
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty()
        {
            waker.notify_one();
        }
    }
}

// ---------------------------------------------------------------------------
// Writer tasks
// ---------------------------------------------------------------------------

/// The two queues a writer task drains, control first.
pub struct Outbound {
    control: mpsc::Receiver<Vec<u8>>,
    data: mpsc::Receiver<Vec<u8>>,
}

impl Outbound {
    /// The next sealed blob to send: a waiting control blob before any bulk blob. `None` once the link is gone and
    /// both queues are empty.
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        tokio::select! {
            biased;
            Some(sealed) = self.control.recv() => Some(sealed),
            Some(sealed) = self.data.recv() => Some(sealed),
            else => None,
        }
    }
}

/// Drain a link's send queues onto a byte stream, control frames first.
async fn write_loop<W>(mut writer: W, mut outbound: Outbound, link: Arc<FramePipe>)
where
    W: AsyncWrite + Unpin + Send,
{
    while let Some(sealed) = outbound.recv().await {
        if write_blob(&mut writer, &sealed).await.is_err() {
            link.close();
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Direct TCP
// ---------------------------------------------------------------------------

/// Dial a peer over TCP, run the authenticated handshake, and return the link plus what we
/// learned about the peer.
///
/// Everything is outbound: the peer answers on the connection we opened, so nothing has to be
/// reachable from outside. `identity` is this node's own identity, used to sign the flight.
/// How long a direct dial may take before the next path is tried.
pub const DIAL_TIMEOUT: Duration = Duration::from_secs(3);

pub async fn dial_tcp(
    id: u32,
    kind: RouteKind,
    target: &str,
    identity: &crate::identity::NodeIdentity,
    expect_node_id: Option<&str>,
) -> Result<(Arc<FramePipe>, LinkKeys, String, Vec<u8>)> {
    // A short wait: an address that does not answer quickly is not the route to wait for, the
    // relay is.
    let mut stream = tokio::time::timeout(DIAL_TIMEOUT, TcpStream::connect(target))
        .await
        .map_err(|_| {
            OverlayError::protocol(format!("{target} did not answer within {DIAL_TIMEOUT:?}"))
        })?
        .map_err(|e| OverlayError::protocol(format!("cannot reach {target}: {e}")))?;
    let _ = stream.set_nodelay(true);
    let hs = crate::wire::handshake_initiator(&mut stream, identity, expect_node_id).await?;
    let keys = hs.keys.clone();
    let (read, write) = stream.into_split();
    let link = split_link(
        id,
        kind,
        format!("tcp://{target}"),
        keys.clone(),
        write,
        read,
    );
    Ok((link, keys, hs.peer_node_id, hs.peer_hybrid_pk))
}

/// Accept a connection and answer the handshake, returning the link plus what we learned.
pub async fn accept_tcp(
    id: u32,
    kind: RouteKind,
    stream: TcpStream,
    identity: &crate::identity::NodeIdentity,
) -> Result<(Arc<FramePipe>, LinkKeys, String, Vec<u8>)> {
    let _ = stream.set_nodelay(true);
    let mut stream = stream;
    let hs = crate::wire::handshake_responder(&mut stream, identity).await?;
    let keys = hs.keys.clone();
    let peer = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_default();
    let (read, write) = stream.into_split();
    let link = split_link(id, kind, format!("tcp://{peer}"), keys.clone(), write, read);
    Ok((link, keys, hs.peer_node_id, hs.peer_hybrid_pk))
}

// ---------------------------------------------------------------------------
// Relay
// ---------------------------------------------------------------------------

/// A registered relay point: our token, the relay address, and the socket the relay knows us by.
pub struct RelayPoint {
    pub addr: SocketAddr,
    pub kind: RouteKind,
    client: Arc<RelayClient>,
    self_token: [u8; 32],
}

impl RelayPoint {
    /// Bind an outbound UDP socket, solve the relay's proof of work, and register `self_token`.
    ///
    /// Registration is what makes the relay able to *deliver* to us, and we are only ever
    /// reachable through the mapping this outbound socket created — no inbound port is needed.
    pub async fn register(addr: SocketAddr, self_token: [u8; 32]) -> Result<Arc<Self>> {
        let client = Arc::new(
            RelayClient::bind(addr)
                .await
                .map_err(|e| OverlayError::Relay {
                    addr: addr.to_string(),
                    reason: e.to_string(),
                })?,
        );
        client
            .register(self_token)
            .await
            .map_err(|e| OverlayError::Relay {
                addr: addr.to_string(),
                reason: e.to_string(),
            })?;
        client.spawn_keepalive_loop(self_token);
        Ok(Arc::new(Self {
            addr,
            kind: RouteKind::Relay,
            client,
            self_token,
        }))
    }

    /// The relay this node is registered on.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The token the relay routes our messages to us under.
    pub fn self_token(&self) -> [u8; 32] {
        self.self_token
    }

    /// Forward one sealed blob to `peer_token`, addressed to the peer, not to us.
    pub async fn forward(&self, peer_token: [u8; 32], sealed: Vec<u8>) -> Result<()> {
        let mut payload = Vec::with_capacity(1 + 32 + sealed.len());
        payload.push(PREFIX_OVERLAY);
        payload.extend_from_slice(&self.self_token);
        payload.extend_from_slice(&sealed);
        self.client
            .send_forward(peer_token, &pad(&payload))
            .await
            .map_err(|e| OverlayError::Relay {
                addr: self.addr.to_string(),
                reason: e.to_string(),
            })
    }

    /// Build a link over this relay to `peer_token`.
    pub fn link(
        self: &Arc<Self>,
        id: u32,
        peer_token: [u8; 32],
        keys: &LinkKeys,
    ) -> Arc<FramePipe> {
        let (link, outbound) = FramePipe::new(
            id,
            self.kind,
            format!("relay://{}#{}", self.addr, hex::encode(peer_token)),
            keys,
        );
        let this = self.clone();
        // The relay is a blind pipe: bytes go out through it, and inbound blobs come back on
        // the socket the relay replies to.
        tokio::spawn(async move {
            let mut outbound = outbound;
            while let Some(sealed) = outbound.recv().await {
                let mut payload = Vec::with_capacity(1 + 32 + sealed.len());
                payload.push(PREFIX_OVERLAY);
                payload.extend_from_slice(&this.self_token);
                payload.extend_from_slice(&sealed);
                // A datagram that could not be sent is a lost one, which the session repairs.
                if let Err(e) = this.client.send_forward(peer_token, &pad(&payload)).await {
                    tracing::debug!("[overlay relay] a datagram was not sent: {e}");
                }
            }
        });
        link
    }
}

/// Pad a relay payload to a power of two, with a length header, so the relay only ever sees
/// fixed-grid sizes (the same rule the messaging relay lane follows).
fn pad(data: &[u8]) -> Vec<u8> {
    let len = data.len() as u32;
    let mut power = 64usize;
    while power < data.len() + 4 {
        power *= 2;
    }
    let mut out = Vec::with_capacity(power);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(data);
    out.resize(power, 0);
    out
}

/// Strip the padding and the overlay prefix, returning the sender's token and the sealed blob.
fn unpad(data: &[u8]) -> Option<([u8; 32], &[u8])> {
    if data.len() < 4 {
        return None;
    }
    let len = u32::from_le_bytes(data[..4].try_into().ok()?) as usize;
    if 4 + len > data.len() {
        return None;
    }
    let body = &data[4..4 + len];
    let (&prefix, rest) = body.split_first()?;
    if prefix != PREFIX_OVERLAY || rest.len() < 32 {
        return None;
    }
    let token: [u8; 32] = rest[..32].try_into().ok()?;
    Some((token, &rest[32..]))
}

/// Read the relay's datagrams and hand every overlay payload to `on_blob`.
pub async fn relay_recv_loop<F>(
    socket: Arc<UdpSocket>,
    link: Arc<FramePipe>,
    keys: &LinkKeys,
    mut on_blob: F,
) where
    F: FnMut([u8; 32], &[u8]) -> bool,
{
    let (tunnel, mut reader) = FramePipe::receiver(keys);
    let mut buf = vec![0u8; 65_536];
    while link.is_up() {
        let Ok((n, _)) = socket.recv_from(&mut buf).await else {
            continue;
        };
        let Some((tag, body)) = split(&buf[..n]) else {
            continue;
        };
        if tag != Tag::Ack {
            continue;
        }
        let Ok(delivered) = bincode::deserialize::<DeliveredMsg>(body) else {
            continue;
        };
        // The relay forwards the sender's token inside the payload, so a peer is identified
        // without the relay ever learning who it is talking to.
        let Some((from, sealed)) = unpad(&delivered.ciphertext) else {
            continue;
        };
        if !on_blob(from, sealed) {
            return; // the inbox is full; stop reading until it drains
        }
        link.feed(&tunnel, &mut reader, sealed);
    }
}

/// Decode a relay payload without a link, for the inbound demultiplexer.
pub fn relay_payload(data: &[u8]) -> Option<([u8; 32], &[u8])> {
    unpad(data)
}

/// Build the `ForwardMsg` a peer must send us; used by tests and by the WebSocket relay.
pub fn forward_message(
    peer_token: [u8; 32],
    sender_token: [u8; 32],
    sealed: &[u8],
) -> Result<Vec<u8>> {
    let mut payload = Vec::with_capacity(1 + 32 + sealed.len());
    payload.push(PREFIX_OVERLAY);
    payload.extend_from_slice(&sender_token);
    payload.extend_from_slice(sealed);
    encode(
        Tag::Forward,
        &ForwardMsg {
            session_token: peer_token,
            pow_nonce: 0,
            sender_seq: 0,
            ciphertext: pad(&payload),
        },
    )
    .map_err(|e| OverlayError::protocol(e.to_string()))
}

/// The token a node registers under on a relay: derived from its node id, so it is the same
/// everywhere and the relay cannot tell nodes apart.
pub fn token_for(node_id: &str) -> [u8; 32] {
    relay_token_for(node_id)
}

/// Turn a pair of byte-stream halves into a running link: one task writes what is queued, one
/// reads what arrives.
pub fn split_link<W, R>(
    id: u32,
    kind: RouteKind,
    describe: String,
    keys: LinkKeys,
    writer: W,
    reader: R,
) -> Arc<FramePipe>
where
    W: AsyncWrite + Unpin + Send + 'static,
    R: AsyncRead + Unpin + Send + 'static,
{
    let (link, outbound) = FramePipe::new(id, kind, describe, &keys);
    let w = link.clone();
    tokio::spawn(write_loop(writer, outbound, w));
    tokio::spawn(read_loop(link.clone(), keys, reader));
    link
}

async fn read_loop<R>(link: Arc<FramePipe>, keys: LinkKeys, mut source: R)
where
    R: AsyncRead + Unpin + Send + 'static,
{
    let (tunnel, mut reader) = FramePipe::receiver(&keys);
    loop {
        // Until the session drains the inbox there is no room, and the next blob stays on the socket.
        while !link.has_room() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let Ok(sealed) = read_blob(&mut source).await else {
            break;
        };
        link.feed(&tunnel, &mut reader, &sealed);
    }
    link.close();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{self, kind};
    use crate::wire::LinkKeys;

    fn bulk_frame(seq: u64) -> Frame {
        let mut frame = Frame::bare(protocol::VERSION_CURRENT as u8, kind::DATA, seq).bulk();
        frame.body = vec![0u8; 1024];
        frame
    }

    /// A control frame is accepted while the bulk queue is full, and it leaves before the bulk
    /// frames queued ahead of it.
    #[tokio::test]
    async fn a_control_frame_leaves_before_a_full_bulk_queue() {
        let session_key = [9u8; 32];
        let keys = LinkKeys::derive(&session_key);
        let (link, mut outbound) = FramePipe::new(1, RouteKind::Direct, "test", &keys);

        // Fill the bulk queue until the link refuses a bulk frame.
        let mut queued = 0u64;
        while link.send(&bulk_frame(queued)).is_ok() {
            queued += 1;
        }
        assert_eq!(queued, SEND_QUEUE as u64, "the bulk queue holds SEND_QUEUE frames");

        // A control frame is still accepted, and it is the first frame out.
        let control = Frame::bare(protocol::VERSION_CURRENT as u8, kind::WINDOW, queued);
        link.send(&control)
            .expect("a control frame is accepted while the bulk queue is full");
        let sealed = outbound.recv().await.expect("a frame is queued");

        // The peer opens with the mirrored keys.
        let (tunnel, mut reader) = FramePipe::receiver(&LinkKeys::derive(&session_key).swapped());
        let plain = tunnel.open(&sealed).expect("the first frame opens");
        let frames = reader.push(&plain);
        assert_eq!(frames.len(), 1);
        assert_eq!(
            frames[0].kind,
            kind::WINDOW,
            "the control frame leaves before the bulk backlog"
        );
    }
}
