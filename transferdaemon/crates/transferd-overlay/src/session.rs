//! One peer's session: the routes to it, the streams over those routes, and the tick that keeps
//! them moving.
//!
//! A session owns a set of [`Link`]s and a [`Mux`]. Everything that decides where bytes go
//! happens here:
//!
//! * **Best route per flow.** An interactive stream is pinned to the cheapest live route, so its
//!   frames take one predictable path.
//! * **Failover mid-stream.** When a route dies, the unacknowledged frames are re-sent over the
//!   next-best route. Because every data frame carries `(stream, seq)`, the peer reassembles
//!   them into the same byte stream: the application's TCP connection is never interrupted or
//!   reset by a route change — the missing bytes simply arrive over a different path.
//! * **Striping.** A bulk stream is split across the live routes, weighted by measured
//!   throughput, so one slow path does not become the ceiling on a transfer.
//! * **Flow control.** Every stream advertises a window, so a slow reader stops being sent to
//!   rather than filling the peer's memory.
//!
//! The session runs in one task that owns all of its mutable state, so no lock is ever held
//! across an `await`. It is driven by two inputs: a command channel and a 20 ms tick.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use crate::error::{OverlayError, Result};
use crate::link::{Link, RouteKind};
use crate::mux::{Mux, OutFrame, StreamId};
use crate::protocol::{
    self, kind, Ack, Close, CtrlAck, Data, Frame, Hello, HelloAck, Open, OpenErr, OpenOk, Ping,
    Pong, PunchMsg, RouteReport, Routes, Window,
};

/// How often the session ticks.
pub const TICK: Duration = Duration::from_millis(20);

/// How often the prober pings each route.
pub const PROBE_EVERY: Duration = Duration::from_millis(1000);

/// How long a frame may sit unacknowledged before it goes out again, on another route.
pub const RESEND_AFTER: Duration = Duration::from_millis(400);

/// Unanswered pings in a row before a route counts as down: one lost datagram is not an outage.
const MISSES_DOWN: u32 = 3;

/// How long a control frame waits for its receipt before it goes out again.
pub const CTRL_RESEND: Duration = Duration::from_millis(300);

/// How long a control frame is resent before the peer is taken to be gone.
const CTRL_GIVE_UP: Duration = Duration::from_secs(60);

/// Control frames remembered for de-duplication.
const CTRL_REMEMBERED: usize = 8192;

/// How long `open` waits for the peer to accept or refuse a stream.
pub const OPEN_TIMEOUT: Duration = Duration::from_secs(15);

/// A frame this big or bigger is treated as bulk: striped across routes rather than pinned.
const BULK_THRESHOLD: usize = 4096;

/// What the session tells the node when something happens.
#[derive(Debug, Clone)]
pub enum SessionEvent {
    /// The peer's hello arrived (the first, or a later one announcing its services), with its
    /// extension bytes.
    Hello {
        peer: String,
        name: String,
        ext: Vec<u8>,
    },
    /// The peer answered our hello and the session is up.
    Ready {
        peer: String,
        version: u16,
        services: Vec<protocol::ServiceInfo>,
    },
    /// The peer refused us (no common protocol version, or an identity mismatch).
    Refused { peer: String, reason: String },
    /// A route to this peer changed state.
    RouteChanged {
        peer: String,
        kind: RouteKind,
        up: bool,
    },
    /// The peer wants to open a stream to one of our services. The node answers with
    /// `SessionCommand::Authorize`, which is where the ACL is enforced: nothing is accepted
    /// before that, so an unauthorised peer never reaches a local socket.
    OpenRequest {
        peer: String,
        stream: StreamId,
        service: String,
    },
    /// The peer sent its side of a hole-punch exchange (request or answer).
    Punch { peer: String, msg: PunchMsg },
    /// The session went away.
    Down { peer: String, reason: String },
}

/// What we know about a peer once its hello is answered.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub node_id: String,
    pub name: String,
    pub version: u16,
    pub services: Vec<protocol::ServiceInfo>,
}

/// Something the application asked the session to do.
pub enum SessionCommand {
    /// Open a stream to one of the peer's services.
    Open {
        service: String,
        reply: mpsc::Sender<Result<StreamId>>,
    },
    /// Queue bytes for a stream.
    Send {
        stream: StreamId,
        bytes: Vec<u8>,
        fin: bool,
    },
    /// Take whatever the peer has sent on a stream.
    Recv {
        stream: StreamId,
        reply: mpsc::Sender<Option<Vec<u8>>>,
    },
    /// Close a stream.
    Close { stream: StreamId },
    /// Add a route discovered after the session came up (a hole punch, a LAN address).
    AddLink { link: Arc<dyn Link> },
    /// Allow or refuse a stream the peer asked for.
    Authorize {
        stream: StreamId,
        service: String,
        ok: bool,
        reason: String,
    },
    /// Tell the peer what we expose now (after an expose or unexpose): a fresh hello, which the
    /// peer answers like any other and uses to update what it knows about us.
    Advertise {
        services: Vec<protocol::ServiceInfo>,
    },
    /// Send our side of a hole-punch exchange (only when the agreed version carries it).
    Punch { msg: PunchMsg },
    /// Stop the session.
    Shutdown,
}

/// The sending half of a session: the handle the rest of the node uses to talk to it.
pub struct SessionHandle {
    pub peer_node_id: String,
    peer_name: parking_lot::RwLock<String>,
    commands: mpsc::Sender<SessionCommand>,
    /// The services the peer advertised, refreshed on every hello.
    pub services: Arc<parking_lot::RwLock<Vec<protocol::ServiceInfo>>>,
    /// The routes this session measures, shared so `overlay.peers` can read them cheaply.
    routes: Arc<parking_lot::RwLock<Vec<protocol::RouteReport>>>,
    /// The agreed protocol version.
    version: Arc<parking_lot::RwLock<u16>>,
}

impl Clone for SessionHandle {
    fn clone(&self) -> Self {
        Self {
            peer_node_id: self.peer_node_id.clone(),
            peer_name: parking_lot::RwLock::new(self.peer_name.read().clone()),
            commands: self.commands.clone(),
            services: self.services.clone(),
            routes: self.routes.clone(),
            version: self.version.clone(),
        }
    }
}

impl SessionHandle {
    /// The peer's display name.
    pub fn peer_name(&self) -> String {
        self.peer_name.read().clone()
    }

    /// Open a stream to a service the peer exposes. Returns once the peer has accepted it (its
    /// access list and rate limit said yes), or with the peer's reason for refusing.
    pub async fn open(&self, service: &str) -> Result<StreamId> {
        let (reply, mut rx) = mpsc::channel(1);
        self.commands
            .send(SessionCommand::Open {
                service: service.to_string(),
                reply,
            })
            .await
            .map_err(|_| self.gone())?;
        match tokio::time::timeout(OPEN_TIMEOUT, rx.recv()).await {
            Ok(answer) => answer.ok_or_else(|| self.gone())?,
            Err(_) => Err(OverlayError::Unreachable {
                node: self.peer_node_id.clone(),
            }),
        }
    }

    /// Queue bytes for a stream. The stream's window decides how much actually moves; the rest
    /// waits for a `Window` frame, which is where backpressure lands.
    pub async fn send(&self, stream: StreamId, bytes: Vec<u8>, fin: bool) -> Result<()> {
        self.commands
            .send(SessionCommand::Send { stream, bytes, fin })
            .await
            .map_err(|_| self.gone())
    }

    /// Take what the peer has sent on a stream, or `None` when nothing is buffered yet.
    pub async fn recv(&self, stream: StreamId) -> Result<Option<Vec<u8>>> {
        let (reply, mut rx) = mpsc::channel(1);
        self.commands
            .send(SessionCommand::Recv { stream, reply })
            .await
            .map_err(|_| self.gone())?;
        Ok(rx.recv().await.unwrap_or(None))
    }

    /// Close a stream.
    pub async fn close(&self, stream: StreamId) {
        let _ = self.commands.send(SessionCommand::Close { stream }).await;
    }

    /// Add a route discovered after the session came up.
    pub async fn add_link(&self, link: Arc<dyn Link>) {
        let _ = self.commands.send(SessionCommand::AddLink { link }).await;
    }

    /// Answer a stream the peer asked for. This is where the ACL decision reaches the wire.
    pub async fn authorize(
        &self,
        stream: StreamId,
        service: String,
        ok: bool,
        reason: String,
    ) -> Result<()> {
        self.commands
            .send(SessionCommand::Authorize {
                stream,
                service,
                ok,
                reason,
            })
            .await
            .map_err(|_| self.gone())
    }

    /// Re-announce what we expose.
    pub async fn advertise(&self, services: Vec<protocol::ServiceInfo>) {
        let _ = self
            .commands
            .send(SessionCommand::Advertise { services })
            .await;
    }

    /// Send our side of a hole-punch exchange. Refused when the session did not agree on a
    /// version that carries it: an older peer would never acknowledge the frame.
    pub async fn send_punch(&self, msg: protocol::PunchMsg) -> Result<()> {
        if self.version() < protocol::VERSION_PUNCH {
            return Err(OverlayError::protocol(
                "the peer's protocol version has no hole punching",
            ));
        }
        self.commands
            .send(SessionCommand::Punch { msg })
            .await
            .map_err(|_| self.gone())
    }

    /// Stop the session.
    pub async fn shutdown(&self) {
        let _ = self.commands.send(SessionCommand::Shutdown).await;
    }

    /// Whether the session can still carry traffic.
    pub fn is_live(&self) -> bool {
        !self.commands.is_closed()
    }

    /// A handle that was never connected: used for peers we know but have not dialled yet.
    pub fn detached(node_id: String, commands: mpsc::Sender<SessionCommand>) -> Self {
        Self {
            peer_node_id: node_id,
            peer_name: parking_lot::RwLock::new(String::new()),
            commands,
            services: Arc::new(parking_lot::RwLock::new(Vec::new())),
            routes: Arc::new(parking_lot::RwLock::new(Vec::new())),
            version: Arc::new(parking_lot::RwLock::new(0)),
        }
    }

    /// The routes this session measures, for `overlay.peers`.
    pub fn routes(&self) -> Vec<crate::protocol::RouteReport> {
        self.routes.read().clone()
    }

    /// Wait until the peer has answered our hello (so what it offers is known), at most `limit`.
    /// False when it did not in time.
    pub async fn ready(&self, limit: std::time::Duration) -> bool {
        let deadline = tokio::time::Instant::now() + limit;
        while self.version() == 0 {
            if !self.is_live() || tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        true
    }

    /// The agreed protocol version, or 0 while the session is still negotiating.
    pub fn version(&self) -> u16 {
        *self.version.read()
    }

    /// A single number for "how good is this session's best route": milliseconds of estimated
    /// completion time. Lower is better, so a group can be placed by quality.
    pub fn route_quality(&self) -> f64 {
        self.routes
            .read()
            .iter()
            .filter(|r| r.active)
            .map(|r| r.rtt_ms + r.loss * 500.0)
            .fold(f64::INFINITY, f64::min)
    }

    fn gone(&self) -> OverlayError {
        OverlayError::Closed(format!("the session with {} is gone", self.peer_node_id))
    }
}

struct PendingRead(mpsc::Sender<Option<Vec<u8>>>);

/// Bytes the application asked to send that have not gone out yet.
#[derive(Default)]
struct WriteQueue {
    chunks: std::collections::VecDeque<Vec<u8>>,
    /// The application said this was the last write for the stream.
    fin: bool,
}

struct Session {
    peer_node_id: String,
    links: Vec<Arc<dyn Link>>,
    wake: Arc<tokio::sync::Notify>,
    mux: Mux,
    /// When each route was last probed.
    last_probe: HashMap<u32, Instant>,
    /// When each unacknowledged frame was last sent, keyed by `(stream, seq)`.
    sent_at: HashMap<(u64, u64), Instant>,
    /// Which route each open ping went out on, so the answer is credited to the right one.
    pings: HashMap<u64, (u32, Instant)>,
    /// Pings in a row a route has not answered; it is down after [`MISSES_DOWN`].
    misses: HashMap<u32, u32>,
    /// Receives still waiting for data.
    pending_reads: HashMap<u64, PendingRead>,
    /// Bytes written by the application that the window has not let out yet, per stream. This
    /// is where backpressure lives: nothing is dropped, it waits for credit.
    write_queue: HashMap<u64, WriteQueue>,
    /// Streams a peer asked for that the node has not answered yet.
    pending_opens: HashMap<u64, String>,
    /// Streams we asked for, waiting for the peer's OPEN_OK or OPEN_ERR.
    awaiting_open: HashMap<u64, (String, mpsc::Sender<Result<StreamId>>)>,
    /// The services the peer advertised.
    services: Vec<protocol::ServiceInfo>,
    /// What we tell the peer about ourselves, in our hello and in an answer to theirs.
    local: Hello,
    /// Control frames sent and not yet receipted: (frame, first sent, last sent).
    ctrl_unacked: std::collections::BTreeMap<u64, (Frame, Instant, Instant)>,
    /// Control frames received, by frame `seq`, so a resent one is acted on once. A set rather
    /// than a sliding window: frame numbers advance with every data frame and ping, so a resent
    /// control frame can arrive far behind the newest one and must still be recognised.
    ctrl_seen: std::collections::BTreeSet<u64>,
    version: u8,
    frame_seq: u64,
    ready: bool,
    stopped: bool,
    events: mpsc::UnboundedSender<SessionEvent>,
    handle_services: Arc<parking_lot::RwLock<Vec<protocol::ServiceInfo>>>,
    handle_name: parking_lot::RwLock<String>,
    handle_routes: Arc<parking_lot::RwLock<Vec<protocol::RouteReport>>>,
    handle_version: Arc<parking_lot::RwLock<u16>>,
}

/// Start a session over `links` and return the handle.
///
/// The first frame is a [`Hello`] advertising this build's whole supported version range; the
/// peer's [`HelloAck`] fixes the version for the session (see `docs/PROTOCOL.md`).
/// Who a session is with and what we tell it about ourselves.
pub struct SessionSetup {
    pub peer_node_id: String,
    pub peer_name: String,
    pub identity: crate::identity::NodeIdentity,
    /// The services we expose, for our hello.
    pub services: Vec<protocol::ServiceInfo>,
    /// The highest protocol version to offer.
    pub max_version: u8,
    /// Our hello's extension bytes (`protocol::HelloExt`).
    pub ext: Vec<u8>,
}

pub async fn spawn(
    setup: SessionSetup,
    links: Vec<Arc<dyn Link>>,
    events: mpsc::UnboundedSender<SessionEvent>,
) -> SessionHandle {
    let SessionSetup {
        peer_node_id,
        peer_name,
        identity,
        services,
        max_version,
        ext,
    } = setup;
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<SessionCommand>(64);
    let shared_services = Arc::new(parking_lot::RwLock::new(Vec::new()));
    let routes = Arc::new(parking_lot::RwLock::new(Vec::new()));
    let version = Arc::new(parking_lot::RwLock::new(0u16));
    let handle = SessionHandle {
        peer_node_id: peer_node_id.clone(),
        peer_name: parking_lot::RwLock::new(peer_name),
        commands: cmd_tx,
        services: shared_services.clone(),
        routes: routes.clone(),
        version: version.clone(),
    };
    let hello = Hello {
        min_version: protocol::VERSION_MIN,
        max_version: max_version as u16,
        node_id: identity.node_id().to_string(),
        name: identity.name().to_string(),
        services,
        ext,
        nonce: random_nonce(),
    };
    // The two ends allocate stream ids from different halves, decided by who has the lower id.
    let odd = identity.node_id() < peer_node_id.as_str();
    // Links wake the session when a frame arrives; the tick is only for probes and resends.
    let wake = Arc::new(tokio::sync::Notify::new());
    for link in &links {
        link.set_waker(wake.clone());
    }
    tokio::spawn(async move {
        let mut s = Session {
            peer_node_id,
            links,
            wake: wake.clone(),
            mux: Mux::with_parity(odd),
            last_probe: HashMap::new(),
            sent_at: HashMap::new(),
            pings: HashMap::new(),
            misses: HashMap::new(),
            pending_reads: HashMap::new(),
            write_queue: HashMap::new(),
            pending_opens: HashMap::new(),
            awaiting_open: HashMap::new(),
            services: Vec::new(),
            local: hello.clone(),
            ctrl_unacked: std::collections::BTreeMap::new(),
            ctrl_seen: std::collections::BTreeSet::new(),
            version: max_version,
            frame_seq: 0,
            ready: false,
            stopped: false,
            events,
            handle_services: shared_services,
            handle_name: parking_lot::RwLock::new(String::new()),
            handle_routes: routes,
            handle_version: version,
        };
        let sent = s.send_frame(
            kind::HELLO,
            bincode::serialize(&hello).unwrap_or_default(),
            false,
        );
        tracing::info!(
            "[overlay session] hello sent to {} ({sent})",
            s.peer_node_id
        );
        let mut ticker = tokio::time::interval(TICK);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                cmd = cmd_rx.recv() => match cmd {
                    Some(SessionCommand::Shutdown) | None => break,
                    Some(c) => s.handle_command(c).await,
                },
                _ = ticker.tick() => s.tick().await,
                _ = wake.notified() => s.drain_inbound().await,
            }
            if s.stopped {
                break;
            }
        }
        for (_, (_, reply)) in s.awaiting_open.drain() {
            let _ = reply.try_send(Err(OverlayError::Closed(format!(
                "the session with {} ended",
                s.peer_node_id
            ))));
        }
        let _ = s.events.send(SessionEvent::Down {
            peer: s.peer_node_id.clone(),
            reason: "session ended".into(),
        });
    });
    handle
}

fn random_nonce() -> [u8; 16] {
    let mut n = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut n);
    n
}

impl Session {
    fn next_seq(&mut self) -> u64 {
        self.frame_seq += 1;
        self.frame_seq
    }

    fn encode<T: serde::Serialize>(value: &T) -> Vec<u8> {
        bincode::serialize(value).unwrap_or_default()
    }

    fn send_frame(&mut self, kind: u8, body: Vec<u8>, bulk: bool) -> bool {
        let seq = self.next_seq();
        let frame = Frame {
            version: self.version,
            kind,
            flags: if bulk { protocol::flags::BULK } else { 0 },
            seq,
            body,
        };
        let sent = self.dispatch(&frame);
        if protocol::is_reliable(kind) {
            // Kept until the peer's receipt comes back; a frame that could not go out at all is
            // tried again on the next resend, so it still counts as queued.
            let now = Instant::now();
            self.ctrl_unacked.insert(seq, (frame, now, now));
            return true;
        }
        sent
    }

    /// Resend the control frames whose receipt has not come back.
    fn resend_control(&mut self) {
        let now = Instant::now();
        let due: Vec<u64> = self
            .ctrl_unacked
            .iter()
            .filter(|(_, (_, _, last))| now.duration_since(*last) >= CTRL_RESEND)
            .map(|(seq, _)| *seq)
            .collect();
        for seq in due {
            let Some((frame, first, _)) = self.ctrl_unacked.get(&seq).cloned() else {
                continue;
            };
            if now.duration_since(first) > CTRL_GIVE_UP {
                tracing::warn!("[overlay session] {}: no receipt for a control frame in {CTRL_GIVE_UP:?}; closing", self.peer_node_id);
                self.stopped = true;
                return;
            }
            let sent = self.dispatch(&frame);
            tracing::trace!(
                "[overlay session] {}: control {:#04x} seq {seq} resent (sent {sent})",
                self.peer_node_id,
                frame.kind
            );
            if let Some(entry) = self.ctrl_unacked.get_mut(&seq) {
                entry.2 = now;
            }
        }
    }

    /// A control frame arrived: send its receipt, and say whether to act on it (false for a
    /// copy we have already acted on).
    fn admit_control(&mut self, frame: &Frame) -> bool {
        let receipt = Self::encode(&CtrlAck { seq: frame.seq });
        self.send_frame(kind::CTRL_ACK, receipt, false);
        let first = self.ctrl_seen.insert(frame.seq);
        tracing::trace!(
            "[overlay session] {}: control {:#04x} seq {} {}",
            self.peer_node_id,
            frame.kind,
            frame.seq,
            if first { "arrived" } else { "arrived again" }
        );
        // Bounded: a copy can only come within the sender's resend budget, far fewer frames than this.
        while self.ctrl_seen.len() > CTRL_REMEMBERED {
            self.ctrl_seen.pop_first();
        }
        first
    }

    /// Put a frame on the best live route; a mirrored frame also goes out on every other one.
    fn dispatch(&mut self, frame: &Frame) -> bool {
        let refs: Vec<&Arc<dyn Link>> = self.links.iter().collect();
        let Some(best) = crate::link::best_route(&refs) else {
            return false;
        };
        let mirrored = frame.is_mirrored();
        let sent = best.send(frame).is_ok();
        if mirrored {
            for other in self
                .links
                .iter()
                .filter(|l| l.id() != best.id() && l.is_up())
            {
                let _ = other.send(frame);
            }
        }
        sent
    }

    /// The route a bulk frame should go out on: striped, weighted by measured throughput.
    ///
    /// The route with the least (used share − bandwidth share) skew wins, which spreads bulk
    /// traffic across every healthy path instead of hammering the fastest one.
    fn route_for_bulk(&mut self) -> Option<usize> {
        let live: Vec<Arc<dyn Link>> = self.links.iter().filter(|l| l.is_up()).cloned().collect();
        if live.is_empty() {
            return None;
        }
        let total: f64 = live
            .iter()
            .map(|l| (l.stats().metrics().mbps * 1_000.0).max(1.0))
            .sum();
        let mut best: Option<(usize, f64)> = None;
        for (i, link) in live.iter().enumerate() {
            let m = link.stats().metrics();
            let share = (m.mbps * 1_000.0).max(1.0) / total;
            let sent = link.stats().frames_sent().max(1) as f64;
            let used = m.active as f64 / sent;
            let skew = used - share;
            if best.map(|(_, b)| skew < b).unwrap_or(true) {
                best = Some((i, skew));
            }
        }
        let index = best.map(|(i, _)| i)?;
        self.links.iter().position(|l| Arc::ptr_eq(l, &live[index]))
    }

    fn data_frame(&mut self, f: &OutFrame, mirrored: bool) -> Frame {
        let body = Self::encode(&Data {
            stream: f.stream.0,
            seq: f.seq,
            fin: f.fin,
            payload: f.payload.clone(),
        });
        let seq = self.next_seq();
        let mut flags = 0;
        if f.payload.len() >= BULK_THRESHOLD {
            flags |= protocol::flags::BULK;
        }
        if mirrored {
            flags |= protocol::flags::MIRROR;
        }
        Frame {
            version: self.version,
            kind: kind::DATA,
            flags,
            seq,
            body,
        }
    }

    fn routes(&self) -> Vec<RouteReport> {
        self.links
            .iter()
            .map(|l| {
                let m = l.stats().metrics();
                RouteReport {
                    kind: l.kind().as_str().to_string(),
                    rtt_ms: round3(m.rtt_ms),
                    loss: round3(m.loss),
                    mbps: round3(m.mbps),
                    active: m.up,
                }
            })
            .collect()
    }

    async fn handle_command(&mut self, cmd: SessionCommand) {
        match cmd {
            SessionCommand::Shutdown => self.stopped = true,
            SessionCommand::Punch { msg } => {
                self.send_frame(kind::CANDIDATE, Self::encode(&msg), false);
            }
            SessionCommand::Advertise { services } => {
                self.local.services = services;
                let hello = Self::encode(&self.local);
                self.send_frame(kind::HELLO, hello, false);
            }
            SessionCommand::AddLink { link } => {
                if !self.links.iter().any(|l| l.id() == link.id()) {
                    link.set_waker(self.wake.clone());
                    let up = link.is_up();
                    let kind = link.kind();
                    let peer = self.peer_node_id.clone();
                    self.links.push(link);
                    let _ = self
                        .events
                        .send(SessionEvent::RouteChanged { peer, kind, up });
                }
            }
            SessionCommand::Open { service, reply } => {
                let stream = self.mux.open(service.clone());
                let body = Self::encode(&Open {
                    stream: stream.0,
                    service: service.clone(),
                    node_id: self.local.node_id.clone(),
                });
                tracing::debug!(
                    "[overlay session] {}: open stream {} for {service}",
                    self.peer_node_id,
                    stream.0
                );
                if self.send_frame(kind::OPEN, body, false) {
                    // Answered by the peer's OPEN_OK or OPEN_ERR.
                    self.awaiting_open.insert(stream.0, (service, reply));
                } else {
                    self.mux.remove_send(stream);
                    self.mux.remove_recv(stream);
                    let _ = reply.try_send(Err(OverlayError::Unreachable {
                        node: self.peer_node_id.clone(),
                    }));
                }
            }
            SessionCommand::Send { stream, bytes, fin } => {
                let queue = self.write_queue.entry(stream.0).or_default();
                if !bytes.is_empty() {
                    queue.chunks.push_back(bytes);
                }
                if fin && !queue.fin {
                    // The end of the stream travels as its own empty frame, after every byte before it.
                    queue.fin = true;
                    queue.chunks.push_back(Vec::new());
                }
                self.pump(stream);
            }
            SessionCommand::Recv { stream, reply } => {
                if self.mux.recv_side(stream).is_none() {
                    // No such stream (closed, refused, never opened): the end, not a wait forever.
                    let _ = reply.try_send(None);
                    return;
                }
                let ready = self.mux.recv_side(stream).and_then(|r| r.take());
                let ended = self
                    .mux
                    .recv_side(stream)
                    .map(|r| r.finished() && r.buffered() == 0)
                    .unwrap_or(true);
                if ready.is_none() && ended {
                    // The peer ended the stream and everything has been read: end of stream.
                    let _ = reply.try_send(None);
                    return;
                }
                match ready {
                    Some(bytes) => {
                        let granted = self
                            .mux
                            .recv_side(stream)
                            .map(|r| r.window_update())
                            .unwrap_or(0);
                        let _ = reply.try_send(Some(bytes));
                        self.grant_window(stream, granted);
                    }
                    None => {
                        self.pending_reads.insert(stream.0, PendingRead(reply));
                    }
                }
            }
            SessionCommand::Authorize {
                stream,
                service,
                ok,
                reason,
            } => {
                tracing::debug!(
                    "[overlay session] {}: stream {} for {service}: {}",
                    self.peer_node_id,
                    stream.0,
                    if ok { "accepted" } else { reason.as_str() }
                );
                if self.pending_opens.remove(&stream.0).is_none() {
                    // The peer closed it before we decided: nothing to accept or refuse.
                    tracing::debug!(
                        "[overlay session] {}: no open pending for stream {}",
                        self.peer_node_id,
                        stream.0
                    );
                    return;
                }
                if ok {
                    self.mux.accept(stream, service);
                    let body = Self::encode(&OpenOk {
                        stream: stream.0,
                        route: self.best_route_name(),
                    });
                    self.send_frame(kind::OPEN_OK, body, false);
                } else {
                    // The code tells the opener which refusal this was; the reason says it in words.
                    let code = match reason.as_str() {
                        "no such service" => "no_such_service",
                        r if r.contains("a minute") => "rate_limited",
                        _ => "denied",
                    };
                    let body = Self::encode(&OpenErr {
                        stream: stream.0,
                        code: code.into(),
                        reason,
                    });
                    self.send_frame(kind::OPEN_ERR, body, false);
                }
            }
            SessionCommand::Close { stream } => {
                tracing::debug!(
                    "[overlay session] {}: closing stream {} (asked here)",
                    self.peer_node_id,
                    stream.0
                );
                let body = Self::encode(&Close {
                    stream: stream.0,
                    code: "closed".into(),
                    reason: String::new(),
                });
                self.send_frame(kind::CLOSE, body, false);
                self.mux.remove_send(stream);
                self.mux.remove_recv(stream);
                self.pending_reads.remove(&stream.0);
            }
        }
    }

    fn grant_window(&mut self, stream: StreamId, credit: u64) {
        if credit > 0 {
            let body = Self::encode(&Window {
                stream: stream.0,
                credit,
            });
            self.send_frame(kind::WINDOW, body, false);
        }
    }

    /// Frame whatever the stream's window allows. Anything left waits for credit: this is the
    /// point where a slow peer slows the writer down instead of losing data.
    fn pump(&mut self, stream: StreamId) {
        let now = Instant::now();
        loop {
            let chunk = match self.write_queue.get_mut(&stream.0) {
                Some(q) => q.chunks.pop_front(),
                None => return,
            };
            let Some(chunk) = chunk else { return };
            let last = self
                .write_queue
                .get(&stream.0)
                .map(|q| q.fin && q.chunks.is_empty())
                .unwrap_or(false);
            let frames = match self.mux.send_side(stream) {
                Some(s) => s.frame(&chunk, last),
                None => return,
            };
            // The window may take only part of the chunk (or none of it): the rest goes back to the
            // front of the queue and waits for credit. Dropping it would lose bytes from the middle.
            let taken: usize = frames.iter().map(|f| f.payload.len()).sum();
            if taken < chunk.len() {
                if let Some(q) = self.write_queue.get_mut(&stream.0) {
                    q.chunks.push_front(chunk[taken..].to_vec());
                }
            }
            if frames.is_empty() {
                return;
            }
            let window_closed = taken < chunk.len();
            let bulk = chunk.len() >= BULK_THRESHOLD;
            for f in frames {
                let frame = self.data_frame(&f, false);
                let target = if bulk { self.route_for_bulk() } else { None };
                let sent = match target.and_then(|i| self.links.get(i).cloned()) {
                    Some(link) => link.send(&frame).is_ok(),
                    None => self.dispatch(&frame),
                };
                tracing::trace!(
                    "[overlay session] {}: send stream {} seq {} ok {sent}",
                    self.peer_node_id,
                    f.stream.0,
                    f.seq
                );
                // Timed from now either way: a frame no route would take is the resend's to send.
                self.sent_at.insert((f.stream.0, f.seq), now);
            }
            if window_closed {
                return; // the rest waits for a WINDOW from the peer
            }
            let done = self
                .write_queue
                .get(&stream.0)
                .map(|q| q.chunks.is_empty())
                .unwrap_or(true);
            if done {
                self.write_queue.remove(&stream.0);
                return;
            }
        }
    }

    async fn tick(&mut self) {
        self.drain_inbound().await;
        self.probe();
        self.resend_control();
        // Republish the measurements so `overlay.peers` and group placement see current numbers.
        *self.handle_routes.write() = self.routes();
        if self.ready {
            self.resend_stale();
        }
    }

    async fn drain_inbound(&mut self) {
        let links = self.links.clone();
        for link in links {
            // Bounded per pass so one busy route cannot starve the others; a route that had more
            // wakes the session again for another pass.
            for taken in 0..=64 {
                if taken == 64 {
                    self.wake.notify_one();
                    break;
                }
                match link.try_recv() {
                    // A ping is answered on the route it came in on, so the answer measures that
                    // route and not whichever one is best right now.
                    Some(frame) if frame.kind == kind::PING => self.answer_ping(&frame, &link),
                    Some(frame) if protocol::is_reliable(frame.kind) => {
                        if self.admit_control(&frame) {
                            self.on_frame(&frame);
                        }
                    }
                    Some(frame) => self.on_frame(&frame),
                    None => break,
                }
            }
            if !link.is_up() {
                link.mark_down();
            }
        }
        // Hand over anything a pending read was waiting for.
        let waiting: Vec<u64> = self.pending_reads.keys().copied().collect();
        for id in waiting {
            let Some(recv) = self.mux.recv_side(StreamId(id)) else {
                continue;
            };
            let Some(bytes) = recv.take() else { continue };
            let granted = recv.window_update();
            if let Some(PendingRead(reply)) = self.pending_reads.remove(&id) {
                let _ = reply.try_send(Some(bytes));
            }
            self.grant_window(StreamId(id), granted);
        }
    }

    /// The session is up: record what the peer told us and tell the node.
    fn become_ready(&mut self, version: u16, name: String, services: Vec<protocol::ServiceInfo>) {
        self.version = version as u8;
        self.services = services.clone();
        *self.handle_services.write() = services.clone();
        *self.handle_name.write() = name;
        *self.handle_version.write() = version;
        *self.handle_routes.write() = self.routes();
        if self.ready {
            return;
        }
        tracing::info!(
            "[overlay session] {} is up: protocol v{version}",
            self.peer_node_id
        );
        self.ready = true;
        let peer = self.peer_node_id.clone();
        let _ = self.events.send(SessionEvent::Ready {
            peer,
            version,
            services,
        });
        // Tell the peer what we can do, so it can place streams too.
        let routes = Self::encode(&Routes {
            routes: self.routes(),
        });
        self.send_frame(kind::ROUTES, routes, false);
    }

    fn on_frame(&mut self, frame: &Frame) {
        match frame.kind {
            kind::HELLO => {
                let Ok(hello) = frame.decode::<Hello>() else {
                    return;
                };
                if hello.node_id == self.peer_node_id {
                    let _ = self.events.send(SessionEvent::Hello {
                        peer: self.peer_node_id.clone(),
                        name: hello.name.clone(),
                        ext: hello.ext.clone(),
                    });
                }
                // The handshake already proved who is on the other end; a hello claiming to be
                // someone else is refused rather than believed.
                let agreed = if hello.node_id != self.peer_node_id {
                    Err(format!(
                        "the hello names {} but the handshake proved {}",
                        hello.node_id, self.peer_node_id
                    ))
                } else {
                    protocol::negotiate(
                        hello.min_version,
                        hello.max_version,
                        self.local.min_version,
                        self.local.max_version,
                    )
                    .ok_or_else(|| {
                        format!(
                            "no common protocol version: it speaks {}, we speak {}-{}",
                            hello.range(),
                            self.local.min_version,
                            self.local.max_version
                        )
                    })
                };
                let ack = HelloAck {
                    version: *agreed.as_ref().unwrap_or(&0),
                    node_id: self.local.node_id.clone(),
                    name: self.local.name.clone(),
                    services: self.local.services.clone(),
                    nonce: hello.nonce,
                    reason: agreed.as_ref().err().cloned().unwrap_or_default(),
                    ext: Vec::new(),
                };
                self.send_frame(kind::HELLO_ACK, Self::encode(&ack), false);
                match agreed {
                    Ok(version) => self.become_ready(version, hello.name, hello.services),
                    Err(reason) => {
                        tracing::warn!("[overlay session] refused {}: {reason}", self.peer_node_id);
                        self.stopped = true;
                        let _ = self.events.send(SessionEvent::Refused {
                            peer: self.peer_node_id.clone(),
                            reason,
                        });
                    }
                }
            }
            kind::HELLO_ACK => {
                let Ok(ack) = frame.decode::<HelloAck>() else {
                    return;
                };
                if ack.nonce != self.local.nonce {
                    tracing::debug!(
                        "[overlay session] a hello answer from {} for another hello",
                        self.peer_node_id
                    );
                    return;
                }
                if ack.version == 0 {
                    tracing::warn!(
                        "[overlay session] {} refused us: {}",
                        self.peer_node_id,
                        ack.reason
                    );
                    self.stopped = true;
                    let _ = self.events.send(SessionEvent::Refused {
                        peer: self.peer_node_id.clone(),
                        reason: ack.reason.clone(),
                    });
                    return;
                }
                self.become_ready(ack.version, ack.name, ack.services);
            }
            kind::OPEN => {
                let Ok(open) = frame.decode::<Open>() else {
                    return;
                };
                if !self.mux.is_peer_stream(StreamId(open.stream))
                    || self.pending_opens.contains_key(&open.stream)
                {
                    let body = Self::encode(&OpenErr {
                        stream: open.stream,
                        code: "protocol".into(),
                        reason: "that stream id is not yours to open".into(),
                    });
                    self.send_frame(kind::OPEN_ERR, body, false);
                    return;
                }
                // Ask the node first: the ACL lives there, and a refused peer must never reach
                // a local socket.
                let peer = self.peer_node_id.clone();
                let _ = self.events.send(SessionEvent::OpenRequest {
                    peer,
                    stream: StreamId(open.stream),
                    service: open.service.clone(),
                });
                self.pending_opens.insert(open.stream, open.service);
            }
            kind::OPEN_OK => {
                let Ok(ok) = frame.decode::<OpenOk>() else {
                    return;
                };
                tracing::debug!(
                    "[overlay session] {}: stream {} accepted by the peer",
                    self.peer_node_id,
                    ok.stream
                );
                if let Some((_, reply)) = self.awaiting_open.remove(&ok.stream) {
                    let _ = reply.try_send(Ok(StreamId(ok.stream)));
                }
            }
            kind::OPEN_ERR => {
                let Ok(err) = frame.decode::<OpenErr>() else {
                    return;
                };
                tracing::debug!(
                    "[overlay session] {}: the peer refused stream {}: {}",
                    self.peer_node_id,
                    err.stream,
                    err.reason
                );
                if let Some((service, reply)) = self.awaiting_open.remove(&err.stream) {
                    let refusal = match err.code.as_str() {
                        "no_such_service" => OverlayError::NoSuchService { service },
                        "rate_limited" => OverlayError::RateLimited {
                            service,
                            reason: err.reason.clone(),
                        },
                        "denied" => OverlayError::Denied {
                            node: self.local.node_id.clone(),
                            service,
                        },
                        _ => OverlayError::Closed(format!(
                            "{} refused the stream: {}",
                            self.peer_node_id, err.reason
                        )),
                    };
                    let _ = reply.try_send(Err(refusal));
                }
                self.mux.remove_send(StreamId(err.stream));
                self.mux.remove_recv(StreamId(err.stream));
                if let Some(PendingRead(reply)) = self.pending_reads.remove(&err.stream) {
                    let _ = reply.try_send(None);
                }
            }
            kind::DATA => {
                let Ok(data) = frame.decode::<Data>() else {
                    return;
                };
                let fin = data.fin;
                let stream = data.stream;
                let seq = data.seq;
                tracing::trace!(
                    "[overlay session] {}: data stream {stream} seq {seq} fin {fin}",
                    self.peer_node_id
                );
                let out = OutFrame {
                    stream: StreamId(stream),
                    seq,
                    payload: data.payload,
                    fin,
                };
                let delivered = match self.mux.recv_side(StreamId(stream)) {
                    Some(recv) => !recv.accept(out).is_empty(),
                    // Not a stream we have (yet): no acknowledgement, so the sender sends it again
                    // rather than believing it arrived.
                    None => {
                        tracing::debug!(
                            "[overlay session] {}: data for unknown stream {stream}",
                            self.peer_node_id
                        );
                        return;
                    }
                };
                // The end of the stream is taken in order by `accept`: closing here on a FIN that
                // overtook earlier frames would throw those frames away.
                // Cumulative, and sent for a duplicate too: a lost acknowledgement is repaired by
                // the resend it causes.
                let next = self
                    .mux
                    .recv_side(StreamId(stream))
                    .map(|r| r.next_expected())
                    .unwrap_or(0);
                let ack = Self::encode(&Ack { stream, seq: next });
                self.send_frame(kind::ACK, ack, false);
                if delivered {
                    self.wake_reader(stream);
                }
                if fin {
                    self.end_reader(stream);
                }
            }
            kind::ACK => {
                let Ok(ack) = frame.decode::<Ack>() else {
                    return;
                };
                if let Some(send) = self.mux.send_side(StreamId(ack.stream)) {
                    send.ack_below(ack.seq);
                }
                self.sent_at
                    .retain(|(s, q), _| *s != ack.stream || *q >= ack.seq);
            }
            kind::WINDOW => {
                let Ok(w) = frame.decode::<Window>() else {
                    return;
                };
                if let Some(send) = self.mux.send_side(StreamId(w.stream)) {
                    send.grant(w.credit);
                }
                // Credit arrived: whatever was waiting behind the window goes now.
                self.pump(StreamId(w.stream));
            }
            kind::CLOSE => {
                let Ok(c) = frame.decode::<Close>() else {
                    return;
                };
                tracing::debug!(
                    "[overlay session] {}: the peer closed stream {}",
                    self.peer_node_id,
                    c.stream
                );
                self.pending_opens.remove(&c.stream);
                self.mux.remove_send(StreamId(c.stream));
                if let Some(recv) = self.mux.recv_side(StreamId(c.stream)) {
                    recv.close();
                }
                if let Some(PendingRead(reply)) = self.pending_reads.remove(&c.stream) {
                    let _ = reply.try_send(None);
                }
            }
            kind::PONG => {
                let Ok(pong) = frame.decode::<Pong>() else {
                    return;
                };
                let Some((route, sent)) = self.pings.remove(&pong.nonce) else {
                    return;
                };
                let rtt = sent.elapsed().as_secs_f64() * 1000.0;
                if let Some(link) = self.links.iter().find(|l| l.id() == route) {
                    link.stats().probe_ok(rtt);
                }
                self.misses.remove(&route);
            }
            kind::ROUTES => {
                // The peer's routes are informational: our own measurements decide where our
                // frames go, so a peer cannot talk us onto a worse path.
                let _ = frame.decode::<Routes>();
            }
            kind::CTRL_ACK => {
                if let Ok(receipt) = frame.decode::<CtrlAck>() {
                    self.ctrl_unacked.remove(&receipt.seq);
                }
            }
            kind::CANDIDATE => {
                // A build that agreed on less than the punch version never acts on one.
                if (self.version as u16) < protocol::VERSION_PUNCH {
                    return;
                }
                if let Ok(msg) = frame.decode::<PunchMsg>() {
                    let _ = self.events.send(SessionEvent::Punch {
                        peer: self.peer_node_id.clone(),
                        msg,
                    });
                }
            }
            kind::BYE => self.stopped = true,
            _ => {}
        }
    }

    fn answer_ping(&mut self, frame: &Frame, link: &Arc<dyn Link>) {
        let Ok(ping) = frame.decode::<Ping>() else {
            return;
        };
        let body = Self::encode(&Pong {
            nonce: ping.nonce,
            sent_us: ping.sent_us,
        });
        let seq = self.next_seq();
        let pong = Frame {
            version: self.version,
            kind: kind::PONG,
            flags: 0,
            seq,
            body,
        };
        if link.send(&pong).is_err() {
            // The route cannot take even a pong: answer on the best one rather than not at all.
            self.dispatch(&pong);
        }
    }

    /// Tell a waiting reader the stream has ended, once nothing is left to read.
    fn end_reader(&mut self, stream: u64) {
        let ended = self
            .mux
            .recv_side(StreamId(stream))
            .map(|r| r.finished() && r.buffered() == 0)
            .unwrap_or(true);
        if ended {
            if let Some(PendingRead(reply)) = self.pending_reads.remove(&stream) {
                let _ = reply.try_send(None);
            }
        }
    }

    /// Hand buffered bytes to a reader that is waiting for them. With nobody waiting they stay
    /// buffered for the next `recv`: taking them out here would drop them.
    fn wake_reader(&mut self, stream: u64) {
        if !self.pending_reads.contains_key(&stream) {
            return;
        }
        let Some(recv) = self.mux.recv_side(StreamId(stream)) else {
            return;
        };
        let Some(bytes) = recv.take() else { return };
        let granted = recv.window_update();
        if let Some(PendingRead(reply)) = self.pending_reads.remove(&stream) {
            let _ = reply.try_send(Some(bytes));
        }
        self.grant_window(StreamId(stream), granted);
    }

    fn best_route_name(&self) -> String {
        let refs: Vec<&Arc<dyn Link>> = self.links.iter().collect();
        crate::link::best_route(&refs)
            .map(|l| l.kind().as_str().to_string())
            .unwrap_or_default()
    }

    /// Re-send what the peer has not acknowledged, on a route other than the one it went out
    /// on: the mechanism that makes a route failure invisible to the application.
    fn resend_stale(&mut self) {
        let now = Instant::now();
        let stale: Vec<OutFrame> = self
            .mux
            .pending_retransmits()
            .into_iter()
            .filter(|f| {
                self.sent_at
                    .get(&(f.stream.0, f.seq))
                    .map(|t| now.duration_since(*t) >= RESEND_AFTER)
                    .unwrap_or(false)
            })
            .collect();
        for f in stale {
            tracing::trace!(
                "[overlay session] {}: resend stream {} seq {}",
                self.peer_node_id,
                f.stream.0,
                f.seq
            );
            let frame = self.data_frame(&f, true);
            let target = self.route_for_bulk();
            let sent = match target.and_then(|i| self.links.get(i).cloned()) {
                Some(link) => link.send(&frame).is_ok(),
                None => self.dispatch(&frame),
            };
            if sent {
                self.sent_at.insert((f.stream.0, f.seq), now);
            }
        }
    }

    fn probe(&mut self) {
        let now = Instant::now();
        for link in self.links.clone() {
            let due = self
                .last_probe
                .get(&link.id())
                .map(|t| now.duration_since(*t) >= PROBE_EVERY)
                .unwrap_or(true);
            if !due {
                continue;
            }
            self.last_probe.insert(link.id(), now);
            // Once per probe round: the loss and throughput estimates are over the last round.
            link.stats().refresh_loss();
            link.stats().refresh_bandwidth();
            // The nonce carries the route, so the answer is credited to the route it came from.
            let nonce = now_micros() ^ ((link.id() as u64) << 40);
            self.pings.insert(nonce, (link.id(), now));
            link.stats().probe_sent();
            let body = Self::encode(&Ping {
                nonce,
                sent_us: now_micros(),
            });
            let seq = self.next_seq();
            let frame = Frame {
                version: self.version,
                kind: kind::PING,
                flags: 0,
                seq,
                body,
            };
            let _ = link.send(&frame);
        }
        // A ping whose answer never came is a miss; a route that misses several in a row is down
        // until a frame arrives on it again.
        let stale: Vec<u64> = self
            .pings
            .iter()
            .filter(|(_, (_, sent))| now.duration_since(*sent) > RESEND_AFTER * 4)
            .map(|(nonce, _)| *nonce)
            .collect();
        for nonce in stale {
            let Some((route, _)) = self.pings.remove(&nonce) else {
                continue;
            };
            let misses = self.misses.entry(route).or_default();
            *misses += 1;
            if *misses >= MISSES_DOWN {
                if let Some(link) = self.links.iter().find(|l| l.id() == route) {
                    tracing::trace!(
                        "[overlay session] {}: route {} marked down (no pong)",
                        self.peer_node_id,
                        link.kind().as_str()
                    );
                    link.stats().mark_down();
                }
            }
        }
    }
}

fn round3(v: f64) -> f64 {
    (v * 1000.0).round() / 1000.0
}

fn now_micros() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64
}

/// A counter shared with the application side of a stream, for byte accounting.
pub type StreamBytes = Arc<AtomicU64>;

/// Increase a shared byte counter.
pub fn count(bytes: &StreamBytes, n: u64) {
    bytes.fetch_add(n, Ordering::Relaxed);
}
