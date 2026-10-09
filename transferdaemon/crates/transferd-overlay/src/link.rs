//! Routes: the paths to a peer, their measured quality, and the plug-in trait that adds new
//! media without a protocol break.
//!
//! A [`Link`] is one *authenticated, outbound* path to a peer. The overlay never opens an
//! inbound listener for overlay traffic: every link is dialled by us and the peer answers on
//! the same connection (or, for a relay, on a connection it made earlier). That is what makes
//! the overlay work behind NAT and CGNAT with no firewall change at all.
//!
//! Adding a new medium (a serial line, a satellite link, a QUIC transport) means implementing
//! [`LinkTransport`] and registering it — no wire change, no session change. See
//! `docs/PROTOCOL.md`.

use async_trait::async_trait;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::error::{OverlayError, Result};
use crate::protocol::{Frame, FrameReader};

/// The kind of path a link is, as reported by `overlay.peers`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RouteKind {
    /// A plain TCP connection we dialled to an address the peer published.
    Direct,
    /// A TCP connection to an address on the same local network.
    Lan,
    /// A UDP path opened by hole punching (no inbound port was ever needed).
    HolePunch,
    /// A blind UDP relay (`relayd`).
    Relay,
    /// A blind WebSocket relay (`relayd-ws`, or a Cloudflare Worker).
    WsRelay,
    /// A direct connection over a Tailscale address.
    Tailscale,
}

impl RouteKind {
    /// The wire name, as used in `overlay.peers[].routes[].kind`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Lan => "lan",
            Self::HolePunch => "holepunch",
            Self::Relay => "relay",
            Self::WsRelay => "ws_relay",
            Self::Tailscale => "tailscale",
        }
    }

    /// Parse a wire name.
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "direct" => Self::Direct,
            "lan" => Self::Lan,
            "holepunch" => Self::HolePunch,
            "relay" => Self::Relay,
            "ws_relay" => Self::WsRelay,
            "tailscale" => Self::Tailscale,
            _ => return None,
        })
    }

    /// The `scheme://` prefix this kind is published with, when it has one.
    pub fn scheme(self) -> Option<&'static str> {
        match self {
            Self::Direct | Self::Lan | Self::Tailscale => Some("tcp"),
            Self::HolePunch => Some("udp"),
            Self::Relay => Some("relay"),
            Self::WsRelay => Some("wsrelay"),
        }
    }

    /// Routes that are worth preferring when both work: cheaper is better.
    pub fn rank(self) -> u8 {
        match self {
            Self::Lan => 0,
            Self::Tailscale => 1,
            Self::HolePunch => 2,
            Self::Direct => 3,
            Self::Relay => 5,
            Self::WsRelay => 6,
        }
    }
}

/// What we measured about one route. Exposed to apps through `overlay.peers`.
#[derive(Debug, Clone, Copy, Default)]
pub struct RouteMetrics {
    /// Smoothed round-trip time in milliseconds.
    pub rtt_ms: f64,
    /// Fraction of probes lost in the last window, 0.0 ..= 1.0.
    pub loss: f64,
    /// Smoothed throughput in megabits per second.
    pub mbps: f64,
    /// Frames handed to this route and not yet acknowledged by the peer.
    pub active: u64,
    /// Whether the route is usable right now.
    pub up: bool,
}

impl RouteMetrics {
    /// The score the router minimises: time to push the next frame out on this route.
    ///
    /// Loss is charged quadratically because a lossy route costs a retransmit, and a dead
    /// route must never win no matter how good its old numbers were.
    pub fn cost(&self) -> f64 {
        if !self.up {
            return f64::INFINITY;
        }
        let bps = (self.mbps * 1_000_000.0).max(1.0);
        self.rtt_ms + self.active as f64 / bps * 1000.0 + self.loss * self.loss * 1000.0
    }
}

/// Rolling statistics for one route, updated by the prober and by real traffic.
#[derive(Debug)]
pub struct RouteStats {
    kind: RouteKind,
    rtt_ms: Mutex<f64>,
    loss: Mutex<f64>,
    mbps: Mutex<f64>,
    active: AtomicU64,
    up: AtomicBool,
    sent: AtomicU64,
    bytes: AtomicU64,
    last_bytes: AtomicU64,
    last_sample: Mutex<Instant>,
    /// Probes sent and probes answered in the current window.
    probes_sent: AtomicU64,
    probes_ok: AtomicU64,
}

impl RouteStats {
    /// Fresh statistics for a route of this kind.
    pub fn new(kind: RouteKind) -> Self {
        Self {
            kind,
            rtt_ms: Mutex::new(0.0),
            loss: Mutex::new(0.0),
            mbps: Mutex::new(0.0),
            active: AtomicU64::new(0),
            up: AtomicBool::new(true),
            sent: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            last_bytes: AtomicU64::new(0),
            last_sample: Mutex::new(Instant::now()),
            probes_sent: AtomicU64::new(0),
            probes_ok: AtomicU64::new(0),
        }
    }

    pub fn kind(&self) -> RouteKind {
        self.kind
    }

    /// Fold a round-trip measurement in (exponential average, so one spike does not dominate).
    pub fn record_rtt(&self, ms: f64) {
        if let Ok(mut cur) = self.rtt_ms.lock() {
            *cur = if *cur <= 0.0 {
                ms
            } else {
                *cur * 0.7 + ms * 0.3
            };
        }
    }

    /// Count one probe sent.
    pub fn probe_sent(&self) {
        self.probes_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Count one probe answered, and fold in the round-trip time.
    pub fn probe_ok(&self, rtt_ms: f64) {
        self.probes_ok.fetch_add(1, Ordering::Relaxed);
        self.record_rtt(rtt_ms);
        self.mark_up();
    }

    /// Recompute the loss estimate. Called once per probe round.
    pub fn refresh_loss(&self) {
        let (sent, ok) = (
            self.probes_sent.load(Ordering::Relaxed),
            self.probes_ok.load(Ordering::Relaxed),
        );
        let estimate = if sent == 0 {
            0.0
        } else {
            1.0 - (ok as f64 / sent as f64).min(1.0)
        };
        if let Ok(mut cur) = self.loss.lock() {
            *cur = (*cur * 0.5).max(0.0) + estimate * 0.5;
        }
        self.probes_sent.store(0, Ordering::Relaxed);
        self.probes_ok.store(0, Ordering::Relaxed);
    }

    /// Record `bytes` handed to this route.
    pub fn record_sent(&self, bytes: u64) {
        self.sent.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(bytes, Ordering::Relaxed);
        self.active.fetch_add(1, Ordering::Relaxed);
    }

    /// Record `n` frames acknowledged by the peer.
    pub fn record_acked(&self, n: u64) {
        let _ = self
            .active
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |a| {
                Some(a.saturating_sub(n))
            });
    }

    /// Recompute throughput from the byte counter. Called once per health tick.
    pub fn refresh_bandwidth(&self) {
        let total = self.bytes.load(Ordering::Relaxed);
        let prev = self.last_bytes.swap(total, Ordering::Relaxed);
        let elapsed = {
            let mut last = self.last_sample.lock().unwrap_or_else(|e| e.into_inner());
            let now = Instant::now();
            let d = now.duration_since(*last).as_secs_f64().max(0.001);
            *last = now;
            d
        };
        let bps = (total.saturating_sub(prev) as f64 * 8.0) / elapsed;
        if let Ok(mut cur) = self.mbps.lock() {
            *cur = if *cur <= 0.0 {
                bps / 1_000_000.0
            } else {
                *cur * 0.7 + (bps / 1_000_000.0) * 0.3
            };
        }
    }

    /// The route stopped working.
    pub fn mark_down(&self) {
        self.up.store(false, Ordering::Relaxed);
    }

    /// The route answered again.
    pub fn mark_up(&self) {
        self.up.store(true, Ordering::Relaxed);
    }

    /// A snapshot for `overlay.peers`.
    pub fn metrics(&self) -> RouteMetrics {
        RouteMetrics {
            rtt_ms: *self.rtt_ms.lock().unwrap_or_else(|e| e.into_inner()),
            loss: *self.loss.lock().unwrap_or_else(|e| e.into_inner()),
            mbps: *self.mbps.lock().unwrap_or_else(|e| e.into_inner()),
            active: self.active.load(Ordering::Relaxed),
            up: self.up.load(Ordering::Relaxed),
        }
    }

    /// Frames sent on this route since it was created.
    pub fn frames_sent(&self) -> u64 {
        self.sent.load(Ordering::Relaxed)
    }
}

/// One authenticated path to a peer.
pub trait Link: Send + Sync {
    /// What kind of path this is.
    fn kind(&self) -> RouteKind;

    /// A stable identifier, unique within a session (`overlay.status.lanes`).
    fn id(&self) -> u32;

    /// This route's measurements.
    fn stats(&self) -> &Arc<RouteStats>;

    /// Send one frame.
    ///
    /// Deliberately not `async`: sealing the frame and queueing it for the writer task are
    /// both immediate, so a route never blocks the session tick on a socket. When the queue is
    /// full the route reports congestion and the router picks another one.
    fn send(&self, frame: &Frame) -> Result<()>;

    /// Take one received frame, if any is buffered. Never blocks.
    fn try_recv(&self) -> Option<Frame>;

    /// Whether the route is usable.
    fn is_up(&self) -> bool;

    /// Mark the route dead (called when a send fails or probes stop being answered).
    fn mark_down(&self);

    /// A human-readable address for diagnostics.
    fn describe(&self) -> String;

    /// Who to wake when a frame arrives, so the session reads it at once instead of at its next
    /// tick. A link that cannot tell (polled only) keeps the default and is read on the tick.
    fn set_waker(&self, _waker: Arc<tokio::sync::Notify>) {}

    /// Whether the link is gone for good (its transport closed), as opposed to merely down
    /// (not answering probes for now).
    fn is_closed(&self) -> bool {
        false
    }
}

/// A plug-in that builds links for one medium.
///
/// This is the extension point the protocol promises: a new transport registers here and the
/// overlay can use it with no wire change, because the frames are identical on every medium.
#[async_trait]
pub trait LinkTransport: Send + Sync {
    /// A short name, used in logs and in `overlay.status`.
    fn name(&self) -> &'static str;

    /// The `scheme://` this transport serves (`tcp`, `relay`, `udp`, ...).
    fn scheme(&self) -> &'static str;

    /// Whether this transport can reach a node we have never dialled before
    /// (a rendezvous can; a plain socket cannot).
    fn needs_rendezvous(&self) -> bool {
        false
    }

    /// Dial a peer. `target` is the transport-specific endpoint (a `host:port`, a relay
    /// address, a `ws://` url...).
    async fn connect(&self, target: &str) -> Result<Box<dyn Link>>;
}

/// The registry of plug-ins, consulted when a route of an unknown scheme is needed.
#[derive(Default)]
pub struct LinkRegistry {
    transports: Vec<Box<dyn LinkTransport>>,
}

impl LinkRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a transport. Later registrations win for a duplicate scheme.
    pub fn register(&mut self, transport: Box<dyn LinkTransport>) {
        self.transports.push(transport);
    }

    /// Find a transport by scheme.
    pub fn find(&self, scheme: &str) -> Option<&dyn LinkTransport> {
        self.transports
            .iter()
            .rev()
            .find(|t| t.scheme() == scheme)
            .map(|t| t.as_ref())
    }

    /// Every registered scheme.
    pub fn schemes(&self) -> Vec<&'static str> {
        self.transports.iter().map(|t| t.scheme()).collect()
    }

    /// Build a link for `scheme://target`, if the scheme is registered.
    pub async fn open(&self, target: &str) -> Result<Box<dyn Link>> {
        let (scheme, rest) = target
            .split_once("://")
            .ok_or_else(|| OverlayError::protocol(format!("{target} has no scheme://")))?;
        let transport = self
            .find(scheme)
            .ok_or_else(|| OverlayError::protocol(format!("no transport for scheme {scheme:?}")))?;
        transport.connect(rest).await
    }
}

// ---------------------------------------------------------------------------
// A link over an abstract byte pipe
// ---------------------------------------------------------------------------

/// The two halves a [`PipeLink`] needs: a writer it can push bytes into and a reader that
/// hands bytes back.
pub struct Pipe {
    pub write: Box<dyn FnMut(Vec<u8>) -> Result<()> + Send>,
    pub incoming: Box<dyn FnMut() -> Result<Option<Vec<u8>>> + Send>,
    pub close: Box<dyn Fn() + Send>,
}

impl std::fmt::Debug for Pipe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Pipe")
    }
}

/// A [`Link`] built on top of a byte pipe.
///
/// The pipe's owner does the transport encryption (the existing `TransferDaemon` lanes do,
/// and the hole-punch lane does), so this only frames, buffers and accounts.
pub struct PipeLink {
    id: u32,
    kind: RouteKind,
    stats: Arc<RouteStats>,
    pipe: Mutex<Pipe>,
    reader: Mutex<FrameReader>,
    describe: String,
}

impl std::fmt::Debug for PipeLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PipeLink")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .finish()
    }
}

impl PipeLink {
    /// Wrap a byte pipe as a link.
    pub fn new(id: u32, kind: RouteKind, describe: impl Into<String>, pipe: Pipe) -> Arc<Self> {
        Arc::new(Self {
            id,
            kind,
            stats: Arc::new(RouteStats::new(kind)),
            pipe: Mutex::new(pipe),
            reader: Mutex::new(FrameReader::new()),
            describe: describe.into(),
        })
    }
}

impl Link for PipeLink {
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
        let wire = frame.encode();
        let size = wire.len() as u64;
        let mut pipe = self.pipe.lock().unwrap_or_else(|e| e.into_inner());
        match (pipe.write)(wire) {
            Ok(()) => {
                self.stats.record_sent(size);
                Ok(())
            }
            Err(e) => {
                self.stats.mark_down();
                Err(e)
            }
        }
    }

    fn try_recv(&self) -> Option<Frame> {
        // Bounded: a caller polls this from the session tick, so one call must not read for
        // ever, and a peer that never completes a frame must not grow the buffer without limit.
        for _ in 0..MAX_PIPE_READS_PER_POLL {
            let chunk = {
                let mut pipe = self.pipe.lock().unwrap_or_else(|e| e.into_inner());
                (pipe.incoming)()
            };
            match chunk {
                Ok(Some(bytes)) => {
                    let mut reader = self.reader.lock().unwrap_or_else(|e| e.into_inner());
                    let frames = reader.push(&bytes);
                    if reader.buffered() > crate::protocol::MAX_BODY {
                        // A peer that keeps sending undecodable bytes is not usable.
                        *reader = FrameReader::new();
                        self.stats.mark_down();
                        return None;
                    }
                    if frames.is_empty() {
                        continue; // partial frame; wait for more bytes
                    }
                    return frames.into_iter().next();
                }
                Ok(None) => return None,
                Err(_) => {
                    self.stats.mark_down();
                    return None;
                }
            }
        }
        None
    }

    fn is_up(&self) -> bool {
        self.stats.metrics().up
    }

    fn mark_down(&self) {
        self.stats.mark_down();
    }

    fn describe(&self) -> String {
        self.describe.clone()
    }
}

/// Choose the live route with the lowest cost. Ties break on [`RouteKind::rank`], so a LAN
/// path wins over a relay of the same measured speed.
pub fn best_route<'a>(links: &'a [&'a Arc<dyn Link>]) -> Option<&'a Arc<dyn Link>> {
    let by_cost = |a: &&&Arc<dyn Link>, b: &&&Arc<dyn Link>| {
        a.stats()
            .metrics()
            .cost()
            .partial_cmp(&b.stats().metrics().cost())
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.kind().rank().cmp(&b.kind().rank()))
    };
    links
        .iter()
        .filter(|l| l.is_up())
        .min_by(by_cost)
        // Nothing answers probes right now: still use the best route that is not closed rather
        // than send nothing (with one route, refusing it only stops the session healing).
        .or_else(|| links.iter().filter(|l| !l.is_closed()).min_by(by_cost))
        .copied()
}

/// How often the prober pings each route.
pub const PROBE_INTERVAL: Duration = Duration::from_millis(1000);

/// How many pipe reads one poll of [`Link::try_recv`] may make, so a caller can never be
/// held by a peer that keeps producing bytes without a whole frame.
const MAX_PIPE_READS_PER_POLL: usize = 8;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::kind;
    use std::collections::VecDeque;

    fn frame(seq: u64) -> Frame {
        Frame::new(
            2,
            kind::PING,
            seq,
            &crate::protocol::Ping {
                nonce: seq,
                sent_us: seq,
            },
        )
        .expect("frame")
    }

    #[test]
    fn route_kinds_round_trip_through_their_wire_names() {
        for k in [
            RouteKind::Direct,
            RouteKind::Lan,
            RouteKind::HolePunch,
            RouteKind::Relay,
            RouteKind::WsRelay,
            RouteKind::Tailscale,
        ] {
            assert_eq!(RouteKind::parse(k.as_str()), Some(k));
        }
        assert_eq!(RouteKind::parse("carrier-pigeon"), None);
        assert!(RouteKind::Lan.rank() < RouteKind::Relay.rank());
    }

    #[test]
    fn a_pipe_link_frames_what_it_is_given_and_reads_it_back() {
        let queue = shared_queue(vec![frame(1).encode(), frame(2).encode()]);
        let link = PipeLink::new(7, RouteKind::Direct, "test", pipe_over(queue.clone()));
        {
            link.send(&frame(3)).expect("send");
            assert_eq!(link.stats().frames_sent(), 1);
            let got = link.try_recv().expect("a frame");
            assert_eq!(got.seq, 1, "frames come back in the order they were queued");
            let got = link.try_recv().expect("a frame");
            assert_eq!(got.seq, 2);
            assert!(link.try_recv().is_none());
        }
    }

    #[test]
    fn a_pipe_link_reassembles_frames_split_across_reads() {
        let wire = frame(9).encode();
        let (head, tail) = wire.split_at(5);
        let queue = shared_queue(vec![head.to_vec()]);
        let link = PipeLink::new(1, RouteKind::Relay, "test", pipe_over(queue.clone()));
        {
            // The first read has only a prefix: no frame yet.
            assert!(link.try_recv().is_none());
            queue.lock().expect("queue").push_back(tail.to_vec());
            let got = link.try_recv().expect("completed frame");
            assert_eq!(got.seq, 9);
            assert!(link.try_recv().is_none(), "and then nothing");
        }
    }

    type Queue = std::sync::Arc<Mutex<VecDeque<Vec<u8>>>>;

    fn shared_queue(initial: Vec<Vec<u8>>) -> Queue {
        std::sync::Arc::new(Mutex::new(VecDeque::from(initial)))
    }

    fn pipe_over(queue: Queue) -> Pipe {
        Pipe {
            write: Box::new(|_bytes: Vec<u8>| Ok(())),
            incoming: Box::new(move || {
                Ok(queue.lock().unwrap_or_else(|e| e.into_inner()).pop_front())
            }),
            close: Box::new(|| {}),
        }
    }

    #[test]
    fn a_failing_write_marks_the_route_down() {
        let link = PipeLink::new(
            1,
            RouteKind::Relay,
            "test",
            Pipe {
                write: Box::new(|_| Err(OverlayError::protocol("link down"))),
                incoming: Box::new(|| Ok(None)),
                close: Box::new(|| {}),
            },
        );
        {
            assert!(link.send(&frame(1)).is_err());
            assert!(
                !link.is_up(),
                "a failed send takes the route out of rotation"
            );
        }
    }

    #[test]
    fn route_stats_smooth_rtt_and_track_loss() {
        let s = RouteStats::new(RouteKind::Relay);
        s.record_rtt(100.0);
        s.record_rtt(10.0);
        let rtt = s.metrics().rtt_ms;
        assert!(
            rtt < 100.0 && rtt > 10.0,
            "the average moves toward the new sample: {rtt}"
        );

        s.probe_sent();
        s.probe_ok(12.0);
        s.refresh_loss();
        assert_eq!(s.metrics().loss, 0.0, "a window with no misses has no loss");

        s.probe_sent();
        s.probe_sent();
        s.refresh_loss();
        assert!(
            s.metrics().loss > 0.0,
            "two of three probes lost is recorded as loss"
        );
    }

    #[test]
    fn a_dead_route_never_wins_the_routing_decision() {
        let fast_but_dead = RouteStats::new(RouteKind::Lan);
        fast_but_dead.record_rtt(1.0);
        fast_but_dead.record_sent(100);
        fast_but_dead.mark_down();
        let slow_but_alive = RouteStats::new(RouteKind::Relay);
        slow_but_alive.record_rtt(80.0);
        slow_but_alive.record_sent(10);
        assert!(fast_but_dead.metrics().cost().is_infinite());
        assert!(slow_but_alive.metrics().cost() < f64::INFINITY);
        assert!(slow_but_alive.metrics().cost() > fast_but_dead.metrics().rtt_ms);
    }

    #[test]
    fn the_registry_resolves_a_scheme_and_refuses_an_unknown_one() {
        struct Fake;
        #[async_trait]
        impl LinkTransport for Fake {
            fn name(&self) -> &'static str {
                "fake"
            }
            fn scheme(&self) -> &'static str {
                "fake"
            }
            async fn connect(&self, _target: &str) -> Result<Box<dyn Link>> {
                Err(OverlayError::protocol("not implemented"))
            }
        }
        let mut reg = LinkRegistry::new();
        reg.register(Box::new(Fake));
        assert_eq!(reg.schemes(), vec!["fake"]);
        assert!(reg.find("fake").is_some());
        assert!(reg.find("carrier-pigeon").is_none());
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("rt");
        rt.block_on(async {
            assert!(
                reg.open("fake://somewhere").await.is_err(),
                "the fake transport refuses"
            );
            assert!(
                reg.open("carrier-pigeon://somewhere").await.is_err(),
                "unknown scheme is an error"
            );
            assert!(
                reg.open("nowhere").await.is_err(),
                "a target with no scheme is an error"
            );
        });
    }
}
