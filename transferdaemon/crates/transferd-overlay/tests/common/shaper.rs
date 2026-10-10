//! A link emulator: a UDP forwarder in front of a relay that behaves like a slow, long path.
//!
//! Each direction of each client is a queue drained at a fixed rate (a token bucket with no
//! burst: datagrams leave one after another, each taking `size / rate`), with a small buffer that
//! drops what does not fit (drop-tail, like a router), and a fixed delay added after the queue.
//! That is what a bottleneck link does, and it is what a sender without congestion control
//! floods: it fills the buffer, loses a share of everything and keeps sending.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::Instant;

/// What the emulator saw, readable while it runs.
#[derive(Default)]
pub struct ShaperStats {
    admitted: AtomicU64,
    dropped: AtomicU64,
    /// Bytes that arrived with the buffer at least 75% full, and all bytes that arrived.
    arrived_full: AtomicU64,
    arrivals: AtomicU64,
}

impl ShaperStats {
    /// Bytes the queues took, and the bytes they dropped.
    pub fn admitted_dropped(&self) -> (u64, u64) {
        (
            self.admitted.load(Ordering::Relaxed),
            self.dropped.load(Ordering::Relaxed),
        )
    }

    /// The share of bytes that arrived to a (nearly) full buffer.
    pub fn full_fraction(&self) -> f64 {
        let n = self.arrivals.load(Ordering::Relaxed).max(1);
        self.arrived_full.load(Ordering::Relaxed) as f64 / n as f64
    }

    /// Forget what was counted so far (to measure only the steady state).
    pub fn reset(&self) {
        for c in [
            &self.admitted,
            &self.dropped,
            &self.arrived_full,
            &self.arrivals,
        ] {
            c.store(0, Ordering::Relaxed);
        }
    }
}

/// One direction: a queue draining at `rate` bytes per second behind a buffer of `limit` bytes.
struct Pipe {
    rate: f64,
    limit: f64,
    delay: Duration,
    /// When the queue empties.
    busy_until: Instant,
    stats: Arc<ShaperStats>,
}

impl Pipe {
    /// Take a datagram of `n` bytes at `now`: when it reaches the far end, or `None` if the
    /// buffer was full.
    fn admit(&mut self, n: usize, now: Instant) -> Option<Instant> {
        let backlog = self.busy_until.saturating_duration_since(now).as_secs_f64() * self.rate;
        self.stats.arrivals.fetch_add(n as u64, Ordering::Relaxed);
        if backlog >= self.limit * 0.75 {
            self.stats
                .arrived_full
                .fetch_add(n as u64, Ordering::Relaxed);
        }
        if backlog + n as f64 > self.limit {
            self.stats.dropped.fetch_add(n as u64, Ordering::Relaxed);
            return None;
        }
        self.stats.admitted.fetch_add(n as u64, Ordering::Relaxed);
        self.busy_until = self.busy_until.max(now) + Duration::from_secs_f64(n as f64 / self.rate);
        Some(self.busy_until + self.delay)
    }
}

/// A forwarder with a bandwidth limit, a small buffer and a delay. Traffic between two nodes
/// crosses it twice (node to relay, relay to node), so each crossing gets half the delay and a
/// datagram's one-way trip takes the whole of it.
pub struct Shaped {
    pub addr: SocketAddr,
    pub stats: Arc<ShaperStats>,
}

/// Deliver datagrams in order, each at its time.
fn deliver(
    socket: Arc<UdpSocket>,
    to: Option<SocketAddr>,
) -> mpsc::UnboundedSender<(Instant, Vec<u8>)> {
    let (tx, mut rx) = mpsc::unbounded_channel::<(Instant, Vec<u8>)>();
    tokio::spawn(async move {
        while let Some((at, data)) = rx.recv().await {
            tokio::time::sleep_until(at).await;
            let _ = match to {
                Some(addr) => socket.send_to(&data, addr).await,
                None => socket.send(&data).await,
            };
        }
    });
    tx
}

/// Windows timers tick every 15.6 ms unless a program asks for finer: ask, so the emulated delay
/// is the delay and not the delay plus the timer's rounding.
#[cfg(windows)]
fn fine_timers() {
    #[link(name = "winmm")]
    extern "system" {
        fn timeBeginPeriod(ms: u32) -> u32;
    }
    // SAFETY: a plain system call with a number; there is nothing to keep valid afterwards.
    unsafe {
        timeBeginPeriod(1);
    }
}

#[cfg(not(windows))]
fn fine_timers() {}

impl Shaped {
    /// Forward to `relay` at `rate` bytes per second in each direction, with `buffer` bytes of
    /// queue and `delay` added one way between two nodes (so the round trip grows by twice that).
    pub async fn start(relay: SocketAddr, rate: u64, buffer: usize, delay: Duration) -> Shaped {
        fine_timers();
        let front = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("binds"));
        let addr = front.local_addr().expect("addr");
        let stats = Arc::new(ShaperStats::default());
        let seen = stats.clone();
        tokio::spawn(async move {
            let pipe = |stats: &Arc<ShaperStats>| Pipe {
                rate: rate as f64,
                limit: buffer as f64,
                delay: delay / 2,
                busy_until: Instant::now(),
                stats: stats.clone(),
            };
            // Per client: a socket towards the relay, and the two directions' queues.
            type Client = (Pipe, mpsc::UnboundedSender<(Instant, Vec<u8>)>);
            let mut clients: std::collections::HashMap<SocketAddr, Client> =
                std::collections::HashMap::new();
            let mut buf = vec![0u8; 65_536];
            loop {
                let Ok((n, client)) = front.recv_from(&mut buf).await else {
                    continue;
                };
                // The sockets are bound with an await, so the entry API does not fit here.
                #[allow(clippy::map_entry)]
                if !clients.contains_key(&client) {
                    let back = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("binds"));
                    back.connect(relay).await.expect("connects");
                    // Towards the client: the relay's answers go through the other queue.
                    let to_client = deliver(front.clone(), Some(client));
                    let mut down = pipe(&seen);
                    let from_relay = back.clone();
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 65_536];
                        while let Ok(n) = from_relay.recv(&mut buf).await {
                            if let Some(at) = down.admit(n, Instant::now()) {
                                let _ = to_client.send((at, buf[..n].to_vec()));
                            }
                        }
                    });
                    clients.insert(client, (pipe(&seen), deliver(back, None)));
                }
                if let Some((up, to_relay)) = clients.get_mut(&client) {
                    if let Some(at) = up.admit(n, Instant::now()) {
                        let _ = to_relay.send((at, buf[..n].to_vec()));
                    }
                }
            }
        });
        Shaped { addr, stats }
    }
}
