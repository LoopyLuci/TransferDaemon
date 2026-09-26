use crate::announce::RelayAnnounce;
use crate::dht::DhtAnnouncer;
use crate::settings::RelaySettings;
use crate::token_bucket::TokenBucket;
use relayd::protocol::{
    self, AckMsg, ChallengeMsg, DeliveredMsg, ErrorCode, ErrorMsg, ForwardMsg,
    KeepaliveMsg, RegisterMsg, Tag,
};
use relayd::relay::Relay;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::broadcast;

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

/// Best-effort public IP detection — falls back to loopback for LAN-only setups.
fn detect_public_addr() -> String {
    // Try connecting to a well-known address to determine local outbound IP.
    // No data is actually sent (UDP connect doesn't transmit).
    if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
        if socket.connect("8.8.8.8:53").is_ok() {
            if let Ok(addr) = socket.local_addr() {
                return addr.ip().to_string();
            }
        }
    }
    "127.0.0.1".to_string()
}

// ---------------------------------------------------------------------------
// Public status snapshot
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct RelayStatus {
    pub active_sessions: usize,
    pub port: u16,
    pub running: bool,
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("relay is already running")]
    AlreadyRunning,
}

// ---------------------------------------------------------------------------
// RelayEngine
// ---------------------------------------------------------------------------

/// Runs the `relayd` relay core as an embedded UDP service inside the daemon.
///
/// The engine spawns three background tasks:
/// 1. **UDP receive loop** — reads datagrams and dispatches to the `Relay` state machine.
/// 2. **Pruner** — removes expired registrations every 10 seconds.
/// 3. **Challenge rotator** — rotates the PoW challenge every 55 seconds.
///
/// Stopping is coordinated via a `broadcast::Sender<()>` shutdown channel so all
/// three tasks exit cleanly before `stop()` returns.
pub struct RelayEngine {
    relay: Arc<Mutex<Relay>>,
    port: u16,
    shutdown_tx: broadcast::Sender<()>,
    /// DHT announcer — `None` if DHT failed to bind (non-fatal).
    pub dht: Option<DhtAnnouncer>,
}

impl RelayEngine {
    /// Bind a UDP socket and start all background tasks.
    pub async fn start(settings: RelaySettings) -> Result<Arc<Self>, EngineError> {
        let addr = format!("0.0.0.0:{}", settings.port);
        let socket = UdpSocket::bind(&addr).await?;
        let port = socket.local_addr()?.port();
        let socket = Arc::new(socket);

        let relay = Arc::new(Mutex::new(Relay::new(
            settings.difficulty,
            300,                    // 5-minute TTL
            protocol::MAX_PAYLOAD,
        )));
        let bucket = Arc::new(TokenBucket::new(settings.bandwidth_kbps));
        let max_sessions = settings.max_sessions;

        let (shutdown_tx, _) = broadcast::channel::<()>(8);

        // ── DHT announcer (non-fatal if bind fails) ──────────────────────────
        let dht_bind = format!("0.0.0.0:{}", settings.dht_port);
        let dht = DhtAnnouncer::new(&dht_bind, settings.identity_pubkey_hash).await.ok();
        if let Some(ref ann) = dht {
            ann.bootstrap(&settings.dht_bootstrap_nodes).await;
            let relay_addr = format!("{}:{port}", detect_public_addr());
            let now = now_secs();
            let announce = RelayAnnounce {
                identity_pubkey_hash: settings.identity_pubkey_hash,
                relay_addr,
                difficulty: settings.difficulty,
                bandwidth_kbps: settings.bandwidth_kbps,
                auth_mode: match &settings.auth_policy {
                    crate::settings::AuthPolicy::Public       => "public".into(),
                    crate::settings::AuthPolicy::AllowList(_) => "allow_list".into(),
                },
                published_at: now,
                expires_at: now + 900,
                auth: [0u8; 32],
            }.sign(&settings.identity_pubkey_hash);
            ann.start_republish_task(announce, shutdown_tx.subscribe());
        }

        let engine = Arc::new(RelayEngine {
            relay: relay.clone(),
            port,
            shutdown_tx: shutdown_tx.clone(),
            dht,
        });

        // ── UDP receive loop ────────────────────────────────────────────────
        {
            let relay = relay.clone();
            let socket = socket.clone();
            let bucket = bucket.clone();
            let mut shutdown_rx = shutdown_tx.subscribe();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65_536];
                loop {
                    tokio::select! {
                        _ = shutdown_rx.recv() => break,
                        result = socket.recv_from(&mut buf) => {
                            if let Ok((n, src)) = result {
                                handle_datagram(
                                    &buf[..n], src,
                                    &relay, &socket, &bucket, max_sessions,
                                ).await;
                            }
                        }
                    }
                }
            });
        }

        // ── Pruner (every 10 s) ─────────────────────────────────────────────
        {
            let relay = relay.clone();
            let mut shutdown_rx = shutdown_tx.subscribe();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = shutdown_rx.recv() => break,
                        _ = tokio::time::sleep(Duration::from_secs(10)) => {
                            relay.lock().unwrap_or_else(|e| e.into_inner()).prune_expired();
                        }
                    }
                }
            });
        }

        // ── Challenge rotator (every 55 s) ──────────────────────────────────
        {
            let relay = relay.clone();
            let mut shutdown_rx = shutdown_tx.subscribe();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = shutdown_rx.recv() => break,
                        _ = tokio::time::sleep(Duration::from_secs(55)) => {
                            relay.lock().unwrap_or_else(|e| e.into_inner()).rotate_challenge();
                        }
                    }
                }
            });
        }

        Ok(engine)
    }

    /// Signals all background tasks to stop.
    pub fn stop(&self) {
        let _ = self.shutdown_tx.send(());
    }

    /// Returns a snapshot of the current engine status.
    pub fn status(&self) -> RelayStatus {
        let active_sessions = self.relay.lock().unwrap_or_else(|e| e.into_inner()).active_count();
        RelayStatus {
            active_sessions,
            port: self.port,
            running: true,
        }
    }

    pub fn port(&self) -> u16 { self.port }
}

impl Drop for RelayEngine {
    fn drop(&mut self) { self.stop(); }
}

// ---------------------------------------------------------------------------
// Datagram handler
// ---------------------------------------------------------------------------

async fn handle_datagram(
    buf: &[u8],
    src: SocketAddr,
    relay: &Arc<Mutex<Relay>>,
    socket: &Arc<UdpSocket>,
    bucket: &Arc<TokenBucket>,
    max_sessions: usize,
) {
    let Some((tag, body)) = protocol::split(buf) else { return };

    match tag {
        Tag::Register => {
            let Ok(msg) = bincode::deserialize::<RegisterMsg>(body) else { return };

            // All relay state mutations complete before any await.
            let outcome: Result<ChallengeMsg, (ErrorCode, u32, String)> = {
                let mut r = relay.lock().unwrap_or_else(|e| e.into_inner());
                if r.active_count() >= max_sessions {
                    Err((ErrorCode::RateLimited, 0, "session limit reached".into()))
                } else {
                    match r.register(&msg, src) {
                        Ok(()) => {
                            let c = r.current_challenge();
                            Ok(ChallengeMsg {
                                challenge: c.bytes,
                                expires_at: c.expires_at,
                                difficulty: c.difficulty,
                            })
                        }
                        Err(e) => Err((e.code(), msg.seq, e.to_string())),
                    }
                }
            }; // MutexGuard dropped here

            match outcome {
                Ok(challenge) => {
                    if let Ok(frame) = protocol::encode(Tag::Challenge, &challenge) {
                        let _ = socket.send_to(&frame, src).await;
                    }
                }
                Err((code, seq, detail)) => {
                    send_error(socket, src, code, seq, &detail).await;
                }
            }
        }

        Tag::Forward => {
            let Ok(msg) = bincode::deserialize::<ForwardMsg>(body) else { return };
            if !bucket.try_consume(msg.ciphertext.len()) {
                send_error(socket, src, ErrorCode::RateLimited, 0, "bandwidth exceeded").await;
                return;
            }
            // Resolve forward destination before any await.
            let result: Result<(SocketAddr, u16, Vec<u8>), (ErrorCode, String)> = {
                match relay.lock().unwrap_or_else(|e| e.into_inner()).forward(&msg) {
                    Ok(dst) => Ok((dst, msg.sender_seq, msg.ciphertext)),
                    Err(e) => Err((e.code(), e.to_string())),
                }
            }; // MutexGuard dropped here

            match result {
                Ok((dst, sender_seq, ciphertext)) => {
                    // Add timing jitter to prevent timing analysis
                    // Per CONTEXT.md design decision #5: "Timing is jittered at the relay"
                    let jitter_ms = rand::random::<u64>() % 10; // 0-9ms random delay
                    tokio::time::sleep(Duration::from_millis(jitter_ms)).await;

                    let delivered = DeliveredMsg { sender_seq, ciphertext };
                    if let Ok(frame) = protocol::encode(Tag::Ack, &delivered) {
                        let _ = socket.send_to(&frame, dst).await;
                    }
                    let ack = AckMsg { sender_seq };
                    if let Ok(frame) = protocol::encode(Tag::Ack, &ack) {
                        let _ = socket.send_to(&frame, src).await;
                    }
                }
                Err((code, detail)) => {
                    send_error(socket, src, code, 0, &detail).await;
                }
            }
        }

        Tag::Keepalive => {
            let Ok(msg) = bincode::deserialize::<KeepaliveMsg>(body) else { return };
            let result = relay.lock().unwrap_or_else(|e| e.into_inner()).keepalive(&msg)
                .map_err(|e| (e.code(), e.to_string())); // guard dropped here
            if let Err((code, detail)) = result {
                send_error(socket, src, code, 0, &detail).await;
            }
        }

        // Clients never send these; silently drop.
        Tag::Challenge | Tag::Error | Tag::Ack => {}
    }
}

async fn send_error(
    socket: &UdpSocket,
    dst: SocketAddr,
    code: ErrorCode,
    seq: u32,
    detail: &str,
) {
    let msg = ErrorMsg { code, seq, detail: detail.to_string() };
    if let Ok(frame) = protocol::encode(Tag::Error, &msg) {
        let _ = socket.send_to(&frame, dst).await;
    }
}



