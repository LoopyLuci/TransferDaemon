//! WebSocket relay client — the same blind relay protocol (`relayd::protocol`)
//! over WebSocket instead of UDP. Use it to reach `relayd-ws` or the Cloudflare
//! Worker relay (`deploy/cloudflare-worker/`), which speak the identical frames.
//!
//! Each outbound blob is a binary frame `encode(Tag, Msg)`; inbound blobs arrive
//! as `DeliveredMsg` under `Tag::Ack`. The client registers once at connect
//! (solving the relay's BLAKE3 PoW challenge), then forwards and keeps the
//! registration alive. A background task feeds inbound ciphertext to a channel.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use relayd::protocol::{ChallengeMsg, DeliveredMsg, ForwardMsg, KeepaliveMsg, RegisterMsg, Tag, encode, split};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, mpsc};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// A shared WebSocket relay connection that HEALS ITSELF.
///
/// `Clone` is cheap (an `Arc`); `send_forward` / `send_keepalive` work from any
/// clone. [`RelayWsClient::connect`] returns a STABLE inbound channel plus a
/// client; a background connection-manager task owns the actual WebSocket,
/// reconnects + re-registers automatically when the connection dies (mobile
/// networks, relay hibernation, idle timeouts), and keeps feeding the same
/// inbound channel. The caller never sees a dropped relay connection.
#[derive(Clone)]
pub struct RelayWsClient {
    sink: Arc<Mutex<Option<futures_util::stream::SplitSink<Ws, Message>>>>,
    seq: Arc<AtomicU64>,
}

impl RelayWsClient {
    /// Connect to a WS relay and register `self_token` (solving its PoW
    /// challenge). Returns the client plus a STABLE channel of inbound
    /// ciphertext blobs addressed to `self_token` (fed across reconnects).
    pub async fn connect(
        ws_url: &str,
        self_token: [u8; 32],
    ) -> Result<(Self, mpsc::Receiver<Vec<u8>>), std::io::Error> {
        let (tx, rx) = mpsc::channel::<Vec<u8>>(64);
        let client = Self {
            sink: Arc::new(Mutex::new(None)),
            seq: Arc::new(AtomicU64::new(1)),
        };

        // First connect must succeed (the caller expects a live registration).
        let (sink, stream) = connect_and_register(ws_url, &self_token).await?;
        *client.sink.lock().await = Some(sink);

        // Connection manager: keep the relay link alive forever.
        let mgr = client.clone();
        let url = ws_url.to_string();
        tokio::spawn(async move {
            let mut backoff = std::time::Duration::from_millis(500);
            let mut stream = stream;
            loop {
                // Read inbound; re-register on a ticker (through the shared sink).
                // 15 s: short enough that the relay's in-memory registration map
                // is refreshed well before its TTL / hibernation-wake window.
                let mut ka = tokio::time::interval(std::time::Duration::from_secs(15));
                ka.tick().await; // consume the immediate tick
                let mut dead = false;
                let mut re_register_pending = false;
                while !dead {
                    if re_register_pending {
                        re_register_pending = false;
                        let mut slot = mgr.sink.lock().await;
                        match slot.as_mut() {
                            Some(sink) => {
                                // Re-register every 45 s: the relay-side map is
                                // refreshed even if the relay's Durable Object
                                // hibernated and dropped it. A keepalive-only
                                // refresh is a no-op when the map entry is gone,
                                // so a fresh Register is what guarantees the
                                // registration survives.
                                if re_register(&mut stream, sink, &self_token).await.is_err() {
                                    dead = true;
                                }
                            }
                            None => dead = true,
                        }
                    }
                    if dead {
                        break;
                    }
                    tokio::select! {
                        frame = stream.next() => {
                            let frame = match frame {
                                Some(Ok(f)) => Some(f),
                                _ => {
                                    dead = true;
                                    None
                                }
                            };
                            if let Some(Message::Binary(f)) = frame {
                                if let Some((Tag::Ack, body)) = split(&f) {
                                    if let Ok(d) = bincode::deserialize::<DeliveredMsg>(body) {
                                        let _ = tx.send(d.ciphertext).await;
                                    }
                                }
                            }
                        }
                        _ = ka.tick() => {
                            re_register_pending = true;
                        }
                    }
                }
                // Connection died: reconnect + re-register, then swap the sink.
                let (new_sink, new_stream) = loop {
                    match connect_and_register(&url, &self_token).await {
                        Ok(pair) => break pair,
                        Err(_) => {
                            tokio::time::sleep(backoff).await;
                            backoff = (backoff * 2).min(std::time::Duration::from_secs(30));
                        }
                    }
                };
                backoff = std::time::Duration::from_millis(500);
                *mgr.sink.lock().await = Some(new_sink);
                stream = new_stream;
            }
        });

        Ok((client, rx))
    }

    /// Send an opaque payload to the peer registered under `token`.
    pub async fn send_forward(&self, token: [u8; 32], payload: &[u8]) -> std::io::Result<()> {
        let seq = (self.seq.fetch_add(1, Ordering::Relaxed) & 0xFFFF) as u16;
        let msg = ForwardMsg {
            session_token: token,
            pow_nonce: 0, // PoW is per-registration for WS relays
            sender_seq: seq,
            ciphertext: payload.to_vec(),
        };
        let frame = encode(Tag::Forward, &msg)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let mut sink = self.sink.lock().await;
        match sink.as_mut() {
            Some(s) => s.send(Message::Binary(frame)).await.map_err(std::io::Error::other),
            None => Err(std::io::Error::new(std::io::ErrorKind::NotConnected, "ws relay disconnected")),
        }
    }

    /// Refresh the relay-side TTL for `token`.
    pub async fn send_keepalive(&self, token: [u8; 32]) -> std::io::Result<()> {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let msg = KeepaliveMsg { session_token: token, pow_nonce: 0, seq: seq as u32 };
        let frame = encode(Tag::Keepalive, &msg)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let mut sink = self.sink.lock().await;
        match sink.as_mut() {
            Some(s) => s.send(Message::Binary(frame)).await.map_err(std::io::Error::other),
            None => Err(std::io::Error::new(std::io::ErrorKind::NotConnected, "ws relay disconnected")),
        }
    }

    /// Spawn the 45 s keepalive loop. The connection manager ALSO keepalives,
    /// so this is a redundant safety net (kept for API compatibility).
    pub fn spawn_keepalive_loop(self: &Arc<Self>, token: [u8; 32]) {
        let this = self.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(45));
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let _ = this.send_keepalive(token).await;
            }
        });
    }
}

/// Establish ONE connection: connect, ask challenge, solve PoW, register.
/// Returns the live (sink, stream) pair (or an error). Bounded waits throughout.
async fn connect_and_register(
    ws_url: &str,
    self_token: &[u8; 32],
) -> Result<
    (
        futures_util::stream::SplitSink<Ws, Message>,
        futures_util::stream::SplitStream<Ws>,
    ),
    std::io::Error,
> {
    let req = ws_url
        .into_client_request()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    // Bound the whole TCP connect + TLS handshake: on a hung network (e.g. a
    // device whose outbound TLS is blocked/suspended) an unbounded connect
    // would hang RelayHub::start forever, silently skipping registration.
    let (ws, _) = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        tokio_tungstenite::connect_async(req),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "relay WS connect timed out"))?
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::ConnectionRefused, e))?;
    let (mut sink, mut source) = ws.split();

    // 1. Ask for the current challenge.
    let ask = encode(Tag::Challenge, &()).unwrap_or_default();
    sink.send(Message::Binary(ask))
        .await
        .map_err(std::io::Error::other)?;
    let (challenge, difficulty) = read_challenge_reply(&mut source).await?;

    // 2. Solve PoW + register.
    let nonce = solve_pow(&challenge, self_token, difficulty);
    let reg = encode(
        Tag::Register,
        &RegisterMsg { session_token: *self_token, pow_nonce: nonce, seq: 1 },
    )
    .unwrap_or_default();
    sink.send(Message::Binary(reg))
        .await
        .map_err(std::io::Error::other)?;
    // 3. Wait for the register acceptance (a Challenge reply).
    let _ = read_challenge_reply(&mut source).await?;
    Ok((sink, source))
}

/// Re-register on an EXISTING connection: ask a fresh challenge, solve PoW,
/// send Register, wait for acceptance. Used by the connection manager's ticker
/// so the relay-side registration survives relay hibernation.
async fn re_register(
    stream: &mut futures_util::stream::SplitStream<Ws>,
    sink: &mut futures_util::stream::SplitSink<Ws, Message>,
    token: &[u8; 32],
) -> std::io::Result<()> {
    let ask = encode(Tag::Challenge, &()).unwrap_or_default();
    sink.send(Message::Binary(ask)).await.map_err(std::io::Error::other)?;
    let (challenge, difficulty) = read_challenge_reply(stream).await?;
    let nonce = solve_pow(&challenge, token, difficulty);
    let reg = encode(
        Tag::Register,
        &RegisterMsg { session_token: *token, pow_nonce: nonce, seq: 1 },
    )
    .unwrap_or_default();
    sink.send(Message::Binary(reg)).await.map_err(std::io::Error::other)?;
    let _ = read_challenge_reply(stream).await?;
    Ok(())
}

/// Read the next `ChallengeMsg` reply frame (bounded). The timeout is generous
/// (30 s): a Cloudflare Durable Object relay hibernates when idle and can take
/// several seconds to cold-start its first challenge reply.
async fn read_challenge_reply(
    source: &mut futures_util::stream::SplitStream<Ws>,
) -> Result<([u8; 16], u32), std::io::Error> {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            let Some(frame) = source.next().await else {
                return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "ws closed"));
            };
            let Ok(Message::Binary(f)) = frame else { continue };
            if let Some((Tag::Challenge, body)) = split(&f) {
                let c: ChallengeMsg = bincode::deserialize(body)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                return Ok((c.challenge, c.difficulty));
            }
        }
    })
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "ws challenge reply timed out"))?
}

/// Solve the relay's BLAKE3 PoW (iterate nonces until the difficulty holds).
fn solve_pow(challenge: &[u8; 16], token: &[u8; 32], difficulty: u32) -> u64 {
    if difficulty == 0 {
        return 0;
    }
    let mut nonce = 0u64;
    loop {
        if relayd::pow::leading_zeros(difficulty, challenge, token, nonce) {
            return nonce;
        }
        nonce = nonce.wrapping_add(1);
    }
}

/// A small forwarding abstraction so a relay hub can treat UDP and WS clients
/// uniformly when replying to a handshake or chunk.
#[async_trait]
pub trait RelayForward {
    async fn relay_send_forward(&self, token: [u8; 32], payload: &[u8]) -> std::io::Result<()>;
}

#[async_trait]
impl RelayForward for RelayWsClient {
    async fn relay_send_forward(&self, token: [u8; 32], payload: &[u8]) -> std::io::Result<()> {
        self.send_forward(token, payload).await
    }
}