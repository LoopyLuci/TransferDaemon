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

/// A shared WebSocket relay connection.
///
/// `Clone` is cheap (an `Arc`); `send_forward` / `send_keepalive` work from any
/// clone. The recv channel produced by [`RelayWsClient::connect`] carries the
/// opaque ciphertext the relay delivers to our registered token.
#[derive(Clone)]
pub struct RelayWsClient {
    sink: Arc<Mutex<futures_util::stream::SplitSink<Ws, Message>>>,
    seq: Arc<AtomicU64>,
}

impl RelayWsClient {
    /// Connect to a WS relay and register `self_token` (solving its PoW
    /// challenge). Returns the client plus a channel of inbound ciphertext
    /// blobs addressed to `self_token`.
    pub async fn connect(
        ws_url: &str,
        self_token: [u8; 32],
    ) -> Result<(Self, mpsc::Receiver<Vec<u8>>), std::io::Error> {
        let req = ws_url
            .into_client_request()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        let (ws, _) = tokio_tungstenite::connect_async(req)
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::ConnectionRefused, e))?;
        let (mut sink, mut source) = ws.split();

        // 1. Ask for the current challenge.
        let ask = encode(Tag::Challenge, &()).unwrap_or_default();
        sink.send(Message::Binary(ask))
            .await
            .map_err(std::io::Error::other)?;
        let (challenge, difficulty) = read_challenge_reply(&mut source).await?;

        // 2. Solve PoW + register.
        let nonce = solve_pow(&challenge, &self_token, difficulty);
        let reg = encode(
            Tag::Register,
            &RegisterMsg { session_token: self_token, pow_nonce: nonce, seq: 1 },
        )
        .unwrap_or_default();
        sink.send(Message::Binary(reg))
            .await
            .map_err(std::io::Error::other)?;
        // 3. Wait for the register acceptance (a Challenge reply).
        let _ = read_challenge_reply(&mut source).await?;

        // 4. Hand the stream to a recv task that routes DeliveredMsg ciphertext.
        let (tx, rx) = mpsc::channel::<Vec<u8>>(64);
        tokio::spawn(async move {
            while let Some(Ok(Message::Binary(frame))) = source.next().await {
                if let Some((Tag::Ack, body)) = split(&frame) {
                    if let Ok(d) = bincode::deserialize::<DeliveredMsg>(body) {
                        let _ = tx.send(d.ciphertext).await;
                    }
                }
            }
        });

        let client = Self {
            sink: Arc::new(Mutex::new(sink)),
            seq: Arc::new(AtomicU64::new(1)),
        };
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
        sink.send(Message::Binary(frame))
            .await
            .map_err(std::io::Error::other)
    }

    /// Refresh the relay-side TTL for `token`.
    pub async fn send_keepalive(&self, token: [u8; 32]) -> std::io::Result<()> {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let msg = KeepaliveMsg { session_token: token, pow_nonce: 0, seq: seq as u32 };
        let frame = encode(Tag::Keepalive, &msg)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let mut sink = self.sink.lock().await;
        sink.send(Message::Binary(frame))
            .await
            .map_err(std::io::Error::other)
    }

    /// Spawn the 45 s keepalive loop (keeps the registration + NAT mapping alive).
    pub fn spawn_keepalive_loop(self: &Arc<Self>, token: [u8; 32]) {
        let this = self.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(45));
            ticker.tick().await; // first tick fires immediately
            loop {
                ticker.tick().await;
                if this.send_keepalive(token).await.is_err() {
                    // Transient; retry next tick.
                }
            }
        });
    }
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