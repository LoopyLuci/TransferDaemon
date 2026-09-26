//! WebSocket relay — the same blind, PoW-authenticated blob forwarding as the
//! UDP `relayd`, but over WebSocket frames. WebSocket traverses essentially
//! every NAT/firewall and Cloudflare's edge, so this is the relay path when
//! UDP is blocked. Each binary frame is `encode(Tag, Msg)` from
//! [`crate::protocol`] — identical wire format to the UDP relay.
//!
//! The Cloudflare Worker (`deploy/cloudflare-worker/`) implements the same
//! protocol at the edge with zero servers.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, mpsc};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

use crate::pow::PowChallenge;
use crate::protocol::{
    AckMsg, ChallengeMsg, DeliveredMsg, ErrorCode, ErrorMsg, ForwardMsg, KeepaliveMsg, RegisterMsg,
    Tag, encode, split,
};

/// Outbound channel to one connection; the drain task writes frames to the WS
/// sink. `Clone` so a token's sender can live in the forwarding map AND this
/// connection can reply through the same channel.
pub type Out = mpsc::UnboundedSender<Message>;

/// The shared relay state: token → outbound channel + registration TTL.
pub struct WsRelay {
    pub difficulty: u32,
    pub ttl_secs: u64,
    pub challenge: PowChallenge,
    pub clients: HashMap<[u8; 32], (SocketAddr, Out)>,
    pub expires: HashMap<[u8; 32], u64>,
}

impl WsRelay {
    pub fn new(difficulty: u32, ttl_secs: u64) -> Self {
        Self {
            difficulty,
            ttl_secs,
            challenge: PowChallenge::new(difficulty, now_secs() + 60),
            clients: HashMap::new(),
            expires: HashMap::new(),
        }
    }

    pub fn send_challenge(&self, out: &Out) {
        let (bytes, expires_at, difficulty) =
            (self.challenge.bytes, self.challenge.expires_at, self.difficulty);
        let frame = encode(
            Tag::Challenge,
            &ChallengeMsg { challenge: bytes, expires_at, difficulty },
        )
        .unwrap_or_default();
        let _ = out.send(Message::Binary(frame));
    }

    /// Rotate the PoW challenge and prune expired registrations.
    pub fn tick(&mut self) {
        self.challenge = PowChallenge::new(self.difficulty, now_secs() + 60);
        let expired: Vec<[u8; 32]> = self
            .expires
            .iter()
            .filter(|(_, exp)| **exp <= now_secs())
            .map(|(t, _)| *t)
            .collect();
        for t in expired {
            self.clients.remove(&t);
            self.expires.remove(&t);
        }
    }

    /// Remove any token registered from `peer` (its connection dropped).
    pub fn forget_peer(&mut self, peer: SocketAddr) {
        self.clients.retain(|_, (addr, _)| *addr != peer);
    }
}

/// Handle one WebSocket client connection until it closes.
pub async fn handle_connection(
    ws: WebSocketStream<TcpStream>,
    peer: SocketAddr,
    relay: Arc<Mutex<WsRelay>>,
) {
    let (mut sink, mut source) = ws.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
    let drain = tokio::spawn(async move {
        while let Some(m) = rx.recv().await {
            if sink.send(m).await.is_err() {
                break;
            }
        }
    });

    while let Some(Ok(Message::Binary(frame))) = source.next().await {
        let Some((tag, body)) = split(&frame) else { continue };
        let mut r = relay.lock().await;
        match tag {
            Tag::Challenge => r.send_challenge(&tx),
            Tag::Register => {
                if let Ok(msg) = bincode::deserialize::<RegisterMsg>(body) {
                    if r.challenge.verify(&msg.session_token, msg.pow_nonce) {
                        r.clients.insert(msg.session_token, (peer, tx.clone()));
                        let ttl = r.ttl_secs;
                        r.expires.insert(msg.session_token, now_secs() + ttl);
                        r.send_challenge(&tx);
                    } else {
                        let e = encode(
                            Tag::Error,
                            &ErrorMsg { code: ErrorCode::InvalidPoW, seq: msg.seq, detail: "invalid PoW".into() },
                        )
                        .unwrap_or_default();
                        let _ = tx.send(Message::Binary(e));
                    }
                }
            }
            Tag::Forward => {
                if let Ok(msg) = bincode::deserialize::<ForwardMsg>(body) {
                    if let Some((_, dst)) = r.clients.get(&msg.session_token) {
                        let delivered = encode(
                            Tag::Ack,
                            &DeliveredMsg { sender_seq: msg.sender_seq, ciphertext: msg.ciphertext },
                        )
                        .unwrap_or_default();
                        let _ = dst.send(Message::Binary(delivered));
                    }
                    let ack = encode(Tag::Ack, &AckMsg { sender_seq: msg.sender_seq }).unwrap_or_default();
                    let _ = tx.send(Message::Binary(ack));
                }
            }
            Tag::Keepalive => {
                if let Ok(msg) = bincode::deserialize::<KeepaliveMsg>(body) {
                    let ttl = r.ttl_secs;
                    r.expires.insert(msg.session_token, now_secs() + ttl);
                }
            }
            Tag::Ack | Tag::Error => {}
        }
    }

    relay.lock().await.forget_peer(peer);
    drain.abort();
}

/// Shared prune/challenge-rotation loop; call from a server task.
pub async fn maintenance_loop(relay: Arc<Mutex<WsRelay>>) {
    let mut ticker = tokio::time::interval(Duration::from_secs(30));
    loop {
        ticker.tick().await;
        relay.lock().await.tick();
    }
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::{SinkExt, StreamExt};
    use tokio::net::TcpListener;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;

    /// Connect a WS client, register `token` (solving the PoW challenge), and
    /// return the (sink, source).
    async fn connect_and_register(
        addr: std::net::SocketAddr,
        token: [u8; 32],
    ) -> (
        futures_util::stream::SplitSink<WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>, Message>,
        futures_util::stream::SplitStream<WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>>,
    ) {
        let req = format!("ws://{addr}/").into_client_request().unwrap();
        let (ws, _) = tokio_tungstenite::connect_async(req).await.unwrap();
        let (mut sink, mut source) = ws.split();

        // Ask for the challenge, solve PoW, register.
        let ask = encode(Tag::Challenge, &()).unwrap_or_default();
        sink.send(Message::Binary(ask.into())).await.unwrap();
        let (challenge, difficulty) = loop {
            if let Some(Ok(Message::Binary(f))) = source.next().await {
                if let Some((Tag::Challenge, body)) = split(&f) {
                    let c: ChallengeMsg = bincode::deserialize(body).unwrap();
                    break (c.challenge, c.difficulty);
                }
            }
        };
        let nonce = crate::pow::solve(&challenge, &token, difficulty, 0, 100_000).unwrap();
        let reg = encode(
            Tag::Register,
            &RegisterMsg { session_token: token, pow_nonce: nonce, seq: 1 },
        )
        .unwrap_or_default();
        sink.send(Message::Binary(reg.into())).await.unwrap();
        // Drain until the register reply (a Challenge) arrives.
        for _ in 0..8 {
            if let Some(Ok(Message::Binary(f))) = source.next().await {
                if let Some((Tag::Challenge, _)) = split(&f) {
                    break;
                }
            }
        }
        (sink, source)
    }

    #[tokio::test]
    async fn ws_relay_registers_and_forwards_opaque_blobs() {
        let relay = Arc::new(Mutex::new(WsRelay::new(4, 90))); // low difficulty = fast
        tokio::spawn(maintenance_loop(relay.clone()));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, peer)) = listener.accept().await else { break };
                let relay = relay.clone();
                tokio::spawn(async move {
                    let Ok(ws) = tokio_tungstenite::accept_async(stream).await else { return };
                    handle_connection(ws, peer, relay).await;
                });
            }
        });

        let token_a = [0xAAu8; 32];
        let token_b = [0xBBu8; 32];
        let (mut a_sink, _a_source) = connect_and_register(addr, token_a).await;
        let (_b_sink, mut b_source) = connect_and_register(addr, token_b).await;

        // A forwards an opaque blob to B.
        let blob = vec![0xDEu8, 0xAD, 0xBE, 0xEF];
        let fwd = encode(
            Tag::Forward,
            &ForwardMsg { session_token: token_b, pow_nonce: 0, sender_seq: 7, ciphertext: blob.clone() },
        )
        .unwrap_or_default();
        a_sink.send(Message::Binary(fwd.into())).await.unwrap();

        // B receives the DeliveredMsg with the exact opaque blob.
        for _ in 0..8 {
            if let Some(Ok(Message::Binary(f))) = b_source.next().await {
                if let Some((Tag::Ack, body)) = split(&f) {
                    if let Ok(d) = bincode::deserialize::<DeliveredMsg>(body) {
                        assert_eq!(d.ciphertext, blob, "B must receive the exact opaque blob");
                        assert_eq!(d.sender_seq, 7);
                        return;
                    }
                }
            }
        }
        panic!("B never received the forwarded blob");
    }
}