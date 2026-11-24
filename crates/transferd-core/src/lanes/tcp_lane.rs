//! TCP transport lane — streams encrypted chunks over a persistent TCP connection.
//!
//! ## Wire framing
//!
//! ```text
//! ┌────────────┬──────┬──────────────┬─────────────────┬────────────────────────┐
//! │ len: u32 BE│ type: u8           │                 │                          │
//! └────────────┴──────┴──────────────┴─────────────────┴────────────────────────┘
//!   DATA (0):   [nonce: 12][gcm_tag: 16][ciphertext = bincode(WireChunk)]
//!   ACK  (1):   [session_id: 16][gsn: 8]
//!   PING (2):   [nonce: 8][sent_ts: 8]
//!   PONG (3):   [nonce: 8][sent_ts: 8]
//! ```
//!
//! `len` covers everything after the length prefix (type + body). AAD for DATA
//! frames is the ciphertext length as u64 LE (reconstructible by the receiver).
//! Control frames are unencrypted (acks/pings reveal no payload).

use crate::transport::{Chunk, ControlMsg, LaneMetrics, TransportError, TransportLane, WireChunk};
use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use transferd_crypto::{DmiDecryptor, DmiEncryptor};

const HEADER_LEN: usize = 4;      // u32 BE frame length prefix
const TYPE_LEN: usize   = 1;
const NONCE_LEN: usize  = 12;
const TAG_LEN: usize    = 16;
const OVERHEAD: usize   = NONCE_LEN + TAG_LEN; // 28 bytes of crypto overhead per DATA frame

const TYPE_DATA: u8 = 0;
const TYPE_ACK: u8  = 1;
const TYPE_PING: u8 = 2;
const TYPE_PONG: u8 = 3;

// ---------------------------------------------------------------------------
// TcpLane
// ---------------------------------------------------------------------------

pub struct TcpLane {
    id: u32,
    metrics: Arc<LaneMetrics>,
    writer: Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
    seq: AtomicU64,
    encryptor: Arc<Mutex<DmiEncryptor>>,
    inbox: Mutex<mpsc::Receiver<Chunk>>,
    control_inbox: Mutex<mpsc::Receiver<ControlMsg>>,
    alive: Arc<AtomicBool>,
}

impl TcpLane {
    pub async fn connect(
        id: u32,
        addr: SocketAddr,
        send_key: &[u8; 32],
        recv_key: &[u8; 32],
    ) -> Result<Self, std::io::Error> {
        let stream = TcpStream::connect(addr).await?;
        Self::from_stream(id, stream, send_key, recv_key)
    }

    pub async fn accept_one(
        id: u32,
        bind_addr: SocketAddr,
        send_key: &[u8; 32],
        recv_key: &[u8; 32],
    ) -> Result<(SocketAddr, Self), std::io::Error> {
        let listener = TcpListener::bind(bind_addr).await?;
        let local_addr = listener.local_addr()?;
        let (stream, _peer) = listener.accept().await?;
        Ok((local_addr, Self::from_stream(id, stream, send_key, recv_key)?))
    }

    pub fn from_stream(
        id: u32,
        stream: TcpStream,
        send_key: &[u8; 32],
        recv_key: &[u8; 32],
    ) -> Result<Self, std::io::Error> {
        let encryptor = Arc::new(Mutex::new(DmiEncryptor::new(send_key)));
        let decryptor = Arc::new(Mutex::new(DmiDecryptor::new(recv_key)));
        let alive = Arc::new(AtomicBool::new(true));
        let metrics = Arc::new(LaneMetrics::default());
        // Conservative defaults; updated by the LaneHealthMonitor in production.
        metrics.bandwidth_bps.store(100_000_000, Ordering::Relaxed); // 100 Mbps
        metrics.rtt_ms.store(5_000, Ordering::Relaxed);              // 5 ms (stored as µs×1000)

        let (reader, writer) = stream.into_split();
        let writer = Arc::new(Mutex::new(writer));
        let (tx, rx) = mpsc::channel::<Chunk>(256);
        let (control_tx, control_rx) = mpsc::channel::<ControlMsg>(64);

        tokio::spawn(recv_task(
            reader,
            writer.clone(),
            decryptor,
            tx,
            control_tx,
            alive.clone(),
            metrics.clone(),
        ));

        Ok(Self {
            id,
            metrics,
            writer,
            seq: AtomicU64::new(0),
            encryptor,
            inbox: Mutex::new(rx),
            control_inbox: Mutex::new(control_rx),
            alive,
        })
    }

    /// Send an RTT ping (the peer echoes it back as a PONG).
    pub async fn send_ping(&self) {
        let nonce: [u8; 8] = self.seq.fetch_add(1, Ordering::Relaxed).to_le_bytes();
        let sent_ts = now_micros();
        let mut body = Vec::with_capacity(16);
        body.extend_from_slice(&nonce);
        body.extend_from_slice(&sent_ts.to_le_bytes());
        let frame = build_frame(TYPE_PING, &body);
        if self.writer.lock().await.write_all(&frame).await.is_ok() {
            let _ = self.seq.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[async_trait]
impl TransportLane for TcpLane {
    fn id(&self) -> u32 { self.id }
    fn metrics(&self) -> Arc<LaneMetrics> { self.metrics.clone() }
    fn capacity(&self) -> usize { if self.alive.load(Ordering::Relaxed) { 64 } else { 0 } }
    fn is_alive(&self) -> bool { self.alive.load(Ordering::Relaxed) }

    async fn send(&self, chunk: Chunk) -> Result<(), TransportError> {
        let wire = WireChunk::from(&chunk);
        let plaintext = bincode::serialize(&wire)
            .map_err(|_| TransportError::ProtocolViolation)?;

        let gsn = chunk.gsn.0;
        let nonce = DmiEncryptor::nonce_for(gsn, chunk.key_epoch);
        let aad = (plaintext.len() as u64).to_le_bytes();

        let (gcm_tag, ciphertext) = {
            let enc = self.encryptor.lock().await;
            let mut buf = plaintext;
            let tag = enc
                .encrypt_detached(&mut buf, &nonce, &aad)
                .map_err(|_| TransportError::Encrypted)?;
            (tag, buf)
        };

        // DATA body: [nonce][tag][ciphertext]
        let mut body = Vec::with_capacity(OVERHEAD + ciphertext.len());
        body.extend_from_slice(&nonce);
        body.extend_from_slice(&gcm_tag);
        body.extend_from_slice(&ciphertext);
        let frame = build_frame(TYPE_DATA, &body);

        let mut writer = self.writer.lock().await;
        writer
            .write_all(&frame)
            .await
            .map_err(|e| TransportError::LinkDown(e.to_string()))?;

        self.metrics.record_sent_bytes(frame.len() as u64);
        let _ = self.seq.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    async fn recv(&mut self) -> Option<Result<Chunk, TransportError>> {
        self.inbox.lock().await.recv().await.map(Ok)
    }

    async fn try_recv(&mut self) -> Option<Result<Chunk, TransportError>> {
        use tokio::sync::mpsc::error::TryRecvError;
        match self.inbox.lock().await.try_recv() {
            Ok(chunk) => Some(Ok(chunk)),
            Err(TryRecvError::Empty) | Err(TryRecvError::Disconnected) => None,
        }
    }

    async fn try_recv_control(&mut self) -> Option<ControlMsg> {
        use tokio::sync::mpsc::error::TryRecvError;
        match self.control_inbox.lock().await.try_recv() {
            Ok(msg) => Some(msg),
            Err(TryRecvError::Empty) | Err(TryRecvError::Disconnected) => None,
        }
    }

    fn ping_interval(&self) -> Option<std::time::Duration> {
        Some(std::time::Duration::from_secs(1))
    }

    async fn ping(&self) {
        self.send_ping().await;
    }
}

/// Build a frame: `[len: u32 BE][type: u8][body]`.
fn build_frame(frame_type: u8, body: &[u8]) -> Vec<u8> {
    let len = (TYPE_LEN + body.len()) as u32;
    let mut frame = Vec::with_capacity(HEADER_LEN + len as usize);
    frame.extend_from_slice(&len.to_be_bytes());
    frame.push(frame_type);
    frame.extend_from_slice(body);
    frame
}

// ---------------------------------------------------------------------------
// Background receive task
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn recv_task(
    mut reader: tokio::net::tcp::OwnedReadHalf,
    writer: Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
    decryptor: Arc<Mutex<DmiDecryptor>>,
    tx: mpsc::Sender<Chunk>,
    control_tx: mpsc::Sender<ControlMsg>,
    alive: Arc<AtomicBool>,
    metrics: Arc<LaneMetrics>,
) {
    let mut len_buf = [0u8; HEADER_LEN];
    loop {
        match reader.read_exact(&mut len_buf).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let frame_len = u32::from_be_bytes(len_buf) as usize;
        if !(1..=64 * 1024).contains(&frame_len) {
            metrics.record_error(10);
            break; // malformed frame — close connection
        }

        let mut body = vec![0u8; frame_len];
        if reader.read_exact(&mut body).await.is_err() { break; }

        let frame_type = body[0];
        let payload = &body[1..];

        match frame_type {
            TYPE_DATA => {
                if payload.len() < OVERHEAD {
                    metrics.record_error(10);
                    continue;
                }
                let Ok(nonce) = <[u8; NONCE_LEN]>::try_from(&payload[..NONCE_LEN]) else { continue };
                let Ok(gcm_tag) = <[u8; TAG_LEN]>::try_from(&payload[NONCE_LEN..OVERHEAD]) else { continue };
                let mut ct = payload[OVERHEAD..].to_vec();

                let aad = (ct.len() as u64).to_le_bytes();
                let ok = {
                    let dec = decryptor.lock().await;
                    dec.decrypt_verify(&mut ct, &nonce, &gcm_tag, &aad).is_ok()
                };
                if !ok {
                    metrics.record_error(10);
                    continue;
                }
                let Ok(wire) = bincode::deserialize::<WireChunk>(&ct) else { continue };
                let chunk = Chunk::from(wire);

                // Auto-ack so the peer can free its in-flight budget.
                let mut ack = Vec::with_capacity(24);
                ack.extend_from_slice(&chunk.session_id.0);
                ack.extend_from_slice(&chunk.gsn.0.to_le_bytes());
                let ack_frame = build_frame(TYPE_ACK, &ack);
                if writer.lock().await.write_all(&ack_frame).await.is_err() {
                    break;
                }

                if tx.send(chunk).await.is_err() {
                    break;
                }
            }
            TYPE_ACK => {
                if payload.len() < 24 {
                    continue;
                }
                let mut session_id = [0u8; 16];
                session_id.copy_from_slice(&payload[..16]);
                let gsn = u64::from_le_bytes(payload[16..24].try_into().unwrap_or([0u8; 8]));
                let _ = control_tx.try_send(ControlMsg::Ack { session_id, gsn });
            }
            TYPE_PING => {
                // Echo back as PONG.
                if writer.lock().await.write_all(&build_frame(TYPE_PONG, payload)).await.is_err() {
                    break;
                }
            }
            TYPE_PONG => {
                if payload.len() >= 16 {
                    let mut nonce = [0u8; 8];
                    nonce.copy_from_slice(&payload[..8]);
                    let sent_ts = u64::from_le_bytes(payload[8..16].try_into().unwrap_or([0u8; 8]));
                    let _ = control_tx.try_send(ControlMsg::Pong { nonce, sent_ts });
                }
            }
            _ => { metrics.record_error(10); }
        }
    }
    alive.store(false, Ordering::Relaxed);
}

fn now_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64
}
