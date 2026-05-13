//! TCP transport lane — streams encrypted chunks over a persistent TCP connection.
//!
//! ## Wire framing
//!
//! Every frame on the wire is:
//!
//! ```text
//! ┌────────────────┬──────────────┬─────────────────┬────────────────────────┐
//! │ frame_len: u32 │ nonce: [u8;12] │ gcm_tag: [u8;16] │ ciphertext: [u8; N]  │
//! │   (BE, = 28+N) │              │                 │ bincode(WireChunk)     │
//! └────────────────┴──────────────┴─────────────────┴────────────────────────┘
//! ```
//!
//! AAD is `frame_len` encoded as a 4-byte big-endian integer — small, unique per frame,
//! and reconstructible by the receiver before it reads the ciphertext.
//!
//! ## TLS upgrade
//!
//! To wrap this lane in TLS, replace `TcpStream` with `TlsStream<TcpStream>` from
//! `tokio-rustls`. The framing and encryption layers are unchanged.

use crate::transport::{Chunk, LaneMetrics, TransportError, TransportLane, WireChunk};
use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use transferd_crypto::{DmiDecryptor, DmiEncryptor};

const HEADER_LEN: usize = 4; // u32 BE frame length prefix
const NONCE_LEN: usize  = 12;
const TAG_LEN: usize    = 16;
const OVERHEAD: usize   = NONCE_LEN + TAG_LEN; // 28 bytes of crypto overhead per frame

// ---------------------------------------------------------------------------
// TcpLane
// ---------------------------------------------------------------------------

/// A `TransportLane` that streams encrypted chunks over a persistent TCP connection.
///
/// Both endpoints use this type:
/// - **Client** (`connect`): dials the server.
/// - **Server** (`accept_one`): waits for one incoming connection.
///
/// A background task feeds `recv()` by reading from the read half of the socket.
pub struct TcpLane {
    id: u32,
    metrics: Arc<LaneMetrics>,
    writer: Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
    seq: AtomicU64,
    encryptor: Arc<Mutex<DmiEncryptor>>,
    inbox: Mutex<mpsc::Receiver<Chunk>>,
    alive: Arc<AtomicBool>,
}

impl TcpLane {
    /// Connects to `addr` and returns a ready lane.
    pub async fn connect(
        id: u32,
        addr: SocketAddr,
        session_key: &[u8; 32],
    ) -> Result<Self, std::io::Error> {
        let stream = TcpStream::connect(addr).await?;
        Self::from_stream(id, stream, session_key)
    }

    /// Binds a listener on `addr`, waits for exactly one incoming connection, and
    /// returns both the bound address and the accepted lane.
    pub async fn accept_one(
        id: u32,
        bind_addr: SocketAddr,
        session_key: &[u8; 32],
    ) -> Result<(SocketAddr, Self), std::io::Error> {
        let listener = TcpListener::bind(bind_addr).await?;
        let local_addr = listener.local_addr()?;
        let (stream, _peer) = listener.accept().await?;
        Ok((local_addr, Self::from_stream(id, stream, session_key)?))
    }

    /// Creates a lane from an already-connected `TcpStream`. Useful in tests
    /// where the caller manages the `TcpListener` lifecycle to avoid port-race conditions.
    pub fn from_stream(id: u32, stream: TcpStream, session_key: &[u8; 32]) -> Result<Self, std::io::Error> {
        let encryptor = Arc::new(Mutex::new(DmiEncryptor::new(session_key)));
        let decryptor = Arc::new(Mutex::new(DmiDecryptor::new(session_key)));
        let alive = Arc::new(AtomicBool::new(true));
        let metrics = Arc::new(LaneMetrics::default());
        // Conservative defaults; updated by the ATE health monitor in production.
        metrics.bandwidth_bps.store(100_000_000, Ordering::Relaxed); // 100 Mbps
        metrics.rtt_ms.store(5_000, Ordering::Relaxed);              // 5 ms (stored as µs×1000)

        let (reader, writer) = stream.into_split();
        let (tx, rx) = mpsc::channel::<Chunk>(256);

        tokio::spawn(recv_task(reader, decryptor, tx, alive.clone(), metrics.clone()));

        Ok(Self {
            id,
            metrics,
            writer: Arc::new(Mutex::new(writer)),
            seq: AtomicU64::new(0),
            encryptor,
            inbox: Mutex::new(rx),
            alive,
        })
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
        // AAD = frame length as 4-byte BE. Unique per (gsn, epoch, payload size).
        let frame_body_len = (OVERHEAD + plaintext.len()) as u32;
        let aad = frame_body_len.to_be_bytes();

        let (gcm_tag, ciphertext) = {
            let enc = self.encryptor.lock().await;
            let mut buf = plaintext;
            let tag = enc
                .encrypt_detached(&mut buf, &nonce, &aad)
                .map_err(|_| TransportError::Encrypted)?;
            (tag, buf)
        };

        // Build the complete frame.
        let total = HEADER_LEN + OVERHEAD + ciphertext.len();
        let mut frame = Vec::with_capacity(total);
        frame.extend_from_slice(&frame_body_len.to_be_bytes()); // 4-byte length prefix
        frame.extend_from_slice(&nonce);                         // 12-byte nonce
        frame.extend_from_slice(&gcm_tag);                       // 16-byte GCM tag
        frame.extend_from_slice(&ciphertext);                    // encrypted WireChunk

        let mut writer = self.writer.lock().await;
        writer
            .write_all(&frame)
            .await
            .map_err(|e| TransportError::LinkDown(e.to_string()))?;

        let _ = self.seq.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    async fn recv(&mut self) -> Option<Result<Chunk, TransportError>> {
        self.inbox.lock().await.recv().await.map(Ok)
    }
}

// ---------------------------------------------------------------------------
// Background receive task
// ---------------------------------------------------------------------------

async fn recv_task(
    mut reader: tokio::net::tcp::OwnedReadHalf,
    decryptor: Arc<Mutex<DmiDecryptor>>,
    tx: mpsc::Sender<Chunk>,
    alive: Arc<AtomicBool>,
    metrics: Arc<LaneMetrics>,
) {
    let mut len_buf = [0u8; HEADER_LEN];
    loop {
        // Read the 4-byte length prefix.
        match reader.read_exact(&mut len_buf).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let frame_body_len = u32::from_be_bytes(len_buf) as usize;
        if frame_body_len < OVERHEAD || frame_body_len > 64 * 1024 {
            metrics.record_error(10);
            break; // malformed frame — close connection
        }

        let mut body = vec![0u8; frame_body_len];
        if reader.read_exact(&mut body).await.is_err() { break; }

        let nonce: [u8; NONCE_LEN] = body[..NONCE_LEN].try_into().unwrap();
        let gcm_tag: [u8; TAG_LEN] = body[NONCE_LEN..OVERHEAD].try_into().unwrap();
        let mut ct = body[OVERHEAD..].to_vec();

        let aad = (frame_body_len as u32).to_be_bytes();

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
        if tx.send(chunk).await.is_err() { break; }
    }
    alive.store(false, Ordering::Relaxed);
}
