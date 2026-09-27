//! Daemon transport — the inbound peer-connection listener.
//!
//! Accepts direct TCP connections from peers, completes the X25519 handshake,
//! wraps the connection in a `TcpLane`, and applies every inbound wire message
//! to daemon state (storing messages, reassembling files, answering acks).

use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use bytes::Bytes;
use parking_lot::Mutex as PkMutex;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

use transferd_core::transport::TransportLane;
use transferd_core::types::{Gsn, SessionId};
use transferd_crypto::ratchet::{DoubleRatchet, RatchetMessage};

use crate::handshake_manager::HandshakeManager;
use crate::peer_manager::directional_keys;
use crate::state::DaemonState;
use crate::wire::WireMsg;

/// Decode a chunk payload through the per-message ratchet.
fn ratchet_message(payload: &[u8], ratchet: &mut DoubleRatchet) -> Option<WireMsg> {
    let rm: RatchetMessage = bincode::deserialize(payload).ok()?;
    let plain = ratchet.decrypt(&rm).ok()?;
    WireMsg::decode(&plain).ok()
}

/// Per-connection file-reassembly buffer keyed by the sender's message id.
struct InboundFile {
    name: String,
    size: u64,
    total_chunks: u32,
    chunks: HashMap<u32, Vec<u8>>,
}

/// Bind the daemon's inbound peer listener on `bind` and spawn the accept loop.
///
/// Returns the actual bound address (useful when `bind` uses port 0).
pub async fn spawn_inbound_listener(
    state: Arc<PkMutex<DaemonState>>,
    bind: std::net::SocketAddr,
) -> io::Result<std::net::SocketAddr> {
    let listener = TcpListener::bind(bind).await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    tracing::info!("[transport] inbound connection from {peer}");
                    let st = state.clone();
                    tokio::spawn(async move {
                        handle_inbound_connection(st, stream).await;
                    });
                }
                Err(e) => {
                    tracing::error!("[transport] accept error: {e}");
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        }
    });
    Ok(addr)
}

/// Spawn the background transport tick: flush queued messages over active lanes
/// and apply any inbound events (acks, read receipts, unsolicited messages).
/// Every 50 ms; marks dispatched messages "sent" and applies inbound WireMsgs.
pub fn spawn_transport_tick(state: Arc<PkMutex<DaemonState>>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(50));
        loop {
            interval.tick().await;
            let transport = state.lock().transport.clone();
            let events = transport.lock().await.process_all_sessions().await;
            if !events.sent_msg_ids.is_empty() || !events.inbound.is_empty() {
                let mut s = state.lock();
                for id in &events.sent_msg_ids {
                    s.mark_status(id, "sent");
                }
                for (_, msg) in events.inbound {
                    let _ = s.apply_inbound(&msg);
                }
                s.try_save();
            }
        }
    });
}

/// Handle one inbound peer connection: handshake → lane → message loop.
pub async fn handle_inbound_connection(
    state: Arc<PkMutex<DaemonState>>,
    mut stream: TcpStream,
) {
    // Complete the authenticated hybrid handshake as responder.
    let identity = match state.lock().hybrid_signing_key() {
        Some(id) => id,
        None => {
            tracing::debug!("[transport] rejecting inbound connection: no identity");
            return;
        }
    };
    let handshake = HandshakeManager::new();
    let (session_key, peer_identity) = match handshake.run_responder(&mut stream, &identity).await {
        Ok(k) => k,
        Err(e) => {
            tracing::debug!("[transport] handshake rejected: {e}");
            return;
        }
    };

    // Record the verified inbound identity (trust-on-first-use) for a known
    // contact. A previously-recorded identity that differs means the peer's
    // keys changed or a MITM is present — refuse the connection.
    let peer_hybrid_pk = peer_identity.to_bytes();
    let peer_pk_hex = hex::encode(&peer_hybrid_pk[..32]);
    {
        let mut s = state.lock();
        if s.contacts.iter().any(|c| c.id == peer_pk_hex)
            && !s.record_verified_identity(&peer_pk_hex, &hex::encode(&peer_hybrid_pk))
        {
            tracing::warn!(
                "[transport] refusing connection from {peer_pk_hex}: peer identity changed since first contact"
            );
            return;
        }
    }

    // Responder: send with role-1 key, receive with role-0 key.
    let (initiator_send, initiator_recv) = directional_keys(&session_key.key);
    let mut lane = match transferd_core::lanes::tcp_lane::TcpLane::from_stream(
        0x54435020,
        stream,
        &initiator_recv, // our recv key == initiator's send key
        &initiator_send, // our send key == initiator's recv key
    ) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("[transport] failed to create lane: {e}");
            return;
        }
    };

    let mut ack_gsn = 0u64;
    let mut files: HashMap<String, InboundFile> = HashMap::new();
    // Responder-side per-message ratchet (aligned with the initiator's).
    let mut ratchet = transferd_crypto::ratchet::DoubleRatchet::new(&session_key.key, false);

    while let Some(res) = lane.recv().await {
        let chunk = match res {
            Ok(c) => c,
            Err(_) => break,
        };
        let msg = match ratchet_message(&chunk.payload, &mut ratchet) {
            Some(m) => m,
            None => {
                tracing::debug!("[transport] dropping undecodable/unauth payload");
                continue;
            }
        };

        // Files accumulate here (TCP preserves order, so chunks are contiguous);
        // once complete they are written to disk and stored as a message.
        if let WireMsg::File { msg_id, file_name, file_size, mime, seq, total_chunks, data, .. } = &msg {
            // Inbound limit check: the RECEIVER's own limits decide what it
            // accepts. A file that exceeds the cap is dropped wholesale.
            let content_type = relayd::limits::ContentType::from_mime(mime);
            let cap = crate::limits::daemon_limits()
                .cap_for(content_type)
                .unwrap_or(u64::MAX);
            if *file_size > cap {
                tracing::warn!(
                    "[transport] rejecting inbound {content_type:?} '{}' ({} > cap {})",
                    file_name,
                    file_size,
                    cap,
                );
                continue;
            }
            let entry = files.entry(msg_id.clone()).or_insert(InboundFile {
                name: file_name.clone(),
                size: *file_size,
                total_chunks: *total_chunks,
                chunks: HashMap::new(),
            });
            entry.chunks.insert(*seq, data.clone());

            if entry.chunks.len() as u32 >= entry.total_chunks {
                if let Some(f) = files.remove(msg_id) {
                    if let Some(path) = write_inbound_file(&f) {
                        tracing::info!(
                            "[transport] received file '{}' ({} bytes) → {}",
                            f.name, f.size, path.display()
                        );
                    }
                }
            }
        }

        // Inbound text cap (the receiver's message limit).
        if let WireMsg::Text { text, .. } = &msg {
            let cap = crate::limits::daemon_limits()
                .cap_for(relayd::limits::ContentType::Message)
                .unwrap_or(u64::MAX);
            if text.len() as u64 > cap {
                tracing::warn!("[transport] rejecting inbound text ({} > cap {})", text.len(), cap);
                continue;
            }
        }

        // Drop messages from blocked contacts (blocked peers are still served
        // acks so they cannot infer the block by timing).
        let blocked = {
            let s = state.lock();
            match &msg {
                WireMsg::Text { sender, .. } | WireMsg::File { sender, .. } => s
                    .contacts
                    .iter()
                    .any(|c| c.id == *sender && c.blocked),
                _ => false,
            }
        };
        if blocked {
            tracing::info!("[transport] dropped message from blocked contact");
            continue;
        }

        // Apply to state; reply with an ack when the message expects one.
        let reply = {
            let mut s = state.lock();
            s.apply_inbound(&msg)
        };
        if let Some(ack) = reply {
            if let Ok(payload) = ack.encode() {
                // Ratchet the ack (per-message key) before sending.
                let ack_payload = ratchet
                    .encrypt(&payload)
                    .ok()
                    .and_then(|rm| bincode::serialize(&rm).ok())
                    .unwrap_or(payload);
                let ack_chunk = transferd_core::transport::Chunk {
                    gsn: Gsn(ack_gsn),
                    session_id: SessionId(chunk.session_id.0),
                    payload: Bytes::from(ack_payload),
                    key_epoch: 0,
                    qos_critical: false,
                };
                if lane.send(ack_chunk).await.is_err() {
                    break;
                }
                ack_gsn += 1;
            }
        }
    }
}

/// Write a fully reassembled inbound file to the downloads directory.
fn write_inbound_file(file: &InboundFile) -> Option<PathBuf> {
    let dir = downloads_dir();
    std::fs::create_dir_all(&dir).ok()?;
    // Avoid path traversal from untrusted file names.
    let safe_name = file.name.replace(['/', '\\'], "_");
    let path = dir.join(&safe_name);

    let mut buf = Vec::with_capacity(file.size as usize);
    for i in 0..file.total_chunks {
        buf.extend_from_slice(file.chunks.get(&i)?);
    }
    std::fs::write(&path, buf).ok()?;
    Some(path)
}

/// Platform data dir + `transferdaemon/downloads`, or `TRANSFERD_DOWNLOADS_DIR`
/// when set (used by tests and portable installs).
fn downloads_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("TRANSFERD_DOWNLOADS_DIR") {
        return PathBuf::from(dir);
    }
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("transferdaemon")
        .join("downloads")
}

/// Send an explicit read receipt over a connected lane (for future UI use).
#[allow(dead_code)]
pub async fn send_read_receipt(
    lane: &transferd_core::lanes::tcp_lane::TcpLane,
    msg_id: &str,
    session_id: SessionId,
    gsn: u64,
) -> io::Result<()> {
    let payload = WireMsg::Read { msg_id: msg_id.to_string() }.encode().map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, e.to_string())
    })?;
    lane.send(transferd_core::transport::Chunk {
        gsn: Gsn(gsn),
        session_id,
        payload: Bytes::from(payload),
        key_epoch: 0,
        qos_critical: false,
    })
    .await
    .map_err(|e| io::Error::other(e.to_string()))
}

/// Flush the shutdown of a connection's write half (best-effort).
#[allow(dead_code)]
async fn flush_write(stream: &mut TcpStream) {
    let _ = stream.flush().await;
}