//! The outbox: messages and files sent while the peer could not be reached are delivered once it can be.
//!
//! A send stores the message as "pending". When a session to the peer exists it goes on the wire at once; when
//! none does, the message waits here. The transport's retry loop calls [`flush`] every couple of seconds for each
//! contact with pending messages: once a session is up, every pending message that is not already queued on it is
//! rebuilt from the store and queued. Files keep their source path in the (encrypted, persisted) settings map under
//! `outbox.file.<msg_id>`, so they survive a daemon restart too without changing the store's schema.
//!
//! Transfers are tracked by the message id of the file: outbound progress counts the chunks the lanes actually
//! dispatched, and completes on the receiver's acknowledgement. Paused transfers (`transfer.paused.<id>`) are left
//! out of the flush until resumed.

use crate::state::DaemonState;
use crate::wire::WireMsg;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

/// Bytes per file chunk on the wire.
pub const CHUNK: usize = 30 * 1024;
/// Files are read into memory to be chunked; larger ones are refused up front.
pub const MAX_FILE: u64 = 200 * 1024 * 1024;

pub fn file_key(msg_id: &str) -> String {
    format!("outbox.file.{msg_id}")
}

pub fn paused_key(transfer_id: &str) -> String {
    format!("transfer.paused.{transfer_id}")
}

/// When each outbound transfer started sending (for its speed); not persisted.
fn started() -> &'static Mutex<HashMap<String, Instant>> {
    static S: std::sync::OnceLock<Mutex<HashMap<String, Instant>>> = std::sync::OnceLock::new();
    S.get_or_init(Default::default)
}

/// Split a file into wire messages for `msg_id`.
pub fn file_chunks(sender: &str, msg_id: &str, file_name: &str, mime: &str, ts: u64, data: &[u8]) -> Vec<WireMsg> {
    let total = data.len().div_ceil(CHUNK).max(1) as u32;
    let parts: Vec<&[u8]> = if data.is_empty() { vec![&[][..]] } else { data.chunks(CHUNK).collect() };
    parts
        .into_iter()
        .enumerate()
        .map(|(i, part)| WireMsg::File {
            sender: sender.to_string(),
            msg_id: msg_id.to_string(),
            file_name: file_name.to_string(),
            file_size: data.len() as u64,
            mime: mime.to_string(),
            ts,
            seq: i as u32,
            total_chunks: total,
            data: part.to_vec(),
        })
        .collect()
}

impl DaemonState {
    /// A chunk (or a whole text) of `msg_id` went out on a lane.
    pub fn note_dispatched(&mut self, msg_id: &str) {
        if let Some(t) = self.transfers.iter_mut().find(|t| t.id == msg_id && t.outbound) {
            let begun = *started().lock().entry(msg_id.to_string()).or_insert_with(Instant::now);
            t.xferd_bytes = (t.xferd_bytes + CHUNK as u64).min(t.size_bytes);
            let secs = begun.elapsed().as_secs_f64().max(0.001);
            t.bps = (t.xferd_bytes as f64 * 8.0 / secs) as u64;
        }
    }

    /// The peer acknowledged `msg_id` (the whole file arrived): the transfer is complete and leaves the outbox.
    pub fn note_delivered(&mut self, msg_id: &str) {
        if let Some(t) = self.transfers.iter_mut().find(|t| t.id == msg_id) {
            t.xferd_bytes = t.size_bytes;
            t.lanes_active = 0;
        }
        started().lock().remove(msg_id);
        self.settings.remove(&file_key(msg_id));
        self.settings.remove(&paused_key(msg_id));
    }

    /// An inbound file chunk arrived (receiver-side progress).
    pub fn note_inbound_chunk(&mut self, sender: &str, msg_id: &str, file_name: &str, size: u64, chunk: usize, done: bool) {
        let id = format!("in-{}-{msg_id}", &sender[..sender.len().min(12)]);
        let name = self.contacts.iter().find(|c| c.id == sender).map(|c| c.name.clone()).unwrap_or_else(|| sender.to_string());
        let begun = *started().lock().entry(id.clone()).or_insert_with(Instant::now);
        let t = match self.transfers.iter_mut().position(|t| t.id == id) {
            Some(i) => &mut self.transfers[i],
            None => {
                self.transfers.push(crate::state::Transfer {
                    id: id.clone(),
                    contact_name: name,
                    file_name: file_name.to_string(),
                    size_bytes: size,
                    xferd_bytes: 0,
                    outbound: false,
                    lanes_active: 1,
                    bps: 0,
                });
                let last = self.transfers.len() - 1;
                &mut self.transfers[last]
            }
        };
        t.xferd_bytes = if done { size } else { (t.xferd_bytes + chunk as u64).min(size) };
        t.bps = (t.xferd_bytes as f64 * 8.0 / begun.elapsed().as_secs_f64().max(0.001)) as u64;
        if done {
            t.lanes_active = 0;
            started().lock().remove(&id);
        }
    }

    /// The outbound 1:1 messages to `contact_id` still waiting for a lane (not paused).
    fn pending_for(&self, contact_id: &str) -> Vec<crate::state::StoredMessage> {
        self.messages
            .get(contact_id)
            .map(|v| {
                v.iter()
                    .filter(|m| m.outbound && m.status == "pending" && m.group_id.is_none())
                    .filter(|m| !self.settings.contains_key(&paused_key(&m.id)))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Queue every pending message for `contact_id` that is not already queued on its session. Returns how many were
/// queued. Does nothing without a session (the caller establishes one first).
pub async fn flush(state: &Arc<Mutex<DaemonState>>, contact_id: &str) -> usize {
    let transport = state.lock().transport.clone();
    let mut pm = transport.lock().await;
    if !pm.has_session(contact_id) {
        return 0;
    }
    let queued = pm.queued_msg_ids(contact_id);
    let (pending, sender, paths) = {
        let s = state.lock();
        let pending: Vec<_> = s.pending_for(contact_id).into_iter().filter(|m| !queued.contains(&m.id)).collect();
        let sender = s.identity.as_ref().map(|i| i.public_key.clone()).unwrap_or_default();
        let paths: HashMap<String, String> =
            pending.iter().filter_map(|m| s.settings.get(&file_key(&m.id)).map(|p| (m.id.clone(), p.clone()))).collect();
        (pending, sender, paths)
    };
    let mut n = 0;
    let mut failed = vec![];
    for m in pending {
        let wires = if m.content_type == "file" {
            let Some(path) = paths.get(&m.id) else {
                failed.push((m.id.clone(), "the file's path was not kept".to_string()));
                continue;
            };
            match std::fs::read(path) {
                Ok(data) if data.len() as u64 <= MAX_FILE => file_chunks(&sender, &m.id, &m.file_name, &m.file_mime, m.timestamp_ts, &data),
                Ok(_) => {
                    failed.push((m.id.clone(), "the file is too large".into()));
                    continue;
                }
                Err(e) => {
                    failed.push((m.id.clone(), format!("{path}: {e}")));
                    continue;
                }
            }
        } else {
            vec![WireMsg::Text {
                sender: sender.clone(),
                msg_id: m.id.clone(),
                text: m.text.clone(),
                ts: m.timestamp_ts,
                group_id: None,
                reply_to: m.reply_to.clone(),
            }]
        };
        for w in wires {
            if let Ok(payload) = w.encode() {
                let _ = pm.send_message(contact_id, m.id.clone(), bytes::Bytes::from(payload));
            }
        }
        n += 1;
    }
    drop(pm);
    if !failed.is_empty() {
        let mut s = state.lock();
        for (id, why) in failed {
            tracing::warn!("[outbox] {id} cannot be sent: {why}");
            s.mark_status(&id, "failed");
            s.settings.remove(&file_key(&id));
        }
        s.try_save();
    }
    if n > 0 {
        tracing::info!("[outbox] queued {n} waiting message(s) for {contact_id}");
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn files_split_into_numbered_chunks() {
        let data = vec![7u8; CHUNK * 2 + 5];
        let parts = file_chunks("me", "m1", "f.bin", "application/octet-stream", 1, &data);
        assert_eq!(parts.len(), 3);
        assert!(matches!(&parts[2], WireMsg::File { seq: 2, total_chunks: 3, data, file_size, .. }
                         if data.len() == 5 && *file_size == (CHUNK * 2 + 5) as u64));
        assert_eq!(file_chunks("me", "m2", "empty", "", 1, &[]).len(), 1, "an empty file is still one message");
    }

    #[test]
    fn progress_counts_chunks_and_completes_on_ack() {
        let mut s = DaemonState::default();
        s.transfers.push(crate::state::Transfer {
            id: "m1".into(), contact_name: "Bob".into(), file_name: "f".into(), size_bytes: (CHUNK * 3) as u64,
            xferd_bytes: 0, outbound: true, lanes_active: 1, bps: 0,
        });
        s.settings.insert(file_key("m1"), "C:/f".into());
        s.note_dispatched("m1");
        assert_eq!(s.transfers[0].xferd_bytes, CHUNK as u64);
        s.note_delivered("m1");
        assert_eq!(s.transfers[0].xferd_bytes, (CHUNK * 3) as u64);
        assert!(!s.settings.contains_key(&file_key("m1")), "delivered files leave the outbox");
        s.note_inbound_chunk("abcdef", "x", "in.bin", 100, 60, false);
        s.note_inbound_chunk("abcdef", "x", "in.bin", 100, 40, true);
        let t = s.transfers.iter().find(|t| !t.outbound).map(|t| (t.xferd_bytes, t.lanes_active));
        assert_eq!(t, Some((100, 0)));
    }
}
