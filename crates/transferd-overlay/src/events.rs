//! Events and the audit trail.
//!
//! Two different things, deliberately:
//!
//! * An **event** is live state: a peer came up, a route changed, a service was exposed. It is
//!   what `overlay.events` streams, and it is kept in a small ring so a client that connects
//!   late still sees what it missed.
//! * An **audit record** is history: every expose, connect, disconnect and refusal, appended to
//!   a file that outlives the process. This is the trail an operator reads to answer "who used
//!   this service, when, and from where".

use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

/// How many events are kept in memory for a late subscriber.
pub const HISTORY: usize = 512;

/// What the overlay announces.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverlayEvent {
    /// Unix seconds.
    pub at: u64,
    /// `peer.up`, `peer.down`, `route.change`, `service.expose`, `service.unexpose`,
    /// `connect.open`, `connect.close`, `connect.denied`.
    pub kind: String,
    /// The peer or node this is about, when there is one.
    #[serde(default)]
    pub node_id: String,
    /// A short human-readable detail.
    #[serde(default)]
    pub detail: String,
}

impl OverlayEvent {
    /// A new event, stamped with the current time.
    pub fn new(kind: &str, node_id: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            at: now_secs(),
            kind: kind.into(),
            node_id: node_id.into(),
            detail: detail.into(),
        }
    }
}

/// Unix seconds.
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// A ring of recent events, for `overlay.events`.
pub struct EventLog {
    recent: std::sync::Mutex<VecDeque<OverlayEvent>>,
    bus: tokio::sync::broadcast::Sender<OverlayEvent>,
}

impl Default for EventLog {
    fn default() -> Self {
        Self::new()
    }
}

impl EventLog {
    /// A log with a live broadcast channel behind it.
    pub fn new() -> Self {
        let (bus, _) = tokio::sync::broadcast::channel(HISTORY);
        Self {
            recent: std::sync::Mutex::new(VecDeque::with_capacity(HISTORY)),
            bus,
        }
    }

    /// Record an event and hand it to anyone listening.
    pub fn push(&self, event: OverlayEvent) {
        if let Ok(mut recent) = self.recent.lock() {
            if recent.len() >= HISTORY {
                recent.pop_front();
            }
            recent.push_back(event.clone());
        }
        let _ = self.bus.send(event);
    }

    /// Subscribe to future events.
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<OverlayEvent> {
        self.bus.subscribe()
    }

    /// The most recent events, oldest first.
    pub fn recent(&self, limit: usize) -> Vec<OverlayEvent> {
        let Ok(recent) = self.recent.lock() else {
            return Vec::new();
        };
        recent.iter().rev().take(limit).rev().cloned().collect()
    }

    /// How many events are remembered.
    pub fn len(&self) -> usize {
        self.recent.lock().map(|r| r.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// One line of the audit trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub at: u64,
    /// What happened: `expose`, `unexpose`, `connect`, `disconnect`, `denied`, `pair`.
    pub action: String,
    /// The node that did it (this node, for a local action).
    #[serde(default)]
    pub actor: String,
    /// The service involved.
    #[serde(default)]
    pub service: String,
    /// The peer it involved.
    #[serde(default)]
    pub peer: String,
    /// The local address involved, when there is one.
    #[serde(default)]
    pub local_addr: String,
    /// The route used, when there is one.
    #[serde(default)]
    pub route: String,
    /// Bytes moved, when it is a transfer.
    #[serde(default)]
    pub bytes: u64,
    /// Why it was refused, when it was.
    #[serde(default)]
    pub error: String,
}

impl AuditRecord {
    /// A record with the current timestamp.
    pub fn new(action: &str) -> Self {
        Self {
            at: now_secs(),
            action: action.into(),
            actor: String::new(),
            service: String::new(),
            peer: String::new(),
            local_addr: String::new(),
            route: String::new(),
            bytes: 0,
            error: String::new(),
        }
    }
}

/// The audit trail: an in-memory ring plus an optional append-only file.
pub struct Audit {
    recent: std::sync::Mutex<VecDeque<AuditRecord>>,
    path: Option<std::path::PathBuf>,
}

impl Audit {
    /// A trail that writes to `path`, or only keeps the ring when there is none.
    pub fn new(path: Option<std::path::PathBuf>) -> Self {
        Self {
            recent: std::sync::Mutex::new(VecDeque::with_capacity(256)),
            path,
        }
    }

    /// Record one action.
    pub fn record(&self, record: AuditRecord) {
        if let Some(path) = &self.path {
            if let Some(dir) = path.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
            {
                use std::io::Write as _;
                let _ = writeln!(f, "{}", serde_json::to_string(&record).unwrap_or_default());
            }
        }
        if let Ok(mut recent) = self.recent.lock() {
            if recent.len() >= 256 {
                recent.pop_front();
            }
            recent.push_back(record);
        }
    }

    /// The most recent records, newest last.
    pub fn recent(&self, limit: usize) -> Vec<AuditRecord> {
        let Ok(recent) = self.recent.lock() else {
            return Vec::new();
        };
        recent.iter().rev().take(limit).rev().cloned().collect()
    }

    /// Where the trail is written, if anywhere.
    pub fn path(&self) -> Option<&std::path::Path> {
        self.path.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn events_are_broadcast_and_kept_for_a_late_subscriber() {
        let log = EventLog::new();
        let mut rx = log.subscribe();
        log.push(OverlayEvent::new("peer.up", "aa", "relay"));
        log.push(OverlayEvent::new("route.change", "aa", "holepunch up"));
        assert_eq!(rx.recv().await.expect("first").kind, "peer.up");
        assert_eq!(rx.recv().await.expect("second").kind, "route.change");
        assert_eq!(log.recent(10).len(), 2);
        assert_eq!(log.recent(1).len(), 1, "the limit is honoured");
        assert_eq!(log.recent(1)[0].kind, "route.change", "newest last");
    }

    #[test]
    fn the_event_ring_is_bounded() {
        let log = EventLog::new();
        for i in 0..(HISTORY + 50) {
            log.push(OverlayEvent::new("route.change", "aa", format!("{i}")));
        }
        assert_eq!(log.len(), HISTORY, "the ring never grows past its bound");
    }

    #[test]
    fn the_audit_trail_is_appended_to_its_file() {
        let dir = std::env::temp_dir().join(format!("tdov-audit-{}", std::process::id()));
        let path = dir.join("audit.jsonl");
        let audit = Audit::new(Some(path.clone()));
        let mut r = AuditRecord::new("expose");
        r.service = "http".into();
        r.local_addr = "127.0.0.1:8000".into();
        audit.record(r.clone());
        let mut denied = AuditRecord::new("denied");
        denied.service = "ssh".into();
        denied.peer = "bb".into();
        denied.error = "not in the access list".into();
        audit.record(denied);
        let text = std::fs::read_to_string(&path).expect("the trail is on disk");
        assert_eq!(text.lines().count(), 2);
        assert!(text.contains("not in the access list"));
        assert_eq!(audit.recent(10).len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
