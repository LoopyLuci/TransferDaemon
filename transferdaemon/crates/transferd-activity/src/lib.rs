//! The activity log: every error, warning, connection and call, kept in memory for the windows to show and in a
//! rotating file so it survives a restart.
//!
//! Events arrive from three places:
//! * `tracing`: every WARN and ERROR from any crate, and INFO from TransferDaemon's own crates (see [`ActivityLayer`]);
//! * explicit [`record`] calls at the points of access (the gRPC server, the control hub, the lanes and sessions);
//! * panics (see [`install_panic_hook`]).
//!
//! Secrets never reach the log: a field whose name says it holds a key, token, PIN or phrase is stored as
//! `[redacted]`.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Events kept in memory. The oldest go first.
pub const MEMORY_EVENTS: usize = 20_000;
/// The file rotates when it would grow past this.
pub const FILE_ROTATE_BYTES: u64 = 5 * 1024 * 1024;
/// Files kept: `activity.jsonl` and `activity.1.jsonl` ... `activity.{FILE_KEEP-1}.jsonl`.
pub const FILE_KEEP: usize = 3;
/// Most events a query returns when it names no limit.
pub const DEFAULT_LIMIT: usize = 500;
const FILE_NAME: &str = "activity.jsonl";
/// Field names containing one of these hold secrets; their values are never stored.
const SECRET_WORDS: &[&str] = &["key", "token", "secret", "pin", "phrase", "password", "passphrase", "auth", "signature"];

/// How serious an event is, least to most.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Debug,
    Info,
    Warn,
    Error,
}

impl Level {
    /// `debug`, `info`, `warn` (or `warning`), `error`; any case.
    pub fn parse(text: &str) -> Option<Level> {
        match text.trim().to_ascii_lowercase().as_str() {
            "debug" | "trace" => Some(Level::Debug),
            "info" => Some(Level::Info),
            "warn" | "warning" => Some(Level::Warn),
            "error" => Some(Level::Error),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Level::Debug => "debug",
            Level::Info => "info",
            Level::Warn => "warn",
            Level::Error => "error",
        }
    }
}

/// One thing that happened.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    /// Increases by one for every event this log records; resumes after a restart.
    pub seq: u64,
    /// Milliseconds since the Unix epoch.
    pub ts_ms: u64,
    pub level: Level,
    /// What kind of thing it is: `lanes`, `overlay`, `relay`, `api`, `gui`, `updates`, `store`, `security`, `panic`,
    /// `system`, or another name a caller chose.
    pub category: String,
    /// Where it came from: the module that logged it, or `daemon`, `hub`, `gui`.
    pub source: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, String>,
}

/// Which events a query returns.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Filter {
    /// Only events at this level or more serious.
    pub min_level: Option<Level>,
    /// Only events in this category.
    pub category: Option<String>,
    /// Only events whose message, category or source contains this text (case-insensitive).
    pub text: Option<String>,
    /// Only events after this sequence number.
    pub since_seq: u64,
    /// The newest this many matches. Zero means [`DEFAULT_LIMIT`].
    pub limit: usize,
}

impl Filter {
    pub fn matches(&self, event: &Event) -> bool {
        if event.seq <= self.since_seq {
            return false;
        }
        if self.min_level.is_some_and(|min| event.level < min) {
            return false;
        }
        if let Some(category) = &self.category {
            if !event.category.eq_ignore_ascii_case(category) {
                return false;
            }
        }
        if let Some(text) = &self.text {
            let needle = text.to_lowercase();
            if !needle.is_empty()
                && !event.message.to_lowercase().contains(&needle)
                && !event.category.to_lowercase().contains(&needle)
                && !event.source.to_lowercase().contains(&needle)
            {
                return false;
            }
        }
        true
    }
}

/// How many events the log holds at each level, since it started (or since the file was loaded).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Counts {
    pub debug: u64,
    pub info: u64,
    pub warn: u64,
    pub error: u64,
    /// Events the file writer could not keep up with (they are still in memory).
    pub not_written: u64,
}

/// The activity log. One per process; see [`global`].
pub struct Log {
    ring: Mutex<VecDeque<Event>>,
    next_seq: AtomicU64,
    counts: [AtomicU64; 4],
    not_written: AtomicU64,
    file: OnceLock<SyncSender<Event>>,
}

impl Default for Log {
    fn default() -> Self {
        Self::new()
    }
}

impl Log {
    /// A log that keeps events in memory only, until [`Log::open`] gives it a folder.
    pub fn new() -> Self {
        Log {
            ring: Mutex::new(VecDeque::new()),
            next_seq: AtomicU64::new(1),
            counts: [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)],
            not_written: AtomicU64::new(0),
            file: OnceLock::new(),
        }
    }

    /// Keep the log in `dir` from now on: load the events already there into memory, then append every new event to
    /// `dir/activity.jsonl`, rotating it as it grows. Calling it again does nothing.
    pub fn open(&self, dir: &Path) -> io::Result<()> {
        if self.file.get().is_some() {
            return Ok(());
        }
        fs::create_dir_all(dir)?;
        let loaded = load_tail(dir);
        if let Some(max) = loaded.iter().map(|e| e.seq).max() {
            self.next_seq.fetch_max(max + 1, Ordering::SeqCst);
        }
        {
            let mut ring = self.lock_ring();
            for event in loaded {
                if ring.len() == MEMORY_EVENTS {
                    ring.pop_front();
                }
                ring.push_back(event);
            }
        }
        let (tx, rx) = mpsc::sync_channel::<Event>(8192);
        let dir = dir.to_path_buf();
        std::thread::Builder::new()
            .name("activity-writer".into())
            .spawn(move || write_events(rx, &dir))?;
        let _ = self.file.set(tx);
        Ok(())
    }

    /// Record an event. Never blocks and never fails: a full file queue only counts as `not_written`.
    pub fn record(&self, level: Level, category: &str, source: &str, message: impl Into<String>, fields: BTreeMap<String, String>) {
        let event = Event {
            seq: self.next_seq.fetch_add(1, Ordering::SeqCst),
            ts_ms: now_ms(),
            level,
            category: category.to_string(),
            source: source.to_string(),
            message: message.into(),
            fields: redact(fields),
        };
        self.counts[level as usize].fetch_add(1, Ordering::Relaxed);
        if let Some(tx) = self.file.get() {
            match tx.try_send(event.clone()) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                    self.not_written.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        let mut ring = self.lock_ring();
        if ring.len() == MEMORY_EVENTS {
            ring.pop_front();
        }
        ring.push_back(event);
    }

    /// Matching events, oldest first, the newest `limit` of them.
    pub fn list(&self, filter: &Filter) -> Vec<Event> {
        let limit = if filter.limit == 0 { DEFAULT_LIMIT } else { filter.limit };
        let ring = self.lock_ring();
        let mut out: Vec<Event> = ring.iter().rev().filter(|e| filter.matches(e)).take(limit).cloned().collect();
        out.reverse();
        out
    }

    /// The sequence number of the newest event, or zero when there are none.
    pub fn last_seq(&self) -> u64 {
        self.next_seq.load(Ordering::SeqCst).saturating_sub(1)
    }

    pub fn counts(&self) -> Counts {
        Counts {
            debug: self.counts[0].load(Ordering::Relaxed),
            info: self.counts[1].load(Ordering::Relaxed),
            warn: self.counts[2].load(Ordering::Relaxed),
            error: self.counts[3].load(Ordering::Relaxed),
            not_written: self.not_written.load(Ordering::Relaxed),
        }
    }

    /// Empty the in-memory view. The file keeps its history.
    pub fn clear_memory(&self) {
        self.lock_ring().clear();
    }

    fn lock_ring(&self) -> MutexGuard<'_, VecDeque<Event>> {
        self.ring.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

static GLOBAL: OnceLock<Log> = OnceLock::new();

/// The process's activity log.
pub fn global() -> &'static Log {
    GLOBAL.get_or_init(Log::new)
}

/// Record on the process's log.
pub fn record(level: Level, category: &str, source: &str, message: impl Into<String>, fields: &[(&str, &str)]) {
    let fields = fields.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    global().record(level, category, source, message, fields);
}

/// Keep the process's log in `dir`. See [`Log::open`].
pub fn open(dir: &Path) -> io::Result<()> {
    global().open(dir)
}

/// Make every panic an error event (category `panic`), then let the previous hook run as usual.
pub fn install_panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let thread = std::thread::current().name().unwrap_or("unnamed").to_string();
        let mut fields = BTreeMap::new();
        fields.insert("thread".to_string(), thread);
        if let Some(location) = info.location() {
            fields.insert("location".to_string(), format!("{}:{}", location.file(), location.line()));
        }
        global().record(Level::Error, "panic", "process", format!("panic: {info}"), fields);
        previous(info);
    }));
}

/// The `tracing` layer that feeds the log. Add it to the subscriber next to the console output.
#[derive(Debug, Clone, Copy, Default)]
pub struct ActivityLayer;

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for ActivityLayer {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: tracing_subscriber::layer::Context<'_, S>) {
        let meta = event.metadata();
        let level = match *meta.level() {
            tracing::Level::ERROR => Level::Error,
            tracing::Level::WARN => Level::Warn,
            tracing::Level::INFO => Level::Info,
            tracing::Level::DEBUG => Level::Debug,
            tracing::Level::TRACE => return,
        };
        let target = meta.target();
        // Our crates: debug and up. Dependencies: warnings and errors only, since they chatter at info and below.
        if level < Level::Warn && !is_our_crate(target) {
            return;
        }
        let mut visitor = Visitor::default();
        event.record(&mut visitor);
        let message = visitor.message.unwrap_or_else(|| meta.name().to_string());
        global().record(level, category_of(target), target, message, visitor.fields);
    }
}

#[derive(Default)]
struct Visitor {
    message: Option<String>,
    fields: BTreeMap<String, String>,
}

impl tracing::field::Visit for Visitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.put(field.name(), value.to_string());
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.put(field.name(), format!("{value:?}"));
    }
}

impl Visitor {
    fn put(&mut self, name: &str, value: String) {
        if name == "message" {
            self.message = Some(value);
        } else {
            self.fields.insert(name.to_string(), value);
        }
    }
}

/// Which of our own crates' info events are kept. Their dependencies log info all the time; they are not kept.
fn is_our_crate(target: &str) -> bool {
    ["transferd", "relayd", "launcher", "ring_channel"].iter().any(|prefix| target.starts_with(prefix))
}

/// A category from a `tracing` target (a module path). Each `::`, `_` or `-` separated word is matched whole, so
/// `build` does not count as `ui`.
pub fn category_of(target: &str) -> &'static str {
    let words: Vec<String> = target
        .split([':', '_', '-'])
        .filter(|w| !w.is_empty())
        .map(|w| w.to_ascii_lowercase())
        .collect();
    let has = |list: &[&str]| words.iter().any(|w| list.contains(&w.as_str()));
    if has(&["panic"]) {
        "panic"
    } else if has(&["overlay", "punch", "dns", "nat"]) {
        "overlay"
    } else if has(&["relay", "relayd", "dht", "webrtc"]) {
        "relay"
    } else if has(&["transport", "peer", "peers", "lane", "lanes", "session", "outbox", "connection"]) {
        "lanes"
    } else if has(&["update", "updates", "updater"]) {
        "updates"
    } else if has(&["grpc", "control", "hub", "api", "mcp", "acp", "rpc", "http"]) {
        "api"
    } else if has(&["crypto", "handshake", "ratchet", "identity", "auth", "security", "tls"]) {
        "security"
    } else if has(&["store", "state", "db", "snapshot", "replica", "sqlite"]) {
        "store"
    } else if has(&["ui", "gui", "window", "terminal"]) {
        "gui"
    } else {
        "system"
    }
}

/// Field values for secret-looking names are replaced, so a log line can never carry a key or a PIN.
fn redact(fields: BTreeMap<String, String>) -> BTreeMap<String, String> {
    fields
        .into_iter()
        .map(|(name, value)| {
            let lower = name.to_ascii_lowercase();
            if SECRET_WORDS.iter().any(|w| lower.contains(w)) {
                (name, "[redacted]".to_string())
            } else {
                (name, value)
            }
        })
        .collect()
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn write_events(rx: Receiver<Event>, dir: &Path) {
    let path = dir.join(FILE_NAME);
    let mut file = open_append(&path);
    let mut size = file.as_ref().and_then(|f| f.metadata().ok()).map(|m| m.len()).unwrap_or(0);
    for event in rx {
        let Ok(mut line) = serde_json::to_string(&event) else { continue };
        line.push('\n');
        let bytes = line.len() as u64;
        if size > 0 && size + bytes > FILE_ROTATE_BYTES {
            rotate(dir);
            file = open_append(&path);
            size = 0;
        }
        if let Some(f) = file.as_mut() {
            if f.write_all(line.as_bytes()).is_ok() {
                size += bytes;
            }
        }
    }
}

fn open_append(path: &Path) -> Option<fs::File> {
    OpenOptions::new().create(true).append(true).open(path).ok()
}

/// `activity.jsonl` becomes `activity.1.jsonl`, and so on; the oldest is dropped.
fn rotate(dir: &Path) {
    let name = |i: usize| -> PathBuf {
        if i == 0 {
            dir.join(FILE_NAME)
        } else {
            dir.join(format!("activity.{i}.jsonl"))
        }
    };
    let _ = fs::remove_file(name(FILE_KEEP - 1));
    for i in (0..FILE_KEEP - 1).rev() {
        let _ = fs::rename(name(i), name(i + 1));
    }
}

/// The events in the files, oldest first, for the last [`MEMORY_EVENTS`] of them. A line that does not parse is
/// skipped.
fn load_tail(dir: &Path) -> Vec<Event> {
    let mut events: Vec<Event> = Vec::new();
    for i in (0..FILE_KEEP).rev() {
        let path = if i == 0 { dir.join(FILE_NAME) } else { dir.join(format!("activity.{i}.jsonl")) };
        let Ok(file) = fs::File::open(&path) else { continue };
        for line in io::BufReader::new(file).lines().map_while(Result::ok) {
            if let Ok(event) = serde_json::from_str::<Event>(&line) {
                events.push(event);
            }
        }
    }
    if events.len() > MEMORY_EVENTS {
        events.drain(..events.len() - MEMORY_EVENTS);
    }
    events
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn fields(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn levels_parse_and_order() {
        assert_eq!(Level::parse("WARNING"), Some(Level::Warn));
        assert_eq!(Level::parse("trace"), Some(Level::Debug));
        assert_eq!(Level::parse("loud"), None);
        assert!(Level::Error > Level::Warn && Level::Warn > Level::Info && Level::Info > Level::Debug);
    }

    #[test]
    fn filters_by_level_category_text_and_sequence() {
        let log = Log::new();
        log.record(Level::Info, "lanes", "transport", "lane opened to Bob", BTreeMap::new());
        log.record(Level::Error, "relay", "relayd", "relay refused the connection", BTreeMap::new());
        log.record(Level::Warn, "lanes", "transport", "lane closed", BTreeMap::new());
        let warnings = log.list(&Filter { min_level: Some(Level::Warn), ..Default::default() });
        assert_eq!(warnings.len(), 2);
        let lanes = log.list(&Filter { category: Some("LANES".into()), ..Default::default() });
        assert_eq!(lanes.len(), 2, "category matches ignore case");
        let text = log.list(&Filter { text: Some("bob".into()), ..Default::default() });
        assert_eq!(text.len(), 1);
        let after = log.list(&Filter { since_seq: 1, ..Default::default() });
        assert_eq!(after.iter().map(|e| e.seq).collect::<Vec<_>>(), vec![2, 3]);
        assert_eq!(log.last_seq(), 3);
    }

    #[test]
    fn the_newest_matches_come_back_oldest_first() {
        let log = Log::new();
        for i in 0..10 {
            log.record(Level::Info, "system", "test", format!("event {i}"), BTreeMap::new());
        }
        let last_three = log.list(&Filter { limit: 3, ..Default::default() });
        let messages: Vec<&str> = last_three.iter().map(|e| e.message.as_str()).collect();
        assert_eq!(messages, vec!["event 7", "event 8", "event 9"]);
    }

    #[test]
    fn secrets_are_never_stored() {
        let log = Log::new();
        log.record(Level::Info, "security", "auth", "signed in", fields(&[("token", "abc"), ("contact", "bob"), ("app.lock.pin", "1234")]));
        let event = &log.list(&Filter::default())[0];
        assert_eq!(event.fields["token"], "[redacted]");
        assert_eq!(event.fields["app.lock.pin"], "[redacted]");
        assert_eq!(event.fields["contact"], "bob");
    }

    #[test]
    fn categories_come_from_the_module_path() {
        assert_eq!(category_of("transferd::transport"), "lanes");
        assert_eq!(category_of("transferd_overlay::punch"), "overlay");
        assert_eq!(category_of("relayd::ws"), "relay");
        assert_eq!(category_of("transferd_control::hub"), "api");
        assert_eq!(category_of("transferd_ui_shared::app"), "gui");
        assert_eq!(category_of("some_crate::thing"), "system");
    }

    #[test]
    fn events_survive_a_restart() {
        let dir = std::env::temp_dir().join(format!("td-activity-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let first = Log::new();
        first.open(&dir).unwrap();
        first.record(Level::Warn, "lanes", "transport", "before the restart", BTreeMap::new());
        drop(first);
        // The writer thread is gone once its sender is dropped; give it a moment to flush.
        std::thread::sleep(std::time::Duration::from_millis(100));
        let second = Log::new();
        second.open(&dir).unwrap();
        let loaded = second.list(&Filter::default());
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].message, "before the restart");
        assert!(second.last_seq() >= 1, "numbering resumes after the file's last event");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotation_keeps_a_fixed_number_of_files() {
        let dir = std::env::temp_dir().join(format!("td-activity-rot-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        // FILE_KEEP is 3: the live file plus two rotated ones. Each round writes the live file, then rotates it.
        for round in ["A", "B", "C"] {
            fs::write(dir.join(FILE_NAME), round).unwrap();
            rotate(&dir);
        }
        assert!(!dir.join(FILE_NAME).exists(), "rotation moves the live file away");
        assert_eq!(fs::read_to_string(dir.join("activity.1.jsonl")).unwrap(), "C");
        assert_eq!(fs::read_to_string(dir.join("activity.2.jsonl")).unwrap(), "B", "the oldest, A, was dropped");
        assert!(!dir.join(format!("activity.{FILE_KEEP}.jsonl")).exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_tracing_layer_keeps_warnings_and_our_info_only() {
        use tracing_subscriber::layer::SubscriberExt;
        let subscriber = tracing_subscriber::registry().with(ActivityLayer);
        let before = global().counts();
        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!(target: "transferd::transport", peer = "bob", "lane stalled");
            tracing::info!(target: "transferd::transport", "lane opened");
            tracing::info!(target: "hyper::client", "a dependency's info line");
            tracing::error!(target: "some_dep::thing", "a dependency's error");
        });
        let after = global().counts();
        assert_eq!(after.warn - before.warn, 1);
        assert_eq!(after.info - before.info, 1, "only our crate's info is kept");
        assert_eq!(after.error - before.error, 1, "errors are kept from every crate");
        let stalled = global().list(&Filter { text: Some("lane stalled".into()), ..Default::default() });
        assert_eq!(stalled.last().unwrap().fields["peer"], "bob");
    }
}
