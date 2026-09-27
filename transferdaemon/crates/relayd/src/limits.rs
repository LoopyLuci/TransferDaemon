//! Data-transfer limits: per-content-type size caps (with preset quick-picks),
//! daily/weekly/monthly bandwidth budgets, and the relay node's enforcement
//! (max blob size + rolling per-token bandwidth accounting).
//!
//! Two layers use this:
//! - **Users / peers** advertise a `TransferLimits` (what they will accept, per
//!   content type and per time window) so senders never push more than a peer
//!   wants — and relays/Workers never carry a blob a node can't handle.
//! - **Relay nodes** (relayd, relayd-ws, the Cloudflare Worker) enforce
//!   `RelayLimits`: a hard max ciphertext blob size plus per-token
//!   daily/weekly/monthly bandwidth budgets, so a public relay can never be
//!   drained or flooded beyond what its operator configured.
//!
//! All types are serde-stable (`#[serde(default)]` everywhere), so old records
//! and new configs interoperate — additive-only evolution.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Presets
// ---------------------------------------------------------------------------

/// Quick-pick size presets. The exact list the user asked for: 1 MB → 5 GB.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Preset {
    Mb1,
    Mb5,
    Mb10,
    Mb25,
    Mb50,
    Mb100,
    Mb250,
    Mb500,
    Gb1,
    Gb5,
    Unbounded,
}

impl Preset {
    pub const ALL: [Preset; 11] = [
        Preset::Mb1,
        Preset::Mb5,
        Preset::Mb10,
        Preset::Mb25,
        Preset::Mb50,
        Preset::Mb100,
        Preset::Mb250,
        Preset::Mb500,
        Preset::Gb1,
        Preset::Gb5,
        Preset::Unbounded,
    ];

    /// The byte count, or `None` for `Unbounded`.
    pub fn bytes(&self) -> Option<u64> {
        Some(match self {
            Preset::Mb1 => 1 << 20,
            Preset::Mb5 => 5 << 20,
            Preset::Mb10 => 10 << 20,
            Preset::Mb25 => 25 << 20,
            Preset::Mb50 => 50 << 20,
            Preset::Mb100 => 100 << 20,
            Preset::Mb250 => 250 << 20,
            Preset::Mb500 => 500 << 20,
            Preset::Gb1 => 1 << 30,
            Preset::Gb5 => 5 << 30,
            Preset::Unbounded => return None,
        })
    }

    /// Human label, e.g. `"100 MB"`.
    pub fn label(&self) -> &'static str {
        match self {
            Preset::Mb1 => "1 MB",
            Preset::Mb5 => "5 MB",
            Preset::Mb10 => "10 MB",
            Preset::Mb25 => "25 MB",
            Preset::Mb50 => "50 MB",
            Preset::Mb100 => "100 MB",
            Preset::Mb250 => "250 MB",
            Preset::Mb500 => "500 MB",
            Preset::Gb1 => "1 GB",
            Preset::Gb5 => "5 GB",
            Preset::Unbounded => "Unlimited",
        }
    }

    /// The smallest preset whose byte count is ≥ `n` (the quick-pick a UI
    /// should offer for a transfer of `n` bytes). `Unbounded` when `n` exceeds
    /// every preset.
    pub fn ceil_for(n: u64) -> Preset {
        for p in Preset::ALL {
            match p.bytes() {
                Some(b) if b >= n => return p,
                _ => {}
            }
        }
        Preset::Unbounded
    }
}

// ---------------------------------------------------------------------------
// MaxBytes
// ---------------------------------------------------------------------------

/// A size cap: a named preset and/or a custom byte count. `None` both ways
/// means unbounded. `custom` wins when both are set.
///
/// NOTE: fields MUST NOT use `skip_serializing_if` — the record is carried over
/// bincode (DHT PeerEndpoint), whose fixed struct layout cannot reconstruct
/// skipped fields. `#[serde(default)]` alone handles older records safely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MaxBytes {
    pub preset: Option<Preset>,
    pub custom: Option<u64>,
}

impl MaxBytes {
    pub const UNBOUNDED: MaxBytes = MaxBytes { preset: None, custom: None };

    pub fn preset(p: Preset) -> Self {
        Self { preset: Some(p), custom: None }
    }

    pub fn custom(n: u64) -> Self {
        Self { preset: None, custom: Some(n) }
    }

    /// The effective byte cap, or `None` for unbounded.
    pub fn bytes(&self) -> Option<u64> {
        self.custom.or_else(|| self.preset.and_then(|p| p.bytes()))
    }

    /// Human label, e.g. `"100 MB"` or `"12.5 MB"`.
    pub fn label(&self) -> String {
        match self.bytes() {
            Some(b) => format_bytes(b),
            None => "Unlimited".into(),
        }
    }
}

impl Default for MaxBytes {
    fn default() -> Self {
        Self::UNBOUNDED
    }
}

/// Compact human byte formatting: `1.5 MB`, `2 GB`, `800 KB`, `512 B`.
pub fn format_bytes(n: u64) -> String {
    const KB: u64 = 1 << 10;
    const MB: u64 = 1 << 20;
    const GB: u64 = 1 << 30;
    if n >= GB {
        format!("{:.1} GB", n as f64 / GB as f64)
    } else if n >= MB {
        format!("{:.1} MB", n as f64 / MB as f64)
    } else if n >= KB {
        format!("{:.1} KB", n as f64 / KB as f64)
    } else {
        format!("{n} B")
    }
}

// ---------------------------------------------------------------------------
// Content types
// ---------------------------------------------------------------------------

/// Content types subject to per-type caps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ContentType {
    /// SMS / text messages.
    Message,
    /// Images.
    Photo,
    /// Video files and streams.
    Video,
    /// Voice notes / audio files.
    Voice,
    /// Generic files.
    File,
    /// Live calls / streaming.
    Call,
}

impl ContentType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ContentType::Message => "message",
            ContentType::Photo => "photo",
            ContentType::Video => "video",
            ContentType::Voice => "voice",
            ContentType::File => "file",
            ContentType::Call => "call",
        }
    }

    /// Classify a MIME type into a content type (used on file sends).
    pub fn from_mime(mime: &str) -> ContentType {
        let m = mime.to_ascii_lowercase();
        if m.starts_with("image/") {
            ContentType::Photo
        } else if m.starts_with("video/") {
            ContentType::Video
        } else if m.starts_with("audio/") {
            ContentType::Voice
        } else {
            ContentType::File
        }
    }
}

// ---------------------------------------------------------------------------
// TransferLimits — what a user/peer will accept
// ---------------------------------------------------------------------------

/// Per-content-type caps plus daily/weekly/monthly bandwidth budgets for one
/// peer. Serde-defaulted so old records (no `limits`) load as `default_presets`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TransferLimits {
    /// Max single text/message payload.
    pub message_bytes: MaxBytes,
    /// Max single photo.
    pub photo_bytes: MaxBytes,
    /// Max single video.
    pub video_bytes: MaxBytes,
    /// Max single voice note / audio clip.
    pub voice_bytes: MaxBytes,
    /// Max single generic file.
    pub file_bytes: MaxBytes,
    /// Live-call / streaming bitrate cap, kbps (0 = no cap).
    pub call_kbps: u64,
    /// Rolling daily outbound bandwidth budget.
    pub daily_bytes: MaxBytes,
    /// Rolling weekly outbound bandwidth budget.
    pub weekly_bytes: MaxBytes,
    /// Rolling monthly outbound bandwidth budget.
    pub monthly_bytes: MaxBytes,
}

impl Default for TransferLimits {
    fn default() -> Self {
        Self::default_presets()
    }
}

impl TransferLimits {
    /// Sensible out-of-the-box presets (per-type caps + bandwidth budgets).
    pub fn default_presets() -> Self {
        Self {
            message_bytes: MaxBytes::preset(Preset::Mb1),
            photo_bytes: MaxBytes::preset(Preset::Mb5),
            video_bytes: MaxBytes::preset(Preset::Mb50),
            voice_bytes: MaxBytes::preset(Preset::Mb10),
            file_bytes: MaxBytes::preset(Preset::Mb100),
            call_kbps: 1000,
            daily_bytes: MaxBytes::preset(Preset::Mb500),
            weekly_bytes: MaxBytes::custom(2 << 30),
            monthly_bytes: MaxBytes::custom(8 << 30),
        }
    }

    /// The effective byte cap for a content type, or `None` if unrestricted.
    pub fn cap_for(&self, ct: ContentType) -> Option<u64> {
        match ct {
            ContentType::Message => self.message_bytes.bytes(),
            ContentType::Photo => self.photo_bytes.bytes(),
            ContentType::Video => self.video_bytes.bytes(),
            ContentType::Voice => self.voice_bytes.bytes(),
            ContentType::File => self.file_bytes.bytes(),
            ContentType::Call => None,
        }
    }
}

// ---------------------------------------------------------------------------
// RelayLimits — what a relay NODE will carry
// ---------------------------------------------------------------------------

/// The relay node's enforcement knobs. `None` = no cap / unbounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayLimits {
    /// Hard max ciphertext blob a single FORWARD may carry.
    pub max_blob_bytes: Option<u64>,
    /// Rolling daily bandwidth budget PER TOKEN.
    pub daily_bytes: Option<u64>,
    /// Rolling weekly bandwidth budget PER TOKEN.
    pub weekly_bytes: Option<u64>,
    /// Rolling monthly bandwidth budget PER TOKEN.
    pub monthly_bytes: Option<u64>,
}

impl Default for RelayLimits {
    fn default() -> Self {
        Self::unrestricted()
    }
}

impl RelayLimits {
    pub fn unrestricted() -> Self {
        Self { max_blob_bytes: None, daily_bytes: None, weekly_bytes: None, monthly_bytes: None }
    }

    /// Read limits from environment variables with the given prefix
    /// (`relayd` uses `RELAYD_`, `relayd-ws` uses `RELAYD_WS_`).
    ///
    ///   {PREFIX}MAX_BLOB_BYTES=...      hard per-blob cap in bytes
    ///   {PREFIX}MAX_MB_PER_DAY=...      per-token bandwidth budget (MiB)
    ///   {PREFIX}MAX_MB_PER_WEEK=...     per-token bandwidth budget (MiB)
    ///   {PREFIX}MAX_MB_PER_MONTH=...    per-token bandwidth budget (MiB)
    pub fn from_env(prefix: &str) -> Self {
        let mb = |k: &str| {
            std::env::var(format!("{prefix}{k}"))
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .map(|m| m << 20)
        };
        Self {
            max_blob_bytes: std::env::var(format!("{prefix}MAX_BLOB_BYTES"))
                .ok()
                .and_then(|v| v.parse::<u64>().ok()),
            daily_bytes: mb("MAX_MB_PER_DAY"),
            weekly_bytes: mb("MAX_MB_PER_WEEK"),
            monthly_bytes: mb("MAX_MB_PER_MONTH"),
        }
    }
}

// ---------------------------------------------------------------------------
// BandwidthTracker — rolling per-token window accounting
// ---------------------------------------------------------------------------

/// One rolling window: the epoch bucket (seconds / bucket_secs) it covers and
/// the bytes charged so far in that bucket. A bucket change resets to 0.
#[derive(Debug, Clone, Copy, Default)]
struct Window {
    epoch: u64,
    bytes: u64,
}

/// Per-token bandwidth accounting. Buckets: day (86400s), week (604800s),
/// month (2592000s — a nominal 30-day month; documented approximation).
#[derive(Debug, Default)]
pub struct BandwidthTracker {
    windows: HashMap<[u8; 32], [Window; 3]>,
}

pub const DAY_SECS: u64 = 86_400;
pub const WEEK_SECS: u64 = 604_800;
pub const MONTH_SECS: u64 = 2_592_000;

impl BandwidthTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Try to charge `bytes` to `token`. Returns `false` (and charges nothing)
    /// if the charge would exceed any configured budget; otherwise charges the
    /// rolling windows and returns `true`.
    pub fn charge(&mut self, token: &[u8; 32], bytes: u64, limits: &RelayLimits) -> bool {
        let now = unix_secs();
        let buckets = [now / DAY_SECS, now / WEEK_SECS, now / MONTH_SECS];
        let budgets = [limits.daily_bytes, limits.weekly_bytes, limits.monthly_bytes];

        // Pre-check: would any budget be exceeded by this charge?
        let entry = self.windows.entry(*token).or_default();
        for i in 0..3 {
            let w = &entry[i];
            let cur = if w.epoch == buckets[i] { w.bytes } else { 0 };
            if let Some(budget) = budgets[i] {
                if cur.saturating_add(bytes) > budget {
                    return false;
                }
            }
        }
        // Charge.
        for i in 0..3 {
            let w = &mut entry[i];
            if w.epoch != buckets[i] {
                w.epoch = buckets[i];
                w.bytes = 0;
            }
            w.bytes += bytes;
        }
        true
    }

    /// Current charged bytes for `token` in each window `(day, week, month)`.
    pub fn usage(&self, token: &[u8; 32]) -> (u64, u64, u64) {
        let now = unix_secs();
        let buckets = [now / DAY_SECS, now / WEEK_SECS, now / MONTH_SECS];
        let Some(entry) = self.windows.get(token) else {
            return (0, 0, 0);
        };
        (
            if entry[0].epoch == buckets[0] { entry[0].bytes } else { 0 },
            if entry[1].epoch == buckets[1] { entry[1].bytes } else { 0 },
            if entry[2].epoch == buckets[2] { entry[2].bytes } else { 0 },
        )
    }
}

fn unix_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets_have_expected_bytes() {
        assert_eq!(Preset::Mb1.bytes(), Some(1 << 20));
        assert_eq!(Preset::Gb1.bytes(), Some(1 << 30));
        assert_eq!(Preset::Unbounded.bytes(), None);
    }

    #[test]
    fn ceil_for_picks_the_next_preset() {
        assert_eq!(Preset::ceil_for(2), Preset::Mb1);
        assert_eq!(Preset::ceil_for(1 << 20), Preset::Mb1);
        assert_eq!(Preset::ceil_for(300 << 20), Preset::Mb500);
        assert_eq!(Preset::ceil_for(6 << 30), Preset::Unbounded);
    }

    #[test]
    fn max_bytes_custom_wins_over_preset() {
        let m = MaxBytes { preset: Some(Preset::Mb1), custom: Some(2048) };
        assert_eq!(m.bytes(), Some(2048));
        assert_eq!(MaxBytes::UNBOUNDED.bytes(), None);
        assert_eq!(MaxBytes::custom(12 << 20).label(), "12.0 MB");
    }

    #[test]
    fn limits_serde_roundtrip_and_defaults() {
        let l = TransferLimits::default_presets();
        let json = serde_json::to_string(&l).unwrap();
        let back: TransferLimits = serde_json::from_str(&json).unwrap();
        assert_eq!(back.cap_for(ContentType::Message), Some(1 << 20));
        assert_eq!(back.cap_for(ContentType::Video), Some(50 << 20));

        // Old records without `limits` fields load as the presets.
        let empty: TransferLimits = serde_json::from_str("{}").unwrap();
        assert_eq!(empty.cap_for(ContentType::Photo), Some(5 << 20));

        // Custom cap overrides.
        let custom: TransferLimits = serde_json::from_str(
            r#"{"file_bytes":{"custom":12345}}"#,
        ).unwrap();
        assert_eq!(custom.cap_for(ContentType::File), Some(12345));
        assert_eq!(custom.cap_for(ContentType::Message), Some(1 << 20));
    }

    #[test]
    fn mime_classification() {
        assert_eq!(ContentType::from_mime("image/png"), ContentType::Photo);
        assert_eq!(ContentType::from_mime("video/mp4"), ContentType::Video);
        assert_eq!(ContentType::from_mime("audio/ogg"), ContentType::Voice);
        assert_eq!(ContentType::from_mime("application/pdf"), ContentType::File);
    }

    #[test]
    fn bandwidth_charge_within_budget() {
        let mut t = BandwidthTracker::new();
        let limits = RelayLimits {
            max_blob_bytes: Some(10 << 20),
            daily_bytes: Some(5 << 20),
            weekly_bytes: None,
            monthly_bytes: None,
        };
        let token = [7u8; 32];
        assert!(t.charge(&token, 3 << 20, &limits));
        assert!(t.charge(&token, 2 << 20, &limits));
        assert!(!t.charge(&token, 1 << 20, &limits), "would exceed the daily budget");
        let (day, _, _) = t.usage(&token);
        assert_eq!(day, 5 << 20, "only the successful charges count");
    }

    #[test]
    fn bandwidth_windows_reset_on_rollover() {
        let mut t = BandwidthTracker::new();
        let limits = RelayLimits { max_blob_bytes: None, daily_bytes: Some(100), weekly_bytes: None, monthly_bytes: None };
        let token = [8u8; 32];
        assert!(t.charge(&token, 60, &limits));
        // Simulate a rollover by charging against a different epoch bucket
        // (the tracker derives the bucket from the clock; force a stale
        // window by rewriting the stored epoch).
        let entry = t.windows.get_mut(&token).unwrap();
        entry[0].epoch = 0; // force a different day bucket
        assert!(t.charge(&token, 80, &limits), "a new window bucket resets the budget");
        let (day, _, _) = t.usage(&token);
        assert_eq!(day, 80);
    }

    #[test]
    fn relay_limits_from_env() {
        std::env::set_var("RELAYD_MAX_BLOB_BYTES", "1048576");
        std::env::set_var("RELAYD_MAX_MB_PER_DAY", "500");
        let l = RelayLimits::from_env("RELAYD_");
        std::env::remove_var("RELAYD_MAX_BLOB_BYTES");
        std::env::remove_var("RELAYD_MAX_MB_PER_DAY");
        assert_eq!(l.max_blob_bytes, Some(1 << 20));
        assert_eq!(l.daily_bytes, Some(500 << 20));
        assert_eq!(l.weekly_bytes, None);
    }
}