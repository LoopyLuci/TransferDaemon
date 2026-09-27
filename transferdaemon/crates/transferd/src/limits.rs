//! Daemon-side transfer limits: the operator's own limits (what this daemon
//! accepts and its outbound budgets), read from env / settings, plus the
//! enforcement helpers used at send and receive time.
//!
//! Env keys (the mobile `daemon.config` file sets the same keys):
//!   TRANSFERD_MAX_MSG_BYTES   TRANSFERD_MAX_PHOTO_BYTES
//!   TRANSFERD_MAX_VIDEO_BYTES TRANSFERD_MAX_VOICE_BYTES
//!   TRANSFERD_MAX_FILE_BYTES  TRANSFERD_CALL_KBPS
//!   TRANSFERD_MAX_MB_PER_DAY  TRANSFERD_MAX_MB_PER_WEEK TRANSFERD_MAX_MB_PER_MONTH
//! Values are byte counts (MB keys are MiB); `0` = that cap is disabled.
//! A preset name (`"5mb"`, `"1gb"`) is also accepted.

use relayd::limits::{ContentType, MaxBytes, Preset, TransferLimits};

/// Parse `0` (disabled), a byte count, or a preset name.
fn parse_max(s: &str) -> MaxBytes {
    let t = s.trim();
    if t == "0" || t.is_empty() {
        return MaxBytes::UNBOUNDED;
    }
    if let Ok(n) = t.parse::<u64>() {
        return MaxBytes::custom(n);
    }
    match t.to_ascii_lowercase().as_str() {
        "1mb" | "1m" => MaxBytes::preset(Preset::Mb1),
        "5mb" => MaxBytes::preset(Preset::Mb5),
        "10mb" => MaxBytes::preset(Preset::Mb10),
        "25mb" => MaxBytes::preset(Preset::Mb25),
        "50mb" => MaxBytes::preset(Preset::Mb50),
        "100mb" => MaxBytes::preset(Preset::Mb100),
        "250mb" => MaxBytes::preset(Preset::Mb250),
        "500mb" => MaxBytes::preset(Preset::Mb500),
        "1gb" => MaxBytes::preset(Preset::Gb1),
        "5gb" => MaxBytes::preset(Preset::Gb5),
        "unbounded" | "unlimited" | "none" => MaxBytes::UNBOUNDED,
        _ => MaxBytes::UNBOUNDED,
    }
}

fn env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.trim().is_empty())
}

/// The daemon's own limits from env (defaults = the preset set).
pub fn daemon_limits() -> TransferLimits {
    let mut l = TransferLimits::default_presets();
    if let Some(v) = env("TRANSFERD_MAX_MSG_BYTES") {
        l.message_bytes = parse_max(&v);
    }
    if let Some(v) = env("TRANSFERD_MAX_PHOTO_BYTES") {
        l.photo_bytes = parse_max(&v);
    }
    if let Some(v) = env("TRANSFERD_MAX_VIDEO_BYTES") {
        l.video_bytes = parse_max(&v);
    }
    if let Some(v) = env("TRANSFERD_MAX_VOICE_BYTES") {
        l.voice_bytes = parse_max(&v);
    }
    if let Some(v) = env("TRANSFERD_MAX_FILE_BYTES") {
        l.file_bytes = parse_max(&v);
    }
    if let Some(v) = env("TRANSFERD_CALL_KBPS") {
        if let Ok(n) = v.parse::<u64>() {
            l.call_kbps = n;
        }
    }
    for (key, dst) in [
        ("TRANSFERD_MAX_MB_PER_DAY", &mut l.daily_bytes),
        ("TRANSFERD_MAX_MB_PER_WEEK", &mut l.weekly_bytes),
        ("TRANSFERD_MAX_MB_PER_MONTH", &mut l.monthly_bytes),
    ] {
        if let Some(v) = env(key) {
            if let Ok(mb) = v.trim().parse::<u64>() {
                *dst = if mb == 0 { MaxBytes::UNBOUNDED } else { MaxBytes::custom(mb << 20) };
            }
        }
    }
    l
}

/// Limit-setting keys in the daemon's settings map (`state.settings`).
/// A value is a preset name (`"5mb"`), a byte count, or `"0"`/`"unbounded"`.
/// Bandwidth keys take MiB numbers.
pub const SETTING_KEYS: [(&str, ContentType); 5] = [
    ("limits.message_bytes", ContentType::Message),
    ("limits.photo_bytes", ContentType::Photo),
    ("limits.video_bytes", ContentType::Video),
    ("limits.voice_bytes", ContentType::Voice),
    ("limits.file_bytes", ContentType::File),
];
pub const SETTING_BANDWIDTH_KEYS: [&str; 3] =
    ["limits.daily_mb", "limits.weekly_mb", "limits.monthly_mb"];
pub const SETTING_CALL_KEY: &str = "limits.call_kbps";

/// The daemon's effective limits: env (base) overlaid by the user's stored
/// settings (which win — they are the user-facing configuration).
pub fn daemon_limits_with(settings: &std::collections::HashMap<String, String>) -> TransferLimits {
    let mut l = daemon_limits();
    for (key, ct) in SETTING_KEYS {
        if let Some(v) = settings.get(key).filter(|v| !v.trim().is_empty()) {
            match ct {
                ContentType::Message => l.message_bytes = parse_max(v),
                ContentType::Photo => l.photo_bytes = parse_max(v),
                ContentType::Video => l.video_bytes = parse_max(v),
                ContentType::Voice => l.voice_bytes = parse_max(v),
                ContentType::File => l.file_bytes = parse_max(v),
                ContentType::Call => {}
            }
        }
    }
    for (key, dst) in [
        (SETTING_BANDWIDTH_KEYS[0], &mut l.daily_bytes),
        (SETTING_BANDWIDTH_KEYS[1], &mut l.weekly_bytes),
        (SETTING_BANDWIDTH_KEYS[2], &mut l.monthly_bytes),
    ] {
        if let Some(v) = settings.get(key).filter(|v| !v.trim().is_empty()) {
            if let Ok(mb) = v.trim().parse::<u64>() {
                *dst = if mb == 0 { MaxBytes::UNBOUNDED } else { MaxBytes::custom(mb << 20) };
            }
        }
    }
    if let Some(v) = settings.get(SETTING_CALL_KEY).filter(|v| !v.trim().is_empty()) {
        if let Ok(n) = v.trim().parse::<u64>() {
            l.call_kbps = n;
        }
    }
    l
}

/// A one-line human summary of the effective limits (for the settings UI).
pub fn summarize(l: &TransferLimits) -> String {
    format!(
        "msg {} · photo {} · video {} · voice {} · file {} · call {}kbps · day {} / week {} / month {}",
        l.message_bytes.label(),
        l.photo_bytes.label(),
        l.video_bytes.label(),
        l.voice_bytes.label(),
        l.file_bytes.label(),
        l.call_kbps,
        l.daily_bytes.label(),
        l.weekly_bytes.label(),
        l.monthly_bytes.label(),
    )
}

/// The byte cap a peer will accept for `ct`, if known (None = unknown/unbounded).
pub fn peer_cap(limits: Option<&TransferLimits>, ct: ContentType) -> Option<u64> {
    limits.and_then(|l| l.cap_for(ct))
}

/// Human explanation for a refused transfer.
pub fn refusal_reason(ct: ContentType, size: u64, cap: u64) -> String {
    format!(
        "{} of {} exceeds the peer's {} cap of {}",
        ct.as_str(),
        relayd::limits::format_bytes(size),
        ct.as_str(),
        relayd::limits::format_bytes(cap),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_max_handles_presets_and_custom() {
        assert_eq!(parse_max("0"), MaxBytes::UNBOUNDED);
        assert_eq!(parse_max("5mb"), MaxBytes::preset(Preset::Mb5));
        assert_eq!(parse_max("12345"), MaxBytes::custom(12345));
        assert_eq!(parse_max("unlimited"), MaxBytes::UNBOUNDED);
    }

    #[test]
    fn env_limits_apply() {
        std::env::set_var("TRANSFERD_MAX_FILE_BYTES", "10mb");
        std::env::set_var("TRANSFERD_MAX_MB_PER_DAY", "250");
        let l = daemon_limits();
        std::env::remove_var("TRANSFERD_MAX_FILE_BYTES");
        std::env::remove_var("TRANSFERD_MAX_MB_PER_DAY");
        assert_eq!(l.cap_for(ContentType::File), Some(10 << 20));
        assert_eq!(l.daily_bytes.bytes(), Some(250 << 20));
        assert_eq!(l.cap_for(ContentType::Message), Some(1 << 20));
    }

    #[test]
    fn default_limits_are_the_presets() {
        let l = daemon_limits();
        assert_eq!(l.cap_for(ContentType::Message), Some(1 << 20));
        assert_eq!(l.cap_for(ContentType::Photo), Some(5 << 20));
    }
}