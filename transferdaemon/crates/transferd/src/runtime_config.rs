//! Settings the daemon reads from `config.json` in its data folder, and applies while it runs.
//!
//! The file is checked every few seconds, and a change takes effect without a restart. A file that
//! does not parse, or that sets a value out of range, is logged and ignored: the daemon keeps the
//! settings it had. A valid file replaces every setting, so a key it leaves out takes its default.
//!
//! | Key | Default | Allowed |
//! |---|---|---|
//! | `snapshot_every_secs` | 3600 | at least 60 |
//! | `snapshot_keep` | 24 | 1 to 1000 |
//!
//! Snapshots of the encrypted store are taken on the schedule above, into `snapshots/` beside the
//! store. A snapshot is skipped while the store is identical to the newest one, so an idle daemon
//! does not fill the folder.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use transferd_store::snapshot::{self, Snapshot};

/// The file in the data folder that holds the settings.
pub const FILE_NAME: &str = "config.json";
/// How often the file is checked.
pub const POLL_EVERY: Duration = Duration::from_secs(5);
/// The snapshot folder, beside the store.
pub const SNAPSHOT_DIR: &str = "snapshots";
pub const MIN_SNAPSHOT_EVERY_SECS: u64 = 60;
pub const MAX_SNAPSHOT_KEEP: usize = 1000;

/// The settings the daemon applies while it runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuntimeConfig {
    pub snapshot_every_secs: u64,
    pub snapshot_keep: usize,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            snapshot_every_secs: 3600,
            snapshot_keep: 24,
        }
    }
}

/// Reads settings from the text of a config file. An unknown key, or a value out of range, is refused.
pub fn parse(text: &str) -> Result<RuntimeConfig, String> {
    let config: RuntimeConfig = serde_json::from_str(text).map_err(|e| e.to_string())?;
    if config.snapshot_every_secs < MIN_SNAPSHOT_EVERY_SECS {
        return Err(format!(
            "snapshot_every_secs must be at least {MIN_SNAPSHOT_EVERY_SECS}, not {}",
            config.snapshot_every_secs
        ));
    }
    if !(1..=MAX_SNAPSHOT_KEEP).contains(&config.snapshot_keep) {
        return Err(format!(
            "snapshot_keep must be from 1 to {MAX_SNAPSHOT_KEEP}, not {}",
            config.snapshot_keep
        ));
    }
    Ok(config)
}

/// The settings a reload gives. A valid file gives its own. A file that is rejected keeps `current`,
/// with the reason. No file means the defaults.
pub fn reload(current: &RuntimeConfig, text: Option<&str>) -> (RuntimeConfig, Option<String>) {
    match text {
        None => (RuntimeConfig::default(), None),
        Some(text) => match parse(text) {
            Ok(config) => (config, None),
            Err(problem) => (current.clone(), Some(problem)),
        },
    }
}

/// Starts checking `data_dir/config.json`. The receiver always holds the settings in effect, read
/// once now and again after each change. Must run inside a tokio runtime.
pub fn spawn_watcher(data_dir: PathBuf) -> watch::Receiver<RuntimeConfig> {
    let path = data_dir.join(FILE_NAME);
    let text = std::fs::read_to_string(&path).ok();
    let (initial, problem) = reload(&RuntimeConfig::default(), text.as_deref());
    if let Some(problem) = problem {
        tracing::warn!("[config] {} not applied: {problem}; using the defaults", path.display());
    }
    let (tx, rx) = watch::channel(initial);
    let mut last = stamp(&path);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(POLL_EVERY);
        loop {
            ticker.tick().await;
            let now = stamp(&path);
            if now == last {
                continue;
            }
            last = now;
            let text = std::fs::read_to_string(&path).ok();
            let current = tx.borrow().clone();
            let (next, problem) = reload(&current, text.as_deref());
            if let Some(problem) = problem {
                tracing::warn!("[config] {} not applied: {problem}; keeping the settings in effect", path.display());
            }
            if next != current {
                tracing::info!(
                    snapshot_every_secs = next.snapshot_every_secs,
                    snapshot_keep = next.snapshot_keep,
                    "[config] settings applied from {}",
                    path.display()
                );
                tx.send_replace(next);
            }
        }
    });
    rx
}

/// The file's modification time and length, or `None` when it is absent.
fn stamp(path: &Path) -> Option<(SystemTime, u64)> {
    let meta = std::fs::metadata(path).ok()?;
    Some((meta.modified().ok()?, meta.len()))
}

/// Takes a snapshot of the store now, then keeps only the newest `keep`.
pub fn take_now(store: &Path, root: &Path, keep: usize) -> Result<Snapshot, String> {
    let snapshot = snapshot::take(store, root, now_ms()).map_err(|e| e.to_string())?;
    let removed = snapshot::prune(root, keep).map_err(|e| e.to_string())?;
    if removed > 0 {
        tracing::info!("[snapshots] removed {removed} older snapshot(s); keeping {keep}");
    }
    Ok(snapshot)
}

/// One scheduled pass: snapshot the store unless it does not exist or is identical to the newest
/// snapshot, then prune. Returns the snapshot taken, if there was one.
pub fn scheduled(store: &Path, root: &Path, keep: usize) -> Result<Option<Snapshot>, String> {
    if !store.is_file() {
        return Ok(None);
    }
    if snapshot::matches_newest(store, root).map_err(|e| e.to_string())? {
        return Ok(None);
    }
    take_now(store, root, keep).map(Some)
}

/// Runs [`scheduled`] every `snapshot_every_secs`, restarting the wait whenever the settings change.
/// Must run inside a tokio runtime.
pub fn spawn_snapshots(store: PathBuf, root: PathBuf, mut settings: watch::Receiver<RuntimeConfig>) {
    tokio::spawn(async move {
        loop {
            let every = settings.borrow().snapshot_every_secs;
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(every)) => {
                    let keep = settings.borrow().snapshot_keep;
                    let (store, root) = (store.clone(), root.clone());
                    match tokio::task::spawn_blocking(move || scheduled(&store, &root, keep)).await {
                        Ok(Ok(Some(snapshot))) => {
                            tracing::info!("[snapshots] took {} ({} bytes)", snapshot.path.display(), snapshot.bytes);
                        }
                        Ok(Ok(None)) => {}
                        Ok(Err(problem)) => tracing::warn!("[snapshots] {problem}"),
                        Err(problem) => tracing::warn!("[snapshots] the pass did not finish: {problem}"),
                    }
                }
                changed = settings.changed() => {
                    if changed.is_err() {
                        return;
                    }
                }
            }
        }
    });
}

/// Where the snapshots of the store in `data_dir` are kept.
pub fn snapshot_root(data_dir: &Path) -> PathBuf {
    data_dir.join(SNAPSHOT_DIR)
}

/// Milliseconds since the Unix epoch.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_defaults_are_an_hour_and_twenty_four_snapshots() {
        let defaults = RuntimeConfig::default();
        assert_eq!(defaults.snapshot_every_secs, 3600);
        assert_eq!(defaults.snapshot_keep, 24);
    }

    #[test]
    fn a_valid_file_replaces_every_setting_and_a_missing_key_takes_its_default() {
        let config = parse(r#"{"snapshot_keep": 5}"#).expect("valid");
        assert_eq!(config.snapshot_keep, 5);
        assert_eq!(config.snapshot_every_secs, 3600, "left out, so the default");
    }

    #[test]
    fn an_unknown_key_or_a_value_out_of_range_is_refused() {
        assert!(parse(r#"{"snapshot_hourly": true}"#).is_err());
        assert!(parse(r#"{"snapshot_every_secs": 59}"#).is_err());
        assert!(parse(r#"{"snapshot_keep": 0}"#).is_err());
        assert!(parse(r#"{"snapshot_keep": 1001}"#).is_err());
        assert!(parse("{not json").is_err());
    }

    #[test]
    fn a_rejected_file_keeps_the_settings_in_effect() {
        let current = RuntimeConfig {
            snapshot_every_secs: 120,
            snapshot_keep: 7,
        };
        let (next, problem) = reload(&current, Some(r#"{"snapshot_keep": 0}"#));
        assert_eq!(next, current);
        assert!(problem.is_some());
    }

    #[test]
    fn a_missing_file_means_the_defaults() {
        let custom = RuntimeConfig {
            snapshot_every_secs: 120,
            snapshot_keep: 7,
        };
        let (next, problem) = reload(&custom, None);
        assert_eq!(next, RuntimeConfig::default());
        assert!(problem.is_none());
    }

    #[test]
    fn a_scheduled_pass_snapshots_a_changed_store_and_skips_an_unchanged_one() {
        use transferd_store::{PersistedUserData, StoreParams};
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("user_data.enc");
        let save = |name: &str| {
            let data = PersistedUserData {
                display_name: name.to_owned(),
                ..Default::default()
            };
            transferd_store::save(&store, "phrase", &data, &StoreParams::fast()).expect("save");
        };
        let root = snapshot_root(dir.path());
        save("alice");

        assert!(scheduled(&store, &root, 5).expect("pass").is_some(), "first snapshot");
        assert!(scheduled(&store, &root, 5).expect("pass").is_none(), "unchanged");

        std::thread::sleep(Duration::from_millis(3));
        save("bob");
        assert!(scheduled(&store, &root, 5).expect("pass").is_some(), "changed again");
    }
}
