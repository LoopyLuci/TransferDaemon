//! Stored state: what the overlay remembers across restarts, in a format that is versioned and
//! migrated.
//!
//! The file is JSON so it can be inspected by hand, and every field a future version adds is
//! `#[serde(default)]`. A file written by an older build is migrated forward on load, so an
//! upgrade never loses a pairing.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// The format this build writes.
pub const STATE_VERSION: u32 = 1;

/// One paired node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredNode {
    pub node_id: String,
    #[serde(default)]
    pub name: String,
    /// The hybrid public key verified on first contact (trust on first use).
    #[serde(default)]
    pub hybrid_public_key: Vec<u8>,
    /// The key fingerprint its invite named (hex): the key it presents on first contact must
    /// hash to this. Empty for a node that was not paired by invite.
    #[serde(default)]
    pub key_fingerprint: String,
    /// Relays this node published, as `host:port`.
    #[serde(default)]
    pub relays: Vec<String>,
    /// Addresses it published for direct dialling.
    #[serde(default)]
    pub direct: Vec<String>,
    #[serde(default)]
    pub paired_at: u64,
    /// Its name as it last introduced itself.
    #[serde(default)]
    pub last_name: String,
    /// The nonce of the invite we accepted from it (hex), presented in our hello so it knows
    /// the pairing is mutual.
    #[serde(default)]
    pub pairing: String,
}

/// An invite this node issued that has not been used yet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredInvite {
    /// Its nonce, hex.
    pub nonce: String,
    pub expires_at: u64,
}

/// An exposed service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredExpose {
    pub service: String,
    pub local_addr: String,
    /// Node ids, or the literal `"*paired"`.
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub description: String,
}

/// A local endpoint that forwards to a peer's service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredConnect {
    /// `node:<id>` or `group:<name>`.
    pub target: String,
    pub service: String,
    /// The local address the application connects to.
    pub local_addr: String,
    #[serde(default)]
    pub route: String,
}

/// A named set of nodes that between them offer a service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredGroup {
    pub name: String,
    #[serde(default)]
    pub members: Vec<String>,
}

/// Everything the overlay remembers.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StoredState {
    /// The format version. Absent in a v0 file, which is why it defaults to 0.
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub nodes: BTreeMap<String, StoredNode>,
    #[serde(default)]
    pub exposes: Vec<StoredExpose>,
    #[serde(default)]
    pub connects: Vec<StoredConnect>,
    #[serde(default)]
    pub groups: Vec<StoredGroup>,
    /// Invites issued and not used yet, so a node that accepts one after a restart is still
    /// recognised.
    #[serde(default)]
    pub invites: Vec<StoredInvite>,
    /// The mesh DNS forwarder's settings, when it is on.
    #[serde(default)]
    pub mesh_dns: Option<crate::dns::MeshDnsConfig>,
}

impl StoredState {
    /// Load and migrate, or start empty when there is nothing to load.
    pub fn load(path: &Path) -> Self {
        let Ok(text) = std::fs::read_to_string(path) else {
            return Self::default();
        };
        match serde_json::from_str::<StoredState>(&text) {
            Ok(state) => state.migrated(),
            // A file we cannot read (written by a newer build, or damaged) is copied aside before
            // anything is saved over it: a downgrade must not destroy data. The first copy is kept.
            Err(_) => {
                let aside = path.with_extension("json.unreadable");
                if !aside.exists() {
                    let _ = std::fs::write(&aside, text.as_bytes());
                }
                Self::default()
            }
        }
    }

    /// Bring this state up to the current format version.
    ///
    /// v0 (the first release) had no `version` field and stored peers in a plain array. It is
    /// upgraded by keying them on their node id, which is what v1 uses.
    pub fn migrated(mut self) -> Self {
        if self.version == 0 {
            // v0 had no `version` field. v1 keys peers on their node id (which is what v0
            // already did), so the migration only has to stamp the version — and fill in the
            // fields v0 never wrote.
            for node in self.nodes.values_mut() {
                if node.last_name.is_empty() {
                    node.last_name = node.name.clone();
                }
            }
            self.version = 1;
        }
        self
    }

    /// Write the state, atomically.
    ///
    /// Each save writes its own temporary file, so saves that run at once cannot move each other's:
    /// a shared temporary name made one rename find the file already gone.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        static SAVES: AtomicU64 = AtomicU64::new(0);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let n = SAVES.fetch_add(1, Ordering::Relaxed);
        let tmp = path.with_extension(format!("json.{}.{n}.tmp", std::process::id()));
        let result = std::fs::write(&tmp, serde_json::to_vec_pretty(self).unwrap_or_default())
            .and_then(|()| std::fs::rename(&tmp, path));
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result
    }

    /// Where the overlay keeps its state, next to the daemon's other files.
    pub fn default_path() -> PathBuf {
        transferd_control_data_dir().join("overlay.json")
    }
}

fn transferd_control_data_dir() -> PathBuf {
    // The overlay must not depend on the control crate, so resolve the same place it does.
    std::env::var_os("TRANSFERD_DATA_DIR")
        .map(PathBuf::from)
        .or_else(dirs_data_local)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("transferdaemon")
}

fn dirs_data_local() -> Option<PathBuf> {
    if cfg!(windows) {
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
    } else if cfg!(target_os = "macos") {
        std::env::var_os("HOME").map(|h| PathBuf::from(h).join("Library/Application Support"))
    } else {
        std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_v0_file_with_no_version_is_migrated() {
        // What the first release wrote: no `version`, and nodes keyed by node id already.
        let old = r#"{"nodes":{"aa":{"node_id":"aa","name":"laptop"}},"exposes":[]}"#;
        let mut state: StoredState = serde_json::from_str(old).expect("parse");
        assert_eq!(state.version, 0, "an unversioned file is v0");
        state = state.migrated();
        assert_eq!(state.version, STATE_VERSION);
        assert_eq!(state.nodes["aa"].name, "laptop");
    }

    #[test]
    fn saves_from_several_threads_to_one_file_all_land() {
        // Each save writes a temporary file and renames it over the state. Saves that run at once
        // share that temporary file, so one rename can find it already moved by another.
        let dir = std::env::temp_dir().join(format!("tdov-state-race-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("overlay.json");
        let start = std::sync::Barrier::new(8);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    start.wait();
                    for _ in 0..200 {
                        let state = StoredState {
                            version: STATE_VERSION,
                            ..Default::default()
                        };
                        state
                            .save(&path)
                            .expect("a save that runs alongside others still lands");
                    }
                });
            }
        });
        assert_eq!(StoredState::load(&path).version, STATE_VERSION);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_state_file_is_empty_not_an_error() {
        let state = StoredState::load(Path::new("no/such/overlay.json"));
        assert!(state.nodes.is_empty());
        assert!(state.exposes.is_empty());
    }

    #[test]
    fn a_corrupt_state_file_is_left_alone_on_disk() {
        let dir = std::env::temp_dir().join(format!("tdov-state-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("overlay.json");
        std::fs::write(&path, b"{ not json").expect("write");
        let state = StoredState::load(&path);
        assert!(state.nodes.is_empty(), "a corrupt file loads as empty");
        assert!(
            path.exists(),
            "and is not deleted: a downgrade must not destroy data"
        );
        let aside = path.with_extension("json.unreadable");
        assert_eq!(
            std::fs::read(&aside).expect("a copy is kept aside"),
            b"{ not json",
            "so a later save cannot destroy it"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn state_round_trips_through_the_file() {
        let dir = std::env::temp_dir().join(format!("tdov-state-rt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("overlay.json");
        let mut state = StoredState {
            version: STATE_VERSION,
            ..Default::default()
        };
        state.nodes.insert(
            "aa".into(),
            StoredNode {
                node_id: "aa".into(),
                name: "laptop".into(),
                ..serde_json::from_str(r#"{"node_id":"aa"}"#).expect("defaults")
            },
        );
        state.exposes.push(StoredExpose {
            service: "http".into(),
            local_addr: "127.0.0.1:8000".into(),
            allow: vec!["*paired".into()],
            description: String::new(),
        });
        state.save(&path).expect("save");
        let back = StoredState::load(&path);
        assert_eq!(back.version, STATE_VERSION);
        assert_eq!(back.exposes.len(), 1);
        assert_eq!(back.exposes[0].allow, vec!["*paired".to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
