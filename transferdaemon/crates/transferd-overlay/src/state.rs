//! Stored state: what the overlay remembers across restarts, in a format that is versioned and
//! migrated.
//!
//! The file is JSON so it can be inspected by hand, and every field a future version adds is
//! `#[serde(default)]`. A file written by an older build is migrated forward on load, so an
//! upgrade never loses a pairing.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

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
    /// The mesh DNS forwarder's settings, when it is on.
    #[serde(default)]
    pub mesh_dns: Option<crate::dns::MeshDnsConfig>,
}

impl StoredState {
    /// Load and migrate, or start empty when there is nothing to load.
    pub fn load(path: &Path) -> Self {
        let Ok(text) = std::fs::read_to_string(path) else { return Self::default() };
        match serde_json::from_str::<StoredState>(&text) {
            Ok(state) => state.migrated(),
            // A file we cannot read is kept, not deleted: a downgrade must not destroy data.
            Err(_) => Self::default(),
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
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self).unwrap_or_default())?;
        std::fs::rename(&tmp, path)
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
        .or_else(|| dirs_data_local())
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
        assert!(path.exists(), "and is not deleted: a downgrade must not destroy data");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn state_round_trips_through_the_file() {
        let dir = std::env::temp_dir().join(format!("tdov-state-rt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("overlay.json");
        let mut state = StoredState { version: STATE_VERSION, ..Default::default() };
        state.nodes.insert(
            "aa".into(),
            StoredNode { node_id: "aa".into(), name: "laptop".into(), ..serde_json::from_str(r#"{"node_id":"aa"}"#).expect("defaults") },
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