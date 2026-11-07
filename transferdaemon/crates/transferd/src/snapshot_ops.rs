//! The store's snapshots and the settings in effect, as hub operations: `daemon.snapshot`,
//! `daemon.snapshots` and `daemon.config`. They show up in the CLI, MCP and ACP like every other
//! operation.

use std::path::PathBuf;
use std::sync::Arc;

use serde_json::{Value, json};
use tokio::sync::watch;
use transferd_control::catalog::{Operation, extension_op};
use transferd_control::hub::{Extension, ExtensionCall, Hub};

use crate::runtime_config::{self, RuntimeConfig};

/// The operations, served from the store and its snapshot folder.
pub struct Ops {
    store: PathBuf,
    root: PathBuf,
    config_file: PathBuf,
    settings: watch::Receiver<RuntimeConfig>,
}

impl Ops {
    pub fn new(store: PathBuf, root: PathBuf, config_file: PathBuf, settings: watch::Receiver<RuntimeConfig>) -> Self {
        Self {
            store,
            root,
            config_file,
            settings,
        }
    }
}

/// Puts the operations on `hub`.
pub fn register(hub: &Arc<Hub>, ops: Ops) {
    hub.add_extension(Arc::new(ops));
}

fn snapshot_json(snapshot: &transferd_store::snapshot::Snapshot) -> Value {
    json!({
        "created_ms": snapshot.created_ms,
        "bytes": snapshot.bytes,
        "path": snapshot.path.display().to_string(),
    })
}

fn failed(problem: impl std::fmt::Display) -> (String, String) {
    ("snapshot_failed".to_owned(), problem.to_string())
}

impl Extension for Ops {
    fn operations(&self) -> Vec<Operation> {
        let none = json!({"type": "object", "properties": {}});
        vec![
            extension_op(
                "daemon.snapshot",
                "Take a snapshot of the encrypted store now, then keep only the newest snapshot_keep (see daemon.config). \
                 A snapshot is a copy of the ciphertext: taking one needs no recovery phrase, restoring one does",
                true,
                false,
                none.clone(),
                json!({}),
            ),
            extension_op(
                "daemon.snapshots",
                "The store's snapshots, oldest first: when each was taken, its size and file",
                false,
                false,
                none.clone(),
                json!({}),
            ),
            extension_op(
                "daemon.config",
                "The settings in effect (snapshot_every_secs, snapshot_keep) and the config.json they come from; a valid edit applies within seconds",
                false,
                false,
                none,
                json!({}),
            ),
        ]
    }

    fn call<'a>(&'a self, op: &'a str, _args: Value) -> ExtensionCall<'a> {
        Box::pin(async move {
            match op {
                "daemon.snapshot" => {
                    let keep = self.settings.borrow().snapshot_keep;
                    let (store, root) = (self.store.clone(), self.root.clone());
                    let taken = tokio::task::spawn_blocking(move || runtime_config::take_now(&store, &root, keep))
                        .await
                        .map_err(failed)?
                        .map_err(failed)?;
                    Ok(snapshot_json(&taken))
                }
                "daemon.snapshots" => {
                    let root = self.root.clone();
                    let listed = tokio::task::spawn_blocking(move || transferd_store::snapshot::list(&root))
                        .await
                        .map_err(failed)?
                        .map_err(failed)?;
                    Ok(json!({"snapshots": listed.iter().map(snapshot_json).collect::<Vec<_>>()}))
                }
                "daemon.config" => {
                    let current = self.settings.borrow().clone();
                    Ok(json!({
                        "snapshot_every_secs": current.snapshot_every_secs,
                        "snapshot_keep": current.snapshot_keep,
                        "file": self.config_file.display().to_string(),
                        "file_present": self.config_file.is_file(),
                        "limits": {
                            "snapshot_every_secs_min": runtime_config::MIN_SNAPSHOT_EVERY_SECS,
                            "snapshot_keep_max": runtime_config::MAX_SNAPSHOT_KEEP,
                        },
                    }))
                }
                other => Err(("unknown_operation".to_owned(), other.to_owned())),
            }
        })
    }
}
