//! Snapshots of the encrypted store: point-in-time copies kept in one folder.
//!
//! A snapshot is a byte copy of the store file. The file is ciphertext under the key derived from
//! the recovery phrase, so a copy needs no key and exposes nothing the store does not. The store is
//! replaced by rename, so the file on disk is always one complete version, and a copy taken at any
//! moment is one too.
//!
//! Layout: `<root>/<created_ms, 20 digits>.enc`. A snapshot is written under a `.partial` name and
//! renamed into place, so an interrupted copy leaves nothing that looks complete.
//!
//! Restoring: stop the daemon, copy the snapshot over the store file, start the daemon. The daemon
//! then needs the recovery phrase that was in use when the snapshot was taken, because the key comes
//! from that phrase and the salt the snapshot holds.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::{StoreError, sync_parent};

/// Width of the zero-padded millisecond timestamp that names a snapshot, so names sort in time order.
const NAME_WIDTH: usize = 20;
const SUFFIX: &str = ".enc";
const PARTIAL: &str = ".partial";

/// A complete snapshot in the folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// When the snapshot was taken, in milliseconds since the Unix epoch.
    pub created_ms: u64,
    pub path: PathBuf,
    pub bytes: u64,
}

fn file_name(created_ms: u64) -> String {
    format!("{created_ms:0width$}{SUFFIX}", width = NAME_WIDTH)
}

/// The timestamp a complete snapshot's file name carries, or `None` for any other name.
fn parse_name(name: &str) -> Option<u64> {
    let digits = name.strip_suffix(SUFFIX)?;
    if digits.len() != NAME_WIDTH || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// Copies the store file at `store` into `root` as the snapshot named `created_ms`.
///
/// Refuses a file that is not a store, and a name that is already in use. If it fails, it leaves
/// nothing that looks like a complete snapshot.
pub fn take(store: &Path, root: &Path, created_ms: u64) -> Result<Snapshot, StoreError> {
    let data = fs::read(store)?;
    if data.len() < 4 || &data[..4] != crate::MAGIC {
        return Err(StoreError::InvalidFile);
    }
    fs::create_dir_all(root)?;
    let name = file_name(created_ms);
    let path = root.join(&name);
    if path.exists() {
        return Err(StoreError::SnapshotExists(name));
    }
    let partial = root.join(format!("{name}{PARTIAL}"));
    {
        let mut out = fs::File::create(&partial)?;
        out.write_all(&data)?;
        out.sync_all()?;
    }
    fs::rename(&partial, &path)?;
    sync_parent(&path)?;
    Ok(Snapshot {
        created_ms,
        path,
        bytes: data.len() as u64,
    })
}

/// Every complete snapshot under `root`, oldest first. Other files are ignored, and so are unfinished
/// copies.
pub fn list(root: &Path) -> Result<Vec<Snapshot>, StoreError> {
    if !root.is_dir() {
        return Ok(Vec::new());
    }
    let mut found = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(created_ms) = parse_name(&name) else {
            continue;
        };
        if !entry.file_type()?.is_file() {
            continue;
        }
        found.push(Snapshot {
            created_ms,
            path: entry.path(),
            bytes: entry.metadata()?.len(),
        });
    }
    found.sort_by_key(|snapshot| snapshot.created_ms);
    Ok(found)
}

/// Removes the oldest snapshots so that `keep` remain, and any unfinished copy an interrupted run
/// left behind. Returns how many complete snapshots were removed.
pub fn prune(root: &Path, keep: usize) -> Result<usize, StoreError> {
    if !root.is_dir() {
        return Ok(0);
    }
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().ends_with(PARTIAL) {
            fs::remove_file(entry.path())?;
        }
    }
    let complete = list(root)?;
    let excess = complete.len().saturating_sub(keep);
    for snapshot in complete.iter().take(excess) {
        fs::remove_file(&snapshot.path)?;
    }
    Ok(excess)
}

/// Whether the newest snapshot under `root` holds exactly the bytes the store holds now. The
/// scheduler skips a snapshot of an unchanged store, so an idle daemon does not fill the folder.
/// `false` when there is no snapshot yet.
pub fn matches_newest(store: &Path, root: &Path) -> Result<bool, StoreError> {
    let Some(newest) = list(root)?.pop() else {
        return Ok(false);
    };
    Ok(fs::read(&newest.path)? == fs::read(store)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PersistedUserData, StoreParams, load, save};

    fn store_with(path: &Path, phrase: &str, display_name: &str) {
        let data = PersistedUserData {
            display_name: display_name.to_owned(),
            ..Default::default()
        };
        save(path, phrase, &data, &StoreParams::fast()).expect("save");
    }

    #[test]
    fn a_snapshot_is_a_byte_copy_of_the_store() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("user_data.enc");
        store_with(&store, "phrase", "alice");

        let snap = take(&store, &dir.path().join("snapshots"), 1_000).expect("take");

        assert_eq!(fs::read(&snap.path).unwrap(), fs::read(&store).unwrap());
        assert_eq!(snap.bytes, fs::metadata(&store).unwrap().len());
    }

    #[test]
    fn a_snapshot_restores_the_data_it_was_taken_from() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("user_data.enc");
        store_with(&store, "phrase", "before");
        let snap = take(&store, &dir.path().join("snapshots"), 2_000).expect("take");

        store_with(&store, "phrase", "after");
        fs::copy(&snap.path, &store).expect("restore");

        let restored = load(&store, "phrase", &StoreParams::fast()).expect("load");
        assert_eq!(restored.display_name, "before");
    }

    #[test]
    fn a_file_that_is_not_a_store_is_not_snapshotted() {
        let dir = tempfile::tempdir().unwrap();
        let junk = dir.path().join("junk.enc");
        fs::write(&junk, b"hello").unwrap();
        let root = dir.path().join("snapshots");

        assert!(matches!(
            take(&junk, &root, 3),
            Err(StoreError::InvalidFile)
        ));
        assert!(list(&root).unwrap().is_empty());
    }

    #[test]
    fn a_snapshot_name_is_not_reused() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("user_data.enc");
        store_with(&store, "phrase", "alice");
        let root = dir.path().join("snapshots");
        take(&store, &root, 4_000).expect("first");

        let second = take(&store, &root, 4_000);

        assert!(matches!(second, Err(StoreError::SnapshotExists(_))));
    }

    #[test]
    fn list_is_oldest_first_and_ignores_other_files() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("user_data.enc");
        store_with(&store, "phrase", "alice");
        let root = dir.path().join("snapshots");
        for created in [30, 10, 20] {
            take(&store, &root, created).expect("take");
        }
        fs::write(root.join("notes.txt"), b"x").unwrap();
        fs::write(root.join("7.enc"), b"x").unwrap();

        let times: Vec<u64> = list(&root).unwrap().iter().map(|s| s.created_ms).collect();

        assert_eq!(times, vec![10, 20, 30]);
    }

    #[test]
    fn prune_keeps_the_newest_and_clears_unfinished_copies() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("user_data.enc");
        store_with(&store, "phrase", "alice");
        let root = dir.path().join("snapshots");
        for created in [10, 20, 30, 40] {
            take(&store, &root, created).expect("take");
        }
        let partial = root.join(format!("{:020}.enc.partial", 50));
        fs::write(&partial, b"unfinished").unwrap();

        let removed = prune(&root, 2).expect("prune");

        assert_eq!(removed, 2);
        let left: Vec<u64> = list(&root).unwrap().iter().map(|s| s.created_ms).collect();
        assert_eq!(left, vec![30, 40]);
        assert!(!partial.exists());
    }

    #[test]
    fn matches_newest_tells_an_unchanged_store_from_a_changed_one() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("user_data.enc");
        store_with(&store, "phrase", "alice");
        let root = dir.path().join("snapshots");
        assert!(!matches_newest(&store, &root).unwrap(), "no snapshot yet");

        take(&store, &root, 5_000).expect("take");
        assert!(matches_newest(&store, &root).unwrap());

        store_with(&store, "phrase", "changed");
        assert!(!matches_newest(&store, &root).unwrap());
    }
}
