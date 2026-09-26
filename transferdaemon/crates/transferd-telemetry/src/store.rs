use std::path::{Path, PathBuf};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::events::TelemetryEvent;

const MAGIC: &[u8; 4] = b"TDTL";
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const MAX_FILES: u32 = 5;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("encryption failed")]
    Encrypt,
    #[error("decryption failed")]
    Decrypt,
    #[error("serialization: {0}")]
    Serialize(#[from] bincode::Error),
    #[error("corrupt header")]
    CorruptHeader,
}

/// Load an existing device key from `path`, or generate and persist a new one.
///
/// The returned key is zeroized on drop. Note: the key must remain readable
/// on disk for offline decryption after restart; it protects device-local
/// telemetry, not user secrets.
pub fn load_or_create_device_key(path: &Path) -> Result<Zeroizing<[u8; KEY_LEN]>, StoreError> {
    if path.exists() {
        let bytes = std::fs::read(path)?;
        if bytes.len() == KEY_LEN {
            let mut key = [0u8; KEY_LEN];
            key.copy_from_slice(&bytes);
            return Ok(Zeroizing::new(key));
        }
    }
    let mut key = [0u8; KEY_LEN];
    rand::thread_rng().fill_bytes(&mut key);
    std::fs::write(path, key.as_slice())?;
    Ok(Zeroizing::new(key))
}

fn base_path(dir: &Path) -> PathBuf {
    dir.join("user_telemetry.enc")
}

fn rotated_path(dir: &Path, n: u32) -> PathBuf {
    dir.join(format!("user_telemetry.{n}.enc"))
}

/// Rotate existing flush files: `.4.enc` dropped, each shifts up by one.
fn rotate(dir: &Path) -> Result<(), StoreError> {
    // Drop the oldest slot if full.
    let oldest = rotated_path(dir, MAX_FILES - 1);
    if oldest.exists() {
        std::fs::remove_file(&oldest)?;
    }
    // Shift .3→.4, .2→.3, …, .0→.1
    for n in (0..(MAX_FILES - 1)).rev() {
        let src = rotated_path(dir, n);
        let dst = rotated_path(dir, n + 1);
        if src.exists() {
            std::fs::rename(&src, &dst)?;
        }
    }
    // Move current base → .0
    let base = base_path(dir);
    if base.exists() {
        std::fs::rename(&base, rotated_path(dir, 0))?;
    }
    Ok(())
}

/// Encrypt and flush `events` to `dir/user_telemetry.enc`, rotating old files.
pub fn flush(dir: &Path, key: &[u8; KEY_LEN], events: &[TelemetryEvent]) -> Result<(), StoreError> {
    if events.is_empty() {
        return Ok(());
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| StoreError::Encrypt)?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext: Vec<u8> = bincode::serialize(events)?;
    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).map_err(|_| StoreError::Encrypt)?;

    // Layout: MAGIC (4) | nonce (12) | ciphertext
    let mut buf = Vec::with_capacity(MAGIC.len() + NONCE_LEN + ciphertext.len());
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(&nonce_bytes);
    buf.extend_from_slice(&ciphertext);

    rotate(dir)?;
    std::fs::write(base_path(dir), &buf)?;
    Ok(())
}

/// Decrypt and deserialize events from the most recent flush file.
pub fn load_latest(dir: &Path, key: &[u8; KEY_LEN]) -> Result<Vec<TelemetryEvent>, StoreError> {
    let path = base_path(dir);
    if !path.exists() {
        return Ok(vec![]);
    }
    let buf = std::fs::read(&path)?;
    if buf.len() < MAGIC.len() + NONCE_LEN || &buf[..MAGIC.len()] != MAGIC {
        return Err(StoreError::CorruptHeader);
    }
    let nonce_bytes = &buf[MAGIC.len()..MAGIC.len() + NONCE_LEN];
    let ciphertext = &buf[MAGIC.len() + NONCE_LEN..];

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| StoreError::Decrypt)?;
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| StoreError::Decrypt)?;

    let events: Vec<TelemetryEvent> = bincode::deserialize(&plaintext)?;
    Ok(events)
}
