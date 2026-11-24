//! Encrypted backup and restore for TransferDaemon.
//!
//! Provides functionality to export and import identity, contacts,
//! and message history in an encrypted format.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};

/// Backup file format version.
pub const BACKUP_VERSION: u32 = 1;

/// Magic bytes for backup files.
pub const BACKUP_MAGIC: &[u8; 8] = b"TD-BACK\0";

// ---------------------------------------------------------------------------
// Backup Data
// ---------------------------------------------------------------------------

/// Complete backup data.
#[derive(Debug, Serialize, Deserialize)]
pub struct BackupData {
    /// Backup format version.
    pub version: u32,
    /// Timestamp when the backup was created.
    pub timestamp: u64,
    /// User's identity (public key and display name).
    pub identity: BackupIdentity,
    /// List of contacts.
    pub contacts: Vec<BackupContact>,
    /// Message history (optional, can be large).
    #[serde(default)]
    pub messages: Vec<BackupMessage>,
}

/// Identity data in backup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupIdentity {
    pub public_key: String,
    pub display_name: String,
}

/// Contact data in backup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupContact {
    pub id: String,
    pub name: String,
    pub nickname: Option<String>,
    pub public_key: String,
}

/// Message data in backup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupMessage {
    pub contact_id: String,
    pub content: String,
    pub timestamp: u64,
    pub outbound: bool,
}

// ---------------------------------------------------------------------------
// Backup Export
// ---------------------------------------------------------------------------

/// Export a backup to a file.
pub fn export_backup(
    path: &Path,
    identity: &BackupIdentity,
    contacts: &[BackupContact],
    messages: &[BackupMessage],
    passphrase: &str,
) -> Result<(), BackupError> {
    let data = BackupData {
        version: BACKUP_VERSION,
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        identity: identity.clone(),
        contacts: contacts.to_vec(),
        messages: messages.to_vec(),
    };

    // Serialize to JSON
    let json = serde_json::to_string_pretty(&data)
        .map_err(|e| BackupError::SerializationError(e.to_string()))?;

    // Encrypt the data
    let encrypted = encrypt_backup(json.as_bytes(), passphrase)?;

    // Write to file
    let mut output = Vec::new();
    output.extend_from_slice(BACKUP_MAGIC);
    output.extend_from_slice(&BACKUP_VERSION.to_le_bytes());
    output.extend_from_slice(&(encrypted.len() as u32).to_le_bytes());
    output.extend_from_slice(&encrypted);

    std::fs::write(path, &output)
        .map_err(|e| BackupError::IoError(e.to_string()))?;

    Ok(())
}

/// Import a backup from a file.
pub fn import_backup(
    path: &Path,
    passphrase: &str,
) -> Result<BackupData, BackupError> {
    // Read file
    let data = std::fs::read(path)
        .map_err(|e| BackupError::IoError(e.to_string()))?;

    // Verify magic bytes
    if data.len() < 16 {
        return Err(BackupError::InvalidFormat("File too small".into()));
    }
    if &data[..8] != BACKUP_MAGIC {
        return Err(BackupError::InvalidFormat("Invalid magic bytes".into()));
    }

    // Read version (length verified by the >= 16 check above)
    let version = u32::from_le_bytes(data[8..12].try_into().expect("backup header is >= 16 bytes"));
    if version != BACKUP_VERSION {
        return Err(BackupError::UnsupportedVersion(version));
    }

    // Read encrypted data length
    let enc_len =
        u32::from_le_bytes(data[12..16].try_into().expect("backup header is >= 16 bytes")) as usize;
    if data.len() < 16 + enc_len {
        return Err(BackupError::InvalidFormat("Truncated data".into()));
    }

    // Decrypt the data
    let encrypted = &data[16..16 + enc_len];
    let json_bytes = decrypt_backup(encrypted, passphrase)?;

    // Parse JSON
    let json_str = String::from_utf8(json_bytes)
        .map_err(|e| BackupError::InvalidFormat(e.to_string()))?;

    let backup: BackupData = serde_json::from_str(&json_str)
        .map_err(|e| BackupError::DeserializationError(e.to_string()))?;

    Ok(backup)
}

// ---------------------------------------------------------------------------
// Encryption
// ---------------------------------------------------------------------------

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use argon2::Argon2;
use rand::RngCore;

/// Derive an AES-256 key from a passphrase using Argon2id.
fn derive_key(passphrase: &str, salt: &[u8; 16]) -> Result<[u8; 32], BackupError> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| BackupError::EncryptionError(format!("Argon2 key derivation failed: {e}")))?;
    Ok(key)
}

fn encrypt_backup(data: &[u8], passphrase: &str) -> Result<Vec<u8>, BackupError> {
    // Generate random salt and nonce
    let mut salt = [0u8; 16];
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    // Derive key from passphrase
    let key = derive_key(passphrase, &salt)?;

    // Create cipher and encrypt
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| BackupError::EncryptionError(format!("Failed to create cipher: {e}")))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|e| BackupError::EncryptionError(format!("Encryption failed: {e}")))?;

    // Return salt || nonce || ciphertext
    let mut out = Vec::with_capacity(16 + 12 + ciphertext.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn decrypt_backup(data: &[u8], passphrase: &str) -> Result<Vec<u8>, BackupError> {
    // Need at least 16 (salt) + 12 (nonce) + 16 (GCM tag) = 44 bytes
    if data.len() < 44 {
        return Err(BackupError::DecryptionError("Data too short".into()));
    }

    // Extract salt, nonce, and ciphertext
    let salt: [u8; 16] = data[..16]
        .try_into()
        .map_err(|_| BackupError::DecryptionError("Invalid salt".into()))?;
    let nonce_bytes: [u8; 12] = data[16..28]
        .try_into()
        .map_err(|_| BackupError::DecryptionError("Invalid nonce".into()))?;
    let ciphertext = &data[28..];

    // Derive key from passphrase
    let key = derive_key(passphrase, &salt)?;

    // Create cipher and decrypt
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| BackupError::DecryptionError(format!("Failed to create cipher: {e}")))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| BackupError::DecryptionError(format!("Decryption failed (wrong passphrase?): {e}")))?;

    Ok(plaintext)
}

// ---------------------------------------------------------------------------
// Backup Error
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    #[error("IO error: {0}")]
    IoError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    #[error("Invalid backup format: {0}")]
    InvalidFormat(String),

    #[error("Unsupported backup version: {0}")]
    UnsupportedVersion(u32),

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("Decryption error: {0}")]
    DecryptionError(String),
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backup_version() {
        assert_eq!(BACKUP_VERSION, 1);
    }

    #[test]
    fn test_backup_magic() {
        assert_eq!(BACKUP_MAGIC, b"TD-BACK\0");
    }

    #[test]
    fn test_encryption_roundtrip() {
        let plaintext = b"Hello, this is a test backup!";
        let passphrase = "my-secret-passphrase";

        // Encrypt
        let encrypted = encrypt_backup(plaintext, passphrase).unwrap();
        assert_ne!(encrypted, plaintext.to_vec());

        // Decrypt with correct passphrase
        let decrypted = decrypt_backup(&encrypted, passphrase).unwrap();
        assert_eq!(decrypted, plaintext.to_vec());
    }

    #[test]
    fn test_encryption_wrong_passphrase() {
        let plaintext = b"Secret data";
        let passphrase = "correct-passphrase";

        let encrypted = encrypt_backup(plaintext, passphrase).unwrap();

        // Try to decrypt with wrong passphrase
        let result = decrypt_backup(&encrypted, "wrong-passphrase");
        assert!(result.is_err());
    }

    #[test]
    fn test_encryption_different_ciphertext() {
        let plaintext = b"Same data encrypted twice";
        let passphrase = "passphrase";

        let enc1 = encrypt_backup(plaintext, passphrase).unwrap();
        let enc2 = encrypt_backup(plaintext, passphrase).unwrap();

        // Different salt and nonce should produce different ciphertext
        assert_ne!(enc1, enc2);
    }
}
