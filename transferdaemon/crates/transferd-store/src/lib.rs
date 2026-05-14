//! Encrypted persistent user data store for TransferDaemon.
//!
//! # File format
//!
//! ```text
//! MAGIC  (4 bytes : b"TDMN")
//! SALT   (16 bytes: random, generated once at account creation)
//! NONCE  (12 bytes: random, fresh on every save)
//! CIPHERTEXT (bincode(PersistedUserData) encrypted with AES-256-GCM;
//!             the 16-byte GCM authentication tag is appended by the
//!             aes-gcm crate and included in this region)
//! ```
//!
//! # Key derivation
//!
//! `Argon2id(phrase_bytes, salt)` → 32-byte AES-256 key.
//! Params are configurable; use `StoreParams::production()` for real use and
//! `StoreParams::fast()` in tests so they run in milliseconds.
//!
//! # Default file location
//!
//! | Platform | Path |
//! |----------|------|
//! | Linux    | `~/.local/share/transferdaemon/user_data.enc` |
//! | macOS    | `~/Library/Application Support/transferdaemon/user_data.enc` |
//! | Windows  | `%LOCALAPPDATA%\transferdaemon\user_data.enc` |

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Public error type
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid file (wrong magic bytes or truncated)")]
    InvalidFile,

    #[error("wrong passphrase or corrupted data")]
    DecryptionFailed,

    #[error("serialisation error: {0}")]
    Serialisation(String),

    #[error("key derivation error: {0}")]
    Kdf(String),

    #[error("no data directory available on this platform")]
    NoDataDir,
}

// ---------------------------------------------------------------------------
// Argon2 parameters
// ---------------------------------------------------------------------------

/// Controls the cost of key derivation.
///
/// Use [`StoreParams::production()`] for real deployments (resistant to
/// offline brute-force) and [`StoreParams::fast()`] in unit tests so the
/// test suite stays fast.
#[derive(Debug, Clone)]
pub struct StoreParams {
    /// Memory cost in KiB.  Production: 65 536 (64 MiB).
    pub m_cost: u32,
    /// Time cost (iterations).  Production: 3.
    pub t_cost: u32,
    /// Parallelism.  Production: 4.
    pub p_cost: u32,
}

impl StoreParams {
    pub fn production() -> Self {
        Self { m_cost: 65_536, t_cost: 3, p_cost: 4 }
    }

    /// Minimal cost — fast enough for unit tests, NOT safe for production.
    pub fn fast() -> Self {
        Self { m_cost: 1024, t_cost: 1, p_cost: 1 }
    }
}

// ---------------------------------------------------------------------------
// Persisted data model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PersistedContact {
    pub id:           String,
    pub name:         String,
    pub last_seen_ts: u64,
    pub online:       bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PersistedMessage {
    pub id:           String,
    pub contact_id:   String,
    pub outbound:     bool,
    pub content_type: String,
    pub text:         String,
    pub file_name:    String,
    pub file_size:    u64,
    pub file_xferd:   u64,
    pub file_mime:    String,
    pub timestamp_ts: u64,
    pub status:       String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PersistedUserData {
    /// Bump when the schema changes (current: 2).
    pub version:               u32,
    pub display_name:          String,
    /// Hex-encoded 32-byte Ed25519 verifying key.
    pub public_key_hex:        String,
    /// Hex-encoded 2624-byte hybrid public key: `ed25519_pk ‖ ml_dsa_87_pk`.
    /// Empty on records written before the quantum-resistant identity upgrade.
    #[serde(default)]
    pub hybrid_public_key_hex: String,
    pub recovery_phrase:       String,
    pub contacts:              Vec<PersistedContact>,
    /// contact_id → messages
    pub messages:              HashMap<String, Vec<PersistedMessage>>,
    pub settings:              HashMap<String, String>,
    pub next_id:               u64,
    pub created_at:            u64,
    pub last_modified:         u64,
}

// ---------------------------------------------------------------------------
// File-format constants
// ---------------------------------------------------------------------------

const MAGIC:     &[u8; 4] = b"TDMN";
const SALT_LEN:  usize    = 16;
const NONCE_LEN: usize    = 12;
const KEY_LEN:   usize    = 32;

const HDR_LEN: usize = 4 + SALT_LEN + NONCE_LEN; // 32 bytes total

// ---------------------------------------------------------------------------
// Core crypto helpers
// ---------------------------------------------------------------------------

fn derive_key(phrase: &str, salt: &[u8], params: &StoreParams) -> Result<Zeroizing<[u8; KEY_LEN]>, StoreError> {
    let argon2_params = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(KEY_LEN))
        .map_err(|e| StoreError::Kdf(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(phrase.as_bytes(), salt, key.as_mut())
        .map_err(|e| StoreError::Kdf(e.to_string()))?;
    Ok(key)
}

fn encrypt(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<(Vec<u8>, [u8; NONCE_LEN]), StoreError> {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce  = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| StoreError::DecryptionFailed)?;
    Ok((ciphertext, nonce_bytes))
}

fn decrypt(key: &[u8; KEY_LEN], nonce_bytes: &[u8; NONCE_LEN], ciphertext: &[u8]) -> Result<Vec<u8>, StoreError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce  = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| StoreError::DecryptionFailed)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Return the platform-appropriate directory for the user data file.
///
/// Creates the directory if it does not yet exist.
pub fn default_store_path() -> Result<PathBuf, StoreError> {
    let base = dirs::data_local_dir().ok_or(StoreError::NoDataDir)?;
    let dir  = base.join("transferdaemon");
    fs::create_dir_all(&dir)?;
    Ok(dir.join("user_data.enc"))
}

/// Encrypt `data` with a key derived from `phrase` and write to `path`.
///
/// If the file already exists, its salt is reused so the same phrase always
/// produces the same key.  If it does not exist, a fresh random salt is
/// generated and embedded in the new file.
pub fn save(path: &Path, phrase: &str, data: &PersistedUserData, params: &StoreParams) -> Result<(), StoreError> {
    // Reuse existing salt if the file already exists (keeps key stable).
    let salt: [u8; SALT_LEN] = if path.exists() {
        let existing = fs::read(path)?;
        if existing.len() >= HDR_LEN && &existing[..4] == MAGIC {
            existing[4..4 + SALT_LEN].try_into().unwrap_or_else(|_| fresh_salt())
        } else {
            fresh_salt()
        }
    } else {
        fresh_salt()
    };

    let key = derive_key(phrase, &salt, params)?;
    let plaintext  = bincode::serialize(data)
        .map_err(|e| StoreError::Serialisation(e.to_string()))?;
    let (ciphertext, nonce) = encrypt(&key, &plaintext)?;

    // Build the file: MAGIC || SALT || NONCE || CIPHERTEXT
    let mut file = Vec::with_capacity(HDR_LEN + ciphertext.len());
    file.extend_from_slice(MAGIC);
    file.extend_from_slice(&salt);
    file.extend_from_slice(&nonce);
    file.extend_from_slice(&ciphertext);

    // Atomic write: write to a temp file then rename.
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, &file)?;
    fs::rename(&tmp, path)?;

    Ok(())
}

/// Decrypt and deserialise user data from `path` using a key derived from `phrase`.
///
/// Returns [`StoreError::DecryptionFailed`] if the phrase is wrong.
pub fn load(path: &Path, phrase: &str, params: &StoreParams) -> Result<PersistedUserData, StoreError> {
    let raw = fs::read(path)?;

    if raw.len() < HDR_LEN {
        return Err(StoreError::InvalidFile);
    }
    if &raw[..4] != MAGIC {
        return Err(StoreError::InvalidFile);
    }

    let salt:  [u8; SALT_LEN]  = raw[4..4 + SALT_LEN].try_into().unwrap();
    let nonce: [u8; NONCE_LEN] = raw[4 + SALT_LEN..HDR_LEN].try_into().unwrap();
    let ciphertext = &raw[HDR_LEN..];

    let key       = derive_key(phrase, &salt, params)?;
    let plaintext = decrypt(&key, &nonce, ciphertext)?;

    let data: PersistedUserData = bincode::deserialize(&plaintext)
        .map_err(|e| StoreError::Serialisation(e.to_string()))?;

    Ok(data)
}

/// Return true if a store file exists at `path` and has the correct magic header.
pub fn file_exists(path: &Path) -> bool {
    fs::read(path)
        .ok()
        .as_deref()
        .and_then(|b| b.get(..4))
        .map(|hdr| hdr == MAGIC)
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

fn fresh_salt() -> [u8; SALT_LEN] {
    let mut s = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut s);
    s
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_data() -> PersistedUserData {
        PersistedUserData {
            version:               2,
            display_name:          "Alice".into(),
            public_key_hex:        "abcd".repeat(16),
            hybrid_public_key_hex: "ef01".repeat(656), // 2624 bytes hex = 5248 chars
            recovery_phrase:       "word ".repeat(12).trim().into(),
            contacts: vec![PersistedContact {
                id:           "bob-key".into(),
                name:         "Bob".into(),
                last_seen_ts: 1_000,
                online:       false,
            }],
            messages: {
                let mut m = HashMap::new();
                m.insert("bob-key".into(), vec![PersistedMessage {
                    id:           "msg-1".into(),
                    contact_id:   "bob-key".into(),
                    outbound:     true,
                    content_type: "text".into(),
                    text:         "hello".into(),
                    ..Default::default()
                }]);
                m
            },
            settings: {
                let mut s = HashMap::new();
                s.insert("theme".into(), "dark".into());
                s
            },
            next_id:       3,
            created_at:    1_000,
            last_modified: 2_000,
        }
    }

    #[test]
    fn roundtrip_correct_phrase() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("user_data.enc");
        let params = StoreParams::fast();
        let data = test_data();

        save(&path, "correct phrase", &data, &params).unwrap();
        assert!(file_exists(&path));

        let loaded = load(&path, "correct phrase", &params).unwrap();
        assert_eq!(loaded.display_name,   data.display_name);
        assert_eq!(loaded.public_key_hex, data.public_key_hex);
        assert_eq!(loaded.contacts.len(), 1);
        assert_eq!(loaded.contacts[0].name, "Bob");
        assert_eq!(loaded.messages["bob-key"][0].text, "hello");
        assert_eq!(loaded.settings["theme"], "dark");
        assert_eq!(loaded.next_id, 3);
    }

    #[test]
    fn wrong_phrase_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("user_data.enc");
        let params = StoreParams::fast();

        save(&path, "right phrase", &test_data(), &params).unwrap();
        let result = load(&path, "wrong phrase", &params);
        assert!(
            matches!(result, Err(StoreError::DecryptionFailed)),
            "Expected DecryptionFailed, got: {result:?}"
        );
    }

    #[test]
    fn salt_reused_on_second_save() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("user_data.enc");
        let params = StoreParams::fast();

        save(&path, "phrase", &test_data(), &params).unwrap();
        let salt1: Vec<u8> = fs::read(&path).unwrap()[4..20].to_vec();

        let mut data2 = test_data();
        data2.display_name = "Updated".into();
        save(&path, "phrase", &data2, &params).unwrap();
        let salt2: Vec<u8> = fs::read(&path).unwrap()[4..20].to_vec();

        assert_eq!(salt1, salt2, "salt must be stable across saves");
    }

    #[test]
    fn truncated_file_is_invalid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("user_data.enc");
        fs::write(&path, b"TDMN\x00\x01").unwrap();
        let result = load(&path, "any", &StoreParams::fast());
        assert!(matches!(result, Err(StoreError::InvalidFile)));
    }

    #[test]
    fn bad_magic_is_invalid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("user_data.enc");
        let mut garbage = vec![0u8; 64];
        garbage[..4].copy_from_slice(b"NOPE");
        fs::write(&path, &garbage).unwrap();
        let result = load(&path, "any", &StoreParams::fast());
        assert!(matches!(result, Err(StoreError::InvalidFile)));
    }
}
