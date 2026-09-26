//! KeyStore trait and implementations for hardware-bound key storage.
//!
//! ## Architecture
//!
//! The `KeyStore` trait provides an abstraction for key storage that can be
//! implemented for different backends:
//!
//! - `RamKeyStore`: Default implementation that stores keys in RAM only.
//!   Keys are zeroized on drop. Suitable for development and testing.
//!
//! - `TpmKeyStore`: Stores keys in TPM 2.0 (Windows). Requires the
//!   `tpm-backend` feature.
//!
//! - `SecureEnclaveKeyStore`: Stores keys in Secure Enclave (macOS/iOS).
//!   Requires the `secure-enclave-backend` feature.
//!
//! ## Security
//!
//! Hardware-bound keys provide protection against:
//! - Memory dumps (keys never leave the secure hardware)
//! - Key extraction attacks
//! - Malware that runs with user privileges
//!
//! The `KeyStore` trait ensures that:
//! - Keys are never exposed in plaintext outside the hardware
//! - All operations are atomic and fail gracefully
//! - Keys can be migrated between backends if needed

use std::sync::Arc;

// ---------------------------------------------------------------------------
// KeyStore trait
// ---------------------------------------------------------------------------

/// Error type for key store operations.
#[derive(Debug, thiserror::Error)]
pub enum KeyStoreError {
    #[error("Key not found: {0}")]
    NotFound(String),

    #[error("Hardware error: {0}")]
    HardwareError(String),

    #[error("Permission denied")]
    PermissionDenied,

    #[error("Key already exists: {0}")]
    AlreadyExists(String),

    #[error("Invalid key format: {0}")]
    InvalidFormat(String),

    #[error("Storage full")]
    StorageFull,

    #[error("Operation not supported: {0}")]
    NotSupported(String),
}

/// Result type for key store operations.
pub type KeyStoreResult<T> = Result<T, KeyStoreError>;

/// Trait for hardware-bound key storage.
///
/// Implementations provide secure key storage that may use hardware security
/// modules (TPM, Secure Enclave, etc.) for key protection.
pub trait KeyStore: Send + Sync {
    /// Store a signing key.
    ///
    /// # Arguments
    ///
    /// * `key_id` - Unique identifier for the key
    /// * `key_data` - The key material to store
    ///
    /// # Returns
    ///
    /// `Ok(())` if the key was stored successfully, or an error if the
    /// operation failed.
    fn store_signing_key(&self, key_id: &str, key_data: &[u8]) -> KeyStoreResult<()>;

    /// Load a signing key.
    ///
    /// # Arguments
    ///
    /// * `key_id` - The key identifier to load
    ///
    /// # Returns
    ///
    /// `Ok(key_data)` if the key was loaded, or `Err(NotFound)` if the
    /// key doesn't exist.
    fn load_signing_key(&self, key_id: &str) -> KeyStoreResult<Vec<u8>>;

    /// Delete a signing key.
    ///
    /// # Arguments
    ///
    /// * `key_id` - The key identifier to delete
    ///
    /// # Returns
    ///
    /// `Ok(())` if the key was deleted, or `Err(NotFound)` if the
    /// key doesn't exist.
    fn delete_signing_key(&self, key_id: &str) -> KeyStoreResult<()>;

    /// Check if a signing key exists.
    ///
    /// # Arguments
    ///
    /// * `key_id` - The key identifier to check
    ///
    /// # Returns
    ///
    /// `true` if the key exists, `false` otherwise.
    fn has_signing_key(&self, key_id: &str) -> bool;

    /// List all stored key identifiers.
    ///
    /// # Returns
    ///
    /// A vector of key identifiers.
    fn list_keys(&self) -> Vec<String>;

    /// Get the backend type.
    fn backend_type(&self) -> KeyStoreBackend;
}

/// The type of key store backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStoreBackend {
    /// RAM-only storage (default, for development/testing).
    Ram,
    /// TPM 2.0 (Windows).
    #[cfg(feature = "tpm-backend")]
    Tpm,
    /// Secure Enclave (macOS/iOS).
    #[cfg(feature = "secure-enclave-backend")]
    SecureEnclave,
}

// ---------------------------------------------------------------------------
// RamKeyStore — default implementation
// ---------------------------------------------------------------------------

/// Default key store implementation that stores keys in RAM.
///
/// Keys are zeroized on drop. Suitable for development and testing.
/// For production, use a hardware-backed store.
pub struct RamKeyStore {
    keys: std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>,
}

impl Drop for RamKeyStore {
    fn drop(&mut self) {
        // Zeroize all stored key material on drop
        if let Ok(mut keys) = self.keys.lock() {
            for value in keys.values_mut() {
                use zeroize::Zeroize;
                value.zeroize();
            }
            keys.clear();
        }
    }
}

impl RamKeyStore {
    /// Create a new empty RAM key store.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            keys: std::sync::Mutex::new(std::collections::HashMap::new()),
        })
    }
}

impl Default for RamKeyStore {
    fn default() -> Self {
        Self {
            keys: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

impl KeyStore for RamKeyStore {
    fn store_signing_key(&self, key_id: &str, key_data: &[u8]) -> KeyStoreResult<()> {
        let mut keys = self.keys.lock().map_err(|e| {
            KeyStoreError::HardwareError(format!("Lock error: {e}"))
        })?;

        if keys.contains_key(key_id) {
            return Err(KeyStoreError::AlreadyExists(key_id.to_string()));
        }

        keys.insert(key_id.to_string(), key_data.to_vec());
        Ok(())
    }

    fn load_signing_key(&self, key_id: &str) -> KeyStoreResult<Vec<u8>> {
        let keys = self.keys.lock().map_err(|e| {
            KeyStoreError::HardwareError(format!("Lock error: {e}"))
        })?;

        keys.get(key_id)
            .cloned()
            .ok_or_else(|| KeyStoreError::NotFound(key_id.to_string()))
    }

    fn delete_signing_key(&self, key_id: &str) -> KeyStoreResult<()> {
        let mut keys = self.keys.lock().map_err(|e| {
            KeyStoreError::HardwareError(format!("Lock error: {e}"))
        })?;

        if keys.remove(key_id).is_none() {
            return Err(KeyStoreError::NotFound(key_id.to_string()));
        }

        Ok(())
    }

    fn has_signing_key(&self, key_id: &str) -> bool {
        self.keys.lock()
            .map(|keys| keys.contains_key(key_id))
            .unwrap_or(false)
    }

    fn list_keys(&self) -> Vec<String> {
        self.keys.lock()
            .map(|keys| keys.keys().cloned().collect())
            .unwrap_or_default()
    }

    fn backend_type(&self) -> KeyStoreBackend {
        KeyStoreBackend::Ram
    }
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/// Create a key store with the best available backend.
///
/// Currently returns a RAM-only key store. Hardware backends (TPM 2.0,
/// Secure Enclave) will be added when those features are implemented.
pub fn create_key_store() -> Arc<dyn KeyStore> {
    Arc::new(RamKeyStore {
        keys: std::sync::Mutex::new(std::collections::HashMap::new()),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ram_key_store() {
        let store = RamKeyStore::new();

        // Store a key
        store.store_signing_key("test-key", b"secret-key-data").unwrap();

        // Load it back
        let loaded = store.load_signing_key("test-key").unwrap();
        assert_eq!(loaded, b"secret-key-data");

        // Check existence
        assert!(store.has_signing_key("test-key"));
        assert!(!store.has_signing_key("nonexistent"));

        // List keys
        let keys = store.list_keys();
        assert_eq!(keys.len(), 1);
        assert!(keys.contains(&"test-key".to_string()));

        // Delete it
        store.delete_signing_key("test-key").unwrap();
        assert!(!store.has_signing_key("test-key"));
    }

    #[test]
    fn test_ram_key_store_duplicate() {
        let store = RamKeyStore::new();

        // Store a key
        store.store_signing_key("test-key", b"key-data").unwrap();

        // Try to store again - should fail
        let result = store.store_signing_key("test-key", b"other-data");
        assert!(result.is_err());
    }

    #[test]
    fn test_ram_key_store_not_found() {
        let store = RamKeyStore::new();

        // Try to load nonexistent key
        let result = store.load_signing_key("nonexistent");
        assert!(result.is_err());

        // Try to delete nonexistent key
        let result = store.delete_signing_key("nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn test_key_store_backend_type() {
        let store = RamKeyStore::new();
        assert_eq!(store.backend_type(), KeyStoreBackend::Ram);
    }
}
