//! Encryption utilities for secure data storage.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::RngCore;

/// Encrypt data with AES-256-GCM using a 32-byte key.
pub fn encrypt_with_key(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, String> {
    // Generate random nonce
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    // Create cipher
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| format!("Failed to create cipher: {e}"))?;

    // Encrypt
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|e| format!("Encryption failed: {e}"))?;

    // Return nonce || ciphertext
    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt data with AES-256-GCM using a 32-byte key.
pub fn decrypt_with_key(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < 12 {
        return Err("Data too short".into());
    }

    let nonce = &data[..12];
    let ciphertext = &data[12..];

    // Create cipher
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| format!("Failed to create cipher: {e}"))?;

    // Decrypt
    let nonce = Nonce::from_slice(nonce);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("Decryption failed: {e}"))?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_roundtrip() {
        let key = [0x42u8; 32];
        let data = b"Hello, this is a secret message!";

        let encrypted = encrypt_with_key(&key, data).unwrap();
        let decrypted = decrypt_with_key(&key, &encrypted).unwrap();

        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_encryption_wrong_key() {
        let key1 = [0x42u8; 32];
        let key2 = [0x43u8; 32];
        let data = b"Secret data";

        let encrypted = encrypt_with_key(&key1, data).unwrap();
        let result = decrypt_with_key(&key2, &encrypted);

        assert!(result.is_err());
    }
}
