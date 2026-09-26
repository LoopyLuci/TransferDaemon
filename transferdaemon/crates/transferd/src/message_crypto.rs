//! Message encryption/decryption using AES-256-GCM.
//!
//! This module provides simple message encryption for TCP transport.
//!
//! ## Security Note
//!
//! Messages are padded to power-of-two sizes before encryption to prevent
//! size-based traffic analysis. This follows the design decision in CONTEXT.md
//! section 5: "Message size is padded to power-of-two before encryption."

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::RngCore;

/// Pad a message to the next power-of-two size with length header.
///
/// Format: [4 bytes original length (LE)] [padded data]
///
/// This prevents size-based traffic analysis by ensuring that
/// messages of different sizes produce ciphertexts of the same size.
fn pad_to_power_of_two(data: &[u8]) -> Vec<u8> {
    let len = data.len();
    if len == 0 {
        // Minimum size: 4 bytes header + 1 byte data
        let mut padded = vec![0u8; 5];
        padded[0..4].copy_from_slice(&0u32.to_le_bytes());
        return padded;
    }

    // Find next power of two (excluding the 4-byte header)
    let mut power = 1;
    while power < len {
        power *= 2;
    }

    // Ensure minimum size for padding to be effective
    let target_data_len = power.max(32);

    // Total size = 4 bytes header + data + padding
    let total_len = 4 + target_data_len;
    let mut padded = Vec::with_capacity(total_len);

    // Store original length in header
    padded.extend_from_slice(&(len as u32).to_le_bytes());

    // Copy original data
    padded.extend_from_slice(data);

    // Pad with random bytes to prevent size detection
    let padding_len = target_data_len - len;
    let mut padding = vec![0u8; padding_len];
    rand::thread_rng().fill_bytes(&mut padding);
    padded.extend_from_slice(&padding);

    padded
}

/// Remove padding from a decrypted message.
///
/// Reads the original length from the 4-byte header and returns only the
/// original data without padding.
fn remove_padding(data: &[u8]) -> Vec<u8> {
    if data.len() < 4 {
        return data.to_vec();
    }

    // Read original length from header
    let original_len = u32::from_le_bytes(data[0..4].try_into().unwrap_or([0; 4])) as usize;

    // Return only the original data (skip 4-byte header)
    if 4 + original_len <= data.len() {
        data[4..4 + original_len].to_vec()
    } else {
        // Fallback: return all data after header
        data[4..].to_vec()
    }
}

/// Encrypt a message using AES-256-GCM with padding.
///
/// # Arguments
///
/// * `key` - 32-byte AES-256 key
/// * `plaintext` - The data to encrypt
///
/// # Returns
///
/// A tuple of (nonce, ciphertext) where:
/// - nonce: 12-byte random nonce
/// - ciphertext: Encrypted padded data with GCM tag appended
pub fn encrypt_message(key: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    // Pad the message to power-of-two size
    let padded = pad_to_power_of_two(plaintext);

    // Generate random nonce
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    // Create cipher
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| format!("Failed to create cipher: {e}"))?;

    // Encrypt the padded message
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, padded.as_slice())
        .map_err(|e| format!("Encryption failed: {e}"))?;

    Ok((nonce_bytes.to_vec(), ciphertext))
}

/// Decrypt a message using AES-256-GCM.
///
/// # Arguments
///
/// * `key` - 32-byte AES-256 key
/// * `nonce` - 12-byte nonce used during encryption
/// * `ciphertext` - The encrypted data with GCM tag
///
/// # Returns
///
/// The decrypted plaintext (with padding removed), or an error if decryption fails.
pub fn decrypt_message(key: &[u8; 32], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    if nonce.len() != 12 {
        return Err("Invalid nonce length".into());
    }

    // Create cipher
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| format!("Failed to create cipher: {e}"))?;

    // Decrypt
    let nonce = Nonce::from_slice(nonce);
    let padded_plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("Decryption failed (wrong key?): {e}"))?;

    // Remove padding
    Ok(remove_padding(&padded_plaintext))
}

/// Derive a session key from a shared secret.
///
/// # Arguments
///
/// * `shared_secret` - The shared secret from the handshake
///
/// # Returns
///
/// A 32-byte session key.
///
/// # Security Note
///
/// This uses BLAKE3 with domain separation to derive a proper session key.
/// In production, the shared_secret should come from a real X25519 DH exchange,
/// not from public information like the contact_id.
pub fn derive_session_key(shared_secret: &[u8]) -> [u8; 32] {
    use blake3::Hasher;

    let mut hasher = Hasher::new();
    hasher.update(b"TransferDaemon-v1-message-key");
    hasher.update(shared_secret);
    *hasher.finalize().as_bytes()
}

/// Generate a random session key for a new connection.
///
/// This is more secure than deriving from public information.
pub fn generate_session_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_roundtrip() {
        let key = [0x42u8; 32];
        let plaintext = b"Hello, this is a secret message!";

        let (nonce, ciphertext) = encrypt_message(&key, plaintext).unwrap();
        let decrypted = decrypt_message(&key, &nonce, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encryption_wrong_key() {
        let key1 = [0x42u8; 32];
        let key2 = [0x43u8; 32];
        let plaintext = b"Secret data";

        let (nonce, ciphertext) = encrypt_message(&key1, plaintext).unwrap();
        let result = decrypt_message(&key2, &nonce, &ciphertext);

        assert!(result.is_err());
    }

    #[test]
    fn test_encryption_different_ciphertext() {
        let key = [0x42u8; 32];
        let plaintext = b"Same data encrypted twice";

        let (nonce1, ciphertext1) = encrypt_message(&key, plaintext).unwrap();
        let (nonce2, ciphertext2) = encrypt_message(&key, plaintext).unwrap();

        // Different nonces should produce different ciphertext
        assert_ne!(nonce1, nonce2);
        assert_ne!(ciphertext1, ciphertext2);
    }

    #[test]
    fn test_derive_session_key() {
        let secret1 = b"shared secret 1";
        let secret2 = b"shared secret 2";

        let key1 = derive_session_key(secret1);
        let key2 = derive_session_key(secret2);

        // Different secrets should produce different keys
        assert_ne!(key1, key2);
    }
}
