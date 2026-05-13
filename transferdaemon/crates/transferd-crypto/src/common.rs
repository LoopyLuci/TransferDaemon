//! Types shared between fused_x86 and fused_aarch64.

/// Output of a single `encrypt_fused` call.
#[derive(Debug, Clone)]
pub struct EncryptResult {
    /// BLAKE3 hash of the plaintext (for content-level integrity).
    pub blake3_hash: [u8; 32],
    /// AES-256-GCM authentication tag (16 bytes).
    pub gcm_tag: [u8; 16],
    /// 96-bit nonce used for this chunk.
    pub nonce: [u8; 12],
}

#[derive(Debug, thiserror::Error)]
pub enum DecryptError {
    #[error("GCM authentication tag mismatch — data may be corrupt or tampered")]
    AuthFailed,
}
