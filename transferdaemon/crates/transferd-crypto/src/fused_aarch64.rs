//! Fused BLAKE3 + AES-256-GCM for aarch64 (ARMv8 Crypto Extensions selected at runtime).
//! Same API as `fused_x86`; NT-store path omitted (ARM uses write-combining differently).

use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes256Gcm, Key, Nonce, Tag,
};
use blake3::Hasher;
use zeroize::Zeroizing;

pub use crate::common::{DecryptError, EncryptResult};

pub struct DmiEncryptor {
    cipher: Aes256Gcm,
    /// Retained only so the key is zeroized on drop (never read otherwise).
    #[allow(dead_code)]
    key_bytes: Zeroizing<[u8; 32]>,
    hasher: Hasher,
}

impl DmiEncryptor {
    pub fn new(key: &[u8; 32]) -> Self {
        let aes_key = Key::<Aes256Gcm>::from_slice(key);
        let mut key_bytes = Zeroizing::new([0u8; 32]);
        key_bytes.copy_from_slice(key);
        Self { cipher: Aes256Gcm::new(aes_key), key_bytes, hasher: Hasher::new() }
    }

    pub fn nonce_for(gsn: u64, epoch: u8) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..8].copy_from_slice(&gsn.to_le_bytes());
        n[8] = epoch;
        n
    }

    /// Encrypt in-place and return the GCM tag. Matches the fused_x86 API used by transport lanes.
    pub fn encrypt_detached(
        &self,
        buf: &mut Vec<u8>,
        nonce: &[u8; 12],
        aad: &[u8],
    ) -> Result<[u8; 16], DecryptError> {
        use aes_gcm::aead::AeadInPlace;
        let nonce = Nonce::from_slice(nonce);
        let tag = self.cipher.encrypt_in_place_detached(nonce, aad, buf)
            .map_err(|_| DecryptError::AuthFailed)?;
        Ok(tag.into())
    }

    pub unsafe fn encrypt_fused(
        &mut self,
        plaintext: &[u8],
        dst: &mut [u8],
        gsn: u64,
        epoch: u8,
        aad: &[u8],
    ) -> EncryptResult {
        assert_eq!(plaintext.len(), dst.len());
        self.hasher.reset();
        let nonce_bytes = Self::nonce_for(gsn, epoch);
        let nonce = Nonce::from_slice(&nonce_bytes);
        dst.copy_from_slice(plaintext);
        self.hasher.update(plaintext);
        let blake3_hash = *self.hasher.finalize().as_bytes();
        let tag = self.cipher.encrypt_in_place_detached(nonce, aad, dst)
            .expect("AES-GCM encrypt");
        EncryptResult { blake3_hash, gcm_tag: tag.into(), nonce: nonce_bytes }
    }
}

pub struct DmiDecryptor {
    cipher: Aes256Gcm,
}

impl DmiDecryptor {
    pub fn new(key: &[u8; 32]) -> Self {
        let aes_key = Key::<Aes256Gcm>::from_slice(key);
        Self { cipher: Aes256Gcm::new(aes_key) }
    }

    pub fn decrypt_verify(
        &self,
        buf: &mut [u8],
        nonce: &[u8; 12],
        tag: &[u8; 16],
        aad: &[u8],
    ) -> Result<[u8; 32], DecryptError> {
        let nonce = Nonce::from_slice(nonce);
        let tag = Tag::from_slice(tag);
        self.cipher.decrypt_in_place_detached(nonce, aad, buf, tag)
            .map_err(|_| DecryptError::AuthFailed)?;
        Ok(*blake3::hash(buf).as_bytes())
    }
}
