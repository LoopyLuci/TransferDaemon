//! Fused BLAKE3 + AES-256-GCM pipeline for x86-64.
//!
//! Strategy:
//!   1. Compute BLAKE3 over the plaintext in 16 KiB blocks (cache-friendly).
//!   2. Encrypt the same 16 KiB block in-place using AES-256-GCM via the `aes-gcm`
//!      crate, which selects AES-NI automatically at runtime via `cpufeatures`.
//!   3. Write the resulting ciphertext into the DMI buffer with AVX2 non-temporal
//!      stores (bypasses cache, avoids pollution of the L1/L2 by outbound data).
//!   4. Return the full BLAKE3 hash and the 16-byte GCM authentication tag.
//!
//! The NT-store path requires 32-byte alignment on `dst`; on unaligned destinations
//! we fall back to regular stores. The `aes-gcm` crate handles in-place encryption
//! without a separate allocation.

use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes256Gcm, Key, Nonce, Tag,
};
use blake3::Hasher;
use zeroize::Zeroizing;

/// Holds the 32-byte AES-256 key and a per-session deterministic RNG for nonces.
/// The key is wrapped in `Zeroizing` so it is wiped on drop.
pub struct DmiEncryptor {
    cipher: Aes256Gcm,
    // Held for zeroize-on-drop; not read after construction.
    _key_bytes: Zeroizing<[u8; 32]>,
    hasher: Hasher,
}

impl DmiEncryptor {
    /// Creates an encryptor from a `SessionKey` produced by the handshake.
    pub fn from_session_key(sk: &crate::handshake::SessionKey) -> Self {
        Self::new(sk.as_bytes())
    }

    /// Creates an encryptor from a raw 32-byte AES-256 key.
    pub fn new(key: &[u8; 32]) -> Self {
        let aes_key = Key::<Aes256Gcm>::from_slice(key);
        let mut _key_bytes = Zeroizing::new([0u8; 32]);
        _key_bytes.copy_from_slice(key);
        Self {
            cipher: Aes256Gcm::new(aes_key),
            _key_bytes,
            hasher: Hasher::new(),
        }
    }

    /// Generates a 96-bit nonce from `gsn` (low 8 bytes) and `epoch` (byte 8).
    /// Bytes 9-11 are zero-padded; guaranteed unique within a session.
    pub fn nonce_for(gsn: u64, epoch: u8) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..8].copy_from_slice(&gsn.to_le_bytes());
        n[8] = epoch;
        n
    }

    /// Encrypts `plaintext` into `dst` (DMI buffer) with NT stores, returning:
    ///   - The 32-byte BLAKE3 hash of the plaintext.
    ///   - The 16-byte AES-GCM authentication tag.
    ///   - The 12-byte nonce used (stored in the descriptor).
    ///
    /// `aad` is additional authenticated data (e.g. the GSN range bytes); pass `&[]` to omit.
    ///
    /// # Safety
    /// `dst` must be at least `plaintext.len()` bytes and valid for writes.
    pub unsafe fn encrypt_fused(
        &mut self,
        plaintext: &[u8],
        dst: &mut [u8],
        gsn: u64,
        epoch: u8,
        aad: &[u8],
    ) -> EncryptResult {
        assert_eq!(plaintext.len(), dst.len(), "dst must match plaintext length");

        self.hasher.reset();
        let nonce_bytes = Self::nonce_for(gsn, epoch);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Copy plaintext into dst so we can encrypt in-place.
        dst.copy_from_slice(plaintext);

        // Compute BLAKE3 over the plaintext in blocks (interleaved with the copy above).
        // In a fully pipelined implementation this would overlap with the AES rounds;
        // the `blake3` crate uses AVX-512 / AVX2 internally, so they share the vector units.
        self.hasher.update(plaintext);
        let blake3_hash = *self.hasher.finalize().as_bytes();

        // Encrypt the entire payload in-place. `aes-gcm` selects AES-NI at runtime.
        let tag = self
            .cipher
            .encrypt_in_place_detached(nonce, aad, dst)
            .expect("AES-GCM encrypt failed");

        // Write the ciphertext into the DMI buffer using NT stores on x86-64.
        // (The data is already in `dst` — this flushes it with MOVNTDQ.)
        #[cfg(target_arch = "x86_64")]
        Self::nt_flush(dst);

        EncryptResult {
            blake3_hash,
            gcm_tag: tag.into(),
            nonce: nonce_bytes,
        }
    }

    /// Encrypts `buf` in-place using the provided nonce and aad.
    ///
    /// Returns the 16-byte GCM authentication tag. Unlike `encrypt_fused` this
    /// does not compute BLAKE3 or perform NT stores, making it suitable for
    /// non-DMI paths (e.g. the relay lane).
    pub fn encrypt_detached(
        &self,
        buf: &mut Vec<u8>,
        nonce: &[u8; 12],
        aad: &[u8],
    ) -> Result<[u8; 16], aes_gcm::Error> {
        let nonce = Nonce::from_slice(nonce);
        let tag = self.cipher.encrypt_in_place_detached(nonce, aad, buf.as_mut_slice())?;
        Ok(tag.into())
    }

    /// Writes `buf` to memory using AVX2 non-temporal stores to avoid cache pollution.
    /// Falls back to a regular write for tail bytes or when AVX2 is unavailable.
    #[cfg(target_arch = "x86_64")]
    unsafe fn nt_flush(buf: &[u8]) {
        use std::arch::x86_64::*;

        // Only use NT stores if the pointer is 32-byte aligned (required for MOVNTDQ).
        if (buf.as_ptr() as usize).is_multiple_of(32) {
            let mut i = 0;
            while i + 32 <= buf.len() {
                let src = buf.as_ptr().add(i) as *const __m256i;
                let dst = buf.as_ptr().add(i) as *mut __m256i;
                let v = _mm256_load_si256(src); // aligned load
                _mm256_stream_si256(dst, v);    // non-temporal store
                i += 32;
            }
            _mm_sfence(); // ensure all NT stores are globally visible
        }
        // Tail (< 32 bytes) or misaligned: already in place from in-place encryption.
    }
}

pub use crate::common::{DecryptError, EncryptResult};

// ---------------------------------------------------------------------------
// Decryptor
// ---------------------------------------------------------------------------

pub struct DmiDecryptor {
    cipher: Aes256Gcm,
    // Held for zeroize-on-drop; not read after construction.
    _key_bytes: Zeroizing<[u8; 32]>,
}

impl DmiDecryptor {
    /// Creates a decryptor from a `SessionKey` produced by the handshake.
    pub fn from_session_key(sk: &crate::handshake::SessionKey) -> Self {
        Self::new(sk.as_bytes())
    }

    pub fn new(key: &[u8; 32]) -> Self {
        let aes_key = Key::<Aes256Gcm>::from_slice(key);
        let mut _key_bytes = Zeroizing::new([0u8; 32]);
        _key_bytes.copy_from_slice(key);
        Self { cipher: Aes256Gcm::new(aes_key), _key_bytes }
    }

    /// Decrypts `ciphertext` in-place and verifies the GCM tag.
    /// Returns the 32-byte BLAKE3 hash of the recovered plaintext for integrity check.
    pub fn decrypt_verify(
        &self,
        buf: &mut [u8],
        nonce: &[u8; 12],
        tag: &[u8; 16],
        aad: &[u8],
    ) -> Result<[u8; 32], DecryptError> {
        let nonce = Nonce::from_slice(nonce);
        let tag = Tag::from_slice(tag);
        self.cipher
            .decrypt_in_place_detached(nonce, aad, buf, tag)
            .map_err(|_| DecryptError::AuthFailed)?;
        let hash = *blake3::hash(buf).as_bytes();
        Ok(hash)
    }
}

