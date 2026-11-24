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

/// Current UTC `(year, month)` — used by the ciphersuite registry to decide
/// whether a suite has been sunset. `chrono` is avoided to keep the crypto
/// crate dependency-light.
pub fn now_ym() -> (u16, u8) {
    #[cfg(target_arch = "wasm32")]
    {
        (2030, 1)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        use std::time::{SystemTime, UNIX_EPOCH};
        let secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        // Days since 1970-01-01, then civil-from-days (Hinnant's algorithm).
        let days = (secs / 86400) as i64;
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z.rem_euclid(146_097);
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let _d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let year = if m <= 2 { y + 1 } else { y };
        (year as u16, m as u8)
    }
}
