pub mod common;
pub mod epochs;
pub mod handshake;
pub mod identity;

#[cfg(target_arch = "x86_64")]
pub mod fused_x86;
#[cfg(target_arch = "aarch64")]
pub mod fused_aarch64;

// Portable software fallback for armv7, x86 (32-bit), WASM, and any other target.
// Uses the same aes-gcm + blake3 crates as the optimised paths; the difference is
// that SIMD and NT-store acceleration are not available.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub mod fused_portable;

#[cfg(target_arch = "x86_64")]
pub use fused_x86::{DecryptError, DmiDecryptor, DmiEncryptor, EncryptResult};
#[cfg(target_arch = "aarch64")]
pub use fused_aarch64::{DecryptError, DmiDecryptor, DmiEncryptor, EncryptResult};
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub use fused_portable::{DecryptError, DmiDecryptor, DmiEncryptor, EncryptResult};

pub use handshake::SessionKey;
pub use identity::{HybridSigningKey, HybridVerifyingKey, HybridSignature, HYBRID_PK_LEN, HYBRID_SIG_LEN};
