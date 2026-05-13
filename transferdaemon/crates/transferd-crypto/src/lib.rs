pub mod epochs;
pub mod handshake;

#[cfg(target_arch = "x86_64")]
pub mod fused_x86;
#[cfg(target_arch = "aarch64")]
pub mod fused_aarch64;

#[cfg(target_arch = "x86_64")]
pub use fused_x86::{DecryptError, DmiDecryptor, DmiEncryptor, EncryptResult};
#[cfg(target_arch = "aarch64")]
pub use fused_aarch64::{DecryptError, DmiDecryptor, DmiEncryptor, EncryptResult};

pub use handshake::SessionKey;

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("TransferDaemon requires x86_64 or aarch64");
