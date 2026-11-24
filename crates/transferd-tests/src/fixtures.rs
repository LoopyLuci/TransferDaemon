//! Test data generators for TransferDaemon integration tests.
//!
//! `TestFixture` provides deterministic test data for identities, contacts,
//! messages, file transfers, and calls.

/// Deterministic test data generator.
pub struct TestFixture;

impl TestFixture {
    /// Create a display name for a test user.
    pub fn display_name(id: u8) -> String {
        format!("TestUser-{id}")
    }

    /// Create a dummy 64-char hex public key.
    pub fn public_key(seed: u8) -> String {
        format!("{:016x}", seed).repeat(4)
    }

    /// Create a dummy recovery phrase (12 BIP-39 words).
    pub fn recovery_phrase() -> String {
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".into()
    }
}
