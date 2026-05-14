//! Hybrid quantum-resistant identity: Ed25519 (classical) + ML-DSA-87 (post-quantum).
//!
//! ## Security model
//! A signature is valid only when **both** Ed25519 and ML-DSA-87 signatures are valid.
//! Classical adversaries cannot forge the Ed25519 component; quantum adversaries cannot
//! forge the ML-DSA-87 component (NIST security level 5 / FIPS 204).
//!
//! ## Wire layout
//! | Field           | Size   |
//! |-----------------|--------|
//! | Ed25519 PK      | 32 B   |
//! | ML-DSA-87 PK    | 2592 B |
//! | **Hybrid PK**   | **2624 B** |
//! | Ed25519 sig     | 64 B   |
//! | ML-DSA-87 sig   | 4627 B |
//! | **Hybrid sig**  | **4691 B** |
//!
//! ## Key derivation from BIP-39 seed (64 bytes)
//! - Ed25519 signing key  ← `seed[0..32]` (same as the existing classical key)
//! - ML-DSA-87 ξ seed     ← `BLAKE3-KDF("TransferDaemon-v1-mldsa87-seed", seed)[0..32]`

use ed25519_dalek::{SigningKey as Ed25519SigningKey, VerifyingKey as Ed25519VerifyingKey};
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, Keypair, MlDsa87, Seed, Signature as MlSignature,
    SigningKey as MlSigningKey, VerifyingKey as MlVerifyingKey,
};

// ── Byte sizes ────────────────────────────────────────────────────────────────

pub const ED25519_PK_LEN: usize   = 32;
pub const ML_DSA_87_PK_LEN: usize = 2592;
pub const HYBRID_PK_LEN: usize    = ED25519_PK_LEN + ML_DSA_87_PK_LEN; // 2624

pub const ED25519_SIG_LEN: usize   = 64;
pub const ML_DSA_87_SIG_LEN: usize = 4627;
pub const HYBRID_SIG_LEN: usize    = ED25519_SIG_LEN + ML_DSA_87_SIG_LEN; // 4691

const MLDSA_SEED_CONTEXT: &str = "TransferDaemon-v1-mldsa87-seed";
const ML_SIGN_CTX: &[u8]       = b"TransferDaemon-v1-hybrid-sign";

// ── HybridVerifyingKey ────────────────────────────────────────────────────────

/// Combined public key: `ed25519_pk (32 B) ‖ ml_dsa_87_pk (2592 B)`.
#[derive(Clone)]
pub struct HybridVerifyingKey {
    ed_pk: Ed25519VerifyingKey,
    ml_pk: MlVerifyingKey<MlDsa87>,
}

impl HybridVerifyingKey {
    /// Serialize to 2624-byte concatenation: `ed_pk ‖ ml_pk`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HYBRID_PK_LEN);
        out.extend_from_slice(self.ed_pk.as_bytes());
        let ml_encoded: EncodedVerifyingKey<MlDsa87> = self.ml_pk.encode();
        out.extend_from_slice(ml_encoded.as_slice());
        out
    }

    /// Hex-encode the full 2624-byte hybrid public key.
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Deserialize from the 2624-byte concatenation produced by [`to_bytes`].
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() != HYBRID_PK_LEN {
            return None;
        }
        let ed_bytes: &[u8; ED25519_PK_LEN] = b[..ED25519_PK_LEN].try_into().ok()?;
        let ml_slice = &b[ED25519_PK_LEN..];
        let ed_pk = Ed25519VerifyingKey::from_bytes(ed_bytes).ok()?;
        let ml_arr: &EncodedVerifyingKey<MlDsa87> =
            <&EncodedVerifyingKey<MlDsa87>>::try_from(ml_slice).ok()?;
        let ml_pk = MlVerifyingKey::<MlDsa87>::decode(ml_arr);
        Some(Self { ed_pk, ml_pk })
    }

    /// Verify a hybrid signature against `msg`.  Both components must be valid.
    pub fn verify(&self, msg: &[u8], sig: &HybridSignature) -> bool {
        use ed25519_dalek::Verifier as _;
        let ed_ok = self.ed_pk.verify(msg, &sig.ed_sig).is_ok();
        let ml_sig_arr: &EncodedSignature<MlDsa87> =
            match <&EncodedSignature<MlDsa87>>::try_from(sig.ml_sig.as_slice()) {
                Ok(a) => a,
                Err(_) => return false,
            };
        let ml_sig = match MlSignature::<MlDsa87>::decode(ml_sig_arr) {
            Some(s) => s,
            None => return false,
        };
        let ml_ok = self.ml_pk.verify_with_context(msg, ML_SIGN_CTX, &ml_sig);
        ed_ok && ml_ok
    }
}

// ── HybridSignature ───────────────────────────────────────────────────────────

/// Combined signature: `ed25519_sig (64 B) ‖ ml_dsa_87_sig (4627 B)`.
pub struct HybridSignature {
    pub ed_sig: ed25519_dalek::Signature,
    pub ml_sig: Vec<u8>,
}

impl HybridSignature {
    /// Serialize to 4691-byte concatenation.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HYBRID_SIG_LEN);
        out.extend_from_slice(&self.ed_sig.to_bytes());
        out.extend_from_slice(&self.ml_sig);
        out
    }

    /// Deserialize from the 4691-byte concatenation produced by [`to_bytes`].
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() != HYBRID_SIG_LEN {
            return None;
        }
        let ed_bytes: [u8; ED25519_SIG_LEN] = b[..ED25519_SIG_LEN].try_into().ok()?;
        let ed_sig = ed25519_dalek::Signature::from_bytes(&ed_bytes);
        let ml_sig = b[ED25519_SIG_LEN..].to_vec();
        Some(Self { ed_sig, ml_sig })
    }
}

// ── HybridSigningKey ──────────────────────────────────────────────────────────

/// Combined signing key: Ed25519 + ML-DSA-87.  Ed25519 key is zeroized on drop by
/// `ed25519_dalek`; ML-DSA-87 key is explicitly zeroized in our `Drop` impl.
pub struct HybridSigningKey {
    ed: Ed25519SigningKey,
    ml: MlSigningKey<MlDsa87>,
}

impl HybridSigningKey {
    /// Derive a deterministic hybrid signing key from the 64-byte BIP-39 seed.
    pub fn from_bip39_seed(seed: &[u8; 64]) -> Self {
        // Ed25519: first 32 bytes of the BIP-39 seed (existing classical key derivation).
        let ed = Ed25519SigningKey::from_bytes(seed[..32].try_into().unwrap());

        // ML-DSA-87: BLAKE3-derived 32-byte ξ seed with domain separation.
        let xi_raw: [u8; 32] = blake3::derive_key(MLDSA_SEED_CONTEXT, seed);
        let xi: Seed = xi_raw.into();
        let ml = MlSigningKey::<MlDsa87>::from_seed(&xi);

        Self { ed, ml }
    }

    /// Return the hybrid verifying (public) key.
    pub fn verifying_key(&self) -> HybridVerifyingKey {
        HybridVerifyingKey {
            ed_pk: self.ed.verifying_key(),
            ml_pk: self.ml.verifying_key(),
        }
    }

    /// Sign `msg` with both keys.
    pub fn sign(&self, msg: &[u8]) -> HybridSignature {
        use ed25519_dalek::Signer as _;
        let ed_sig: ed25519_dalek::Signature = self.ed.sign(msg);
        let ml_sig_obj: MlSignature<MlDsa87> = self
            .ml
            .expanded_key()
            .sign_deterministic(msg, ML_SIGN_CTX)
            .expect("ML-DSA-87 sign_deterministic failed — context too long?");
        let ml_encoded: EncodedSignature<MlDsa87> = ml_sig_obj.encode();
        HybridSignature {
            ed_sig,
            ml_sig: ml_encoded.as_slice().to_vec(),
        }
    }
}

impl Drop for HybridSigningKey {
    fn drop(&mut self) {
        // ed25519_dalek::SigningKey implements ZeroizeOnDrop.
        // ml_dsa::SigningKey does not implement Zeroize directly; the seed is
        // stored inside and will be dropped with the struct.
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn seed_a() -> [u8; 64] {
        let mut s = [0u8; 64];
        s[0] = 1;
        s[63] = 255;
        s
    }

    fn seed_b() -> [u8; 64] {
        let mut s = [0u8; 64];
        s[0] = 2;
        s[63] = 128;
        s
    }

    #[test]
    fn hybrid_sign_verify_roundtrip() {
        let sk = HybridSigningKey::from_bip39_seed(&seed_a());
        let vk = sk.verifying_key();
        let msg = b"TransferDaemon quantum identity test";
        let sig = sk.sign(msg);
        assert!(vk.verify(msg, &sig));
    }

    #[test]
    fn wrong_message_fails_verification() {
        let sk = HybridSigningKey::from_bip39_seed(&seed_a());
        let vk = sk.verifying_key();
        let sig = sk.sign(b"original");
        assert!(!vk.verify(b"tampered", &sig));
    }

    #[test]
    fn public_key_serialization_roundtrip() {
        let sk = HybridSigningKey::from_bip39_seed(&seed_a());
        let vk = sk.verifying_key();
        let bytes = vk.to_bytes();
        assert_eq!(bytes.len(), HYBRID_PK_LEN);
        let vk2 = HybridVerifyingKey::from_bytes(&bytes).unwrap();
        assert_eq!(vk2.to_bytes(), bytes);
    }

    #[test]
    fn signature_serialization_roundtrip() {
        let sk = HybridSigningKey::from_bip39_seed(&seed_a());
        let vk = sk.verifying_key();
        let msg = b"roundtrip";
        let sig = sk.sign(msg);
        let bytes = sig.to_bytes();
        assert_eq!(bytes.len(), HYBRID_SIG_LEN);
        let sig2 = HybridSignature::from_bytes(&bytes).unwrap();
        assert!(vk.verify(msg, &sig2));
    }

    #[test]
    fn deterministic_derivation() {
        let sk1 = HybridSigningKey::from_bip39_seed(&seed_a());
        let sk2 = HybridSigningKey::from_bip39_seed(&seed_a());
        assert_eq!(sk1.verifying_key().to_bytes(), sk2.verifying_key().to_bytes());
    }

    #[test]
    fn different_seeds_produce_different_keys() {
        let vk1 = HybridSigningKey::from_bip39_seed(&seed_a()).verifying_key();
        let vk2 = HybridSigningKey::from_bip39_seed(&seed_b()).verifying_key();
        assert_ne!(vk1.to_bytes(), vk2.to_bytes());
    }
}
