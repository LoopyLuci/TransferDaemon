//! Hybrid post-quantum handshake: X25519 (classical) + ML-KEM-768 (post-quantum).
//!
//! Security model: the session key is secure as long as **either** X25519 **or**
//! ML-KEM-768 remains unbroken. A quantum adversary would break X25519 but not
//! ML-KEM-768; a classical adversary vice-versa.
//!
//! Protocol (2-message, forward-secret):
//!
//!   Initiator                                  Responder
//!   ---------                                  ---------
//!   gen x25519 ephemeral (isk, ipk)
//!   gen ML-KEM-768 keypair (idk, iek)
//!   ──── InitiatorHello { ipk, iek } ────►
//!                                              gen x25519 ephemeral (rsk, rpk)
//!                                              x_ss = DH(rsk, ipk)
//!                                              (ct, kem_ss) = Encap(iek)
//!                                              key = KDF(x_ss ‖ kem_ss)
//!                                              ◄──── ResponderHello { rpk, ct } ────
//!   x_ss = DH(isk, rpk)
//!   kem_ss = Decap(idk, ct)
//!   key = KDF(x_ss ‖ kem_ss)
//!
//! KDF: `blake3::derive_key` with domain context = "TransferDaemon-v1-hybrid-session-key".
//!
//! ## rand_core version note
//! `ml-kem 0.3` requires `rand_core 0.10`; `x25519-dalek 2` requires `rand_core 0.6`.
//! To avoid the conflict we bypass both RNG traits entirely: we generate raw bytes with
//! `rand 0.8` and construct ml-kem's `Seed` / `B32` via their `From<[u8; N]>` impls,
//! then call the deterministic seed-based / `encapsulate_deterministic` APIs.

use ml_kem::{
    B32, Decapsulate, Seed,
    ml_kem_768::{Ciphertext as MlCt768, DecapsulationKey as MlDk768, EncapsulationKey as MlEk768},
};
use rand::RngCore;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const KDF_CONTEXT: &str = "TransferDaemon-v1-hybrid-session-key";

// ---------------------------------------------------------------------------
// SessionKey
// ---------------------------------------------------------------------------

/// 32-byte symmetric session key produced by a successful handshake. Zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SessionKey(pub [u8; 32]);

impl SessionKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// Wire messages (in production: serialised over the control channel)
// ---------------------------------------------------------------------------

/// First flight: Initiator → Responder.
#[derive(Clone)]
pub struct InitiatorHello {
    pub x25519_pk: X25519PublicKey,
    /// ML-KEM-768 encapsulation key (1184 bytes on the wire).
    pub kem_ek: MlEk768,
}

/// Second flight: Responder → Initiator.
#[derive(Clone)]
pub struct ResponderHello {
    pub x25519_pk: X25519PublicKey,
    /// ML-KEM-768 ciphertext produced by Encap(iek).
    pub kem_ct: MlCt768,
}

impl InitiatorHello {
    /// Serialize to wire bytes: `[x25519_pk: 32][kem_ek: 1184]`.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 1184);
        out.extend_from_slice(self.x25519_pk.as_bytes());
        let ek = <MlEk768 as kem::KeyExport>::to_bytes(&self.kem_ek);
        out.extend_from_slice(ek.as_ref());
        out
    }

    /// Deserialize from [`Self::to_wire`] output (must be exactly 1216 bytes).
    pub fn from_wire(data: &[u8]) -> Option<Self> {
        if data.len() != 32 + 1184 {
            return None;
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&data[..32]);
        let ek_key: kem::Key<MlEk768> = data[32..].try_into().ok()?;
        let kem_ek = <MlEk768 as kem::TryKeyInit>::new(&ek_key).ok()?;
        Some(Self {
            x25519_pk: X25519PublicKey::from(pk),
            kem_ek,
        })
    }
}

impl ResponderHello {
    /// Serialize to wire bytes: `[x25519_pk: 32][kem_ct: 1088]`.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 1088);
        out.extend_from_slice(self.x25519_pk.as_bytes());
        out.extend_from_slice(self.kem_ct.as_ref());
        out
    }

    /// Deserialize from [`Self::to_wire`] output (must be exactly 1120 bytes).
    pub fn from_wire(data: &[u8]) -> Option<Self> {
        if data.len() != 32 + 1088 {
            return None;
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&data[..32]);
        let kem_ct: MlCt768 = data[32..].try_into().ok()?;
        Some(Self {
            x25519_pk: X25519PublicKey::from(pk),
            kem_ct,
        })
    }
}

// ---------------------------------------------------------------------------
// Initiator
// ---------------------------------------------------------------------------

pub struct Initiator {
    x25519_sk: EphemeralSecret,
    kem_dk: MlDk768,
    kem_ek: MlEk768,
}

impl Initiator {
    /// Generates all ephemeral key material for the initiator role.
    pub fn new() -> Self {
        // X25519: rand_core 0.6 OsRng via rand 0.8.
        let x25519_sk = EphemeralSecret::random_from_rng(rand::rngs::OsRng);

        // ML-KEM-768: generate a random 64-byte seed using rand 0.8, then use the
        // seed-based API to avoid the rand_core 0.10 dependency.
        // gen() only works up to [u8;32]; use fill_bytes for larger arrays.
        let mut raw_seed = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut raw_seed);
        let seed: Seed = raw_seed.into(); // Seed = Array<u8, U64>, From<[u8;64]> implemented
        let dk = MlDk768::from_seed(seed);
        let ek = dk.encapsulation_key().clone();

        Self { x25519_sk, kem_dk: dk, kem_ek: ek }
    }

    /// Borrows the initiator to produce the first flight.
    pub fn hello(&self) -> InitiatorHello {
        InitiatorHello {
            x25519_pk: X25519PublicKey::from(&self.x25519_sk),
            kem_ek: self.kem_ek.clone(),
        }
    }

    /// Consumes the initiator and derives the session key from the responder's reply.
    pub fn finalize(self, resp: ResponderHello) -> SessionKey {
        let x_ss = self.x25519_sk.diffie_hellman(&resp.x25519_pk);
        let kem_ss = self.kem_dk.decapsulate(&resp.kem_ct);
        hybrid_kdf(x_ss.as_bytes(), kem_ss.as_ref())
    }
}

impl Default for Initiator {
    fn default() -> Self { Self::new() }
}

// ---------------------------------------------------------------------------
// Responder
// ---------------------------------------------------------------------------

pub struct Responder {
    x25519_sk: EphemeralSecret,
}

impl Responder {
    pub fn new() -> Self {
        Self { x25519_sk: EphemeralSecret::random_from_rng(rand::rngs::OsRng) }
    }

    /// Processes the initiator's hello. Returns the responder's hello and the session key.
    pub fn respond(self, hello: &InitiatorHello) -> (ResponderHello, SessionKey) {
        // Compute public key BEFORE consuming EphemeralSecret via diffie_hellman.
        let rpk = X25519PublicKey::from(&self.x25519_sk);
        let x_ss = self.x25519_sk.diffie_hellman(&hello.x25519_pk);

        // ML-KEM-768 encapsulation using a fresh 32-byte random message `m`.
        // `encapsulate_deterministic` is the public (doc-hidden) API accepting B32.
        // Safe as long as `m` has full 256-bit entropy from the OS CSPRNG.
        let mut raw_m = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut raw_m);
        let m: B32 = raw_m.into();
        let (kem_ct, kem_ss) = hello.kem_ek.encapsulate_deterministic(&m);

        let key = hybrid_kdf(x_ss.as_bytes(), kem_ss.as_ref());
        let resp = ResponderHello { x25519_pk: rpk, kem_ct };
        (resp, key)
    }
}

impl Default for Responder {
    fn default() -> Self { Self::new() }
}

// ---------------------------------------------------------------------------
// KDF
// ---------------------------------------------------------------------------

/// BLAKE3 `derive_key` KDF combining both shared secrets.
///
/// Input material: `x25519_ss ‖ kem_ss` (64 bytes total for ML-KEM-768).
/// `blake3::derive_key` internally hashes the context string to a 256-bit key, then
/// applies keyed BLAKE3 over the input — equivalent to HKDF-Extract + HKDF-Expand.
fn hybrid_kdf(x25519_ss: &[u8], kem_ss: &[u8]) -> SessionKey {
    let mut input = Zeroizing::new(Vec::with_capacity(x25519_ss.len() + kem_ss.len()));
    input.extend_from_slice(x25519_ss);
    input.extend_from_slice(kem_ss);
    SessionKey(blake3::derive_key(KDF_CONTEXT, &input))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn initiator_hello_wire_roundtrip() {
        let init = Initiator::new();
        let hello = init.hello();
        let wire = hello.to_wire();
        assert_eq!(wire.len(), 32 + 1184);
        let back = InitiatorHello::from_wire(&wire).expect("must deserialize");
        assert_eq!(back.to_wire(), wire);
    }

    #[test]
    fn responder_hello_wire_roundtrip() {
        let init = Initiator::new();
        let hello = init.hello();
        let responder = Responder::new();
        let (resp, _key) = responder.respond(&hello);
        let wire = resp.to_wire();
        assert_eq!(wire.len(), 32 + 1088);
        let back = ResponderHello::from_wire(&wire).expect("must deserialize");
        assert_eq!(back.to_wire(), wire);
    }

    #[test]
    fn wire_handshake_derives_identical_session_key() {
        // Full handshake where every flight travels as serialized bytes.
        let init = Initiator::new();
        let init_hello = init.hello();
        let hello_wire = init_hello.to_wire();
        let hello_back = InitiatorHello::from_wire(&hello_wire).expect("initiator hello");

        let responder = Responder::new();
        let (resp, responder_key) = responder.respond(&hello_back);
        let resp_wire = resp.to_wire();
        let resp_back = ResponderHello::from_wire(&resp_wire).expect("responder hello");

        let initiator_key = init.finalize(resp_back);
        assert_eq!(initiator_key.as_bytes(), responder_key.as_bytes());
        assert_ne!(initiator_key.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        // A corrupted ciphertext must not yield the same key (KEM soundness).
        let init = Initiator::new();
        let hello = init.hello();
        let responder = Responder::new();
        let (resp, key) = responder.respond(&hello);
        let mut bytes = resp.to_wire();
        let idx = bytes.len() - 5;
        bytes[idx] ^= 0xff;
let tampered = ResponderHello::from_wire(&bytes).expect("parses");
        let tampered_key = init.finalize(tampered);
        assert_ne!(tampered_key.as_bytes(), key.as_bytes());
    }
}
