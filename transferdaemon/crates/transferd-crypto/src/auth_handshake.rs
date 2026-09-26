//! Authenticated hybrid handshake flights (Protocol v2).
//!
//! Each flight binds the ephemeral key-exchange material (X25519 + ML-KEM-768)
//! to the long-term hybrid identity key (Ed25519 + ML-DSA-87). The signature
//! covers a BLAKE3 transcript that includes every field of the flight, so a
//! man-in-the-middle cannot substitute key material without possessing the
//! peer's identity signing key.
//!
//! Wire layout (self-describing envelope, C8b):
//!
//! ```text
//! AuthInitiatorHello (8568 B):
//!   tag u8 = 0x11
//!   protocol_version u16 LE
//!   ciphersuite u16 LE
//!   x25519_pk  [u8; 32]
//!   kem_ek     [u8; 1184]   (ML-KEM-768 encapsulation key)
//!   identity_pk [u8; 2624]  (ed25519_pk ‖ ml_dsa_87_pk)
//!   transcript [u8; 32]
//!   signature  [u8; 4691]   (ed25519_sig ‖ ml_dsa_87_sig)
//!
//! AuthResponderHello (8472 B):
//!   tag u8 = 0x12
//!   ... same layout, kem_ct [u8; 1088] instead of kem_ek
//! ```

use crate::handshake::{Initiator, InitiatorHello, ResponderHello};
use crate::identity::{HybridSignature, HybridSigningKey, HybridVerifyingKey};

/// Wire protocol version negotiated in every flight.
pub const PROTOCOL_VERSION: u16 = 2;

/// Ciphersuite id 2: X25519 (classical) + ML-KEM-768 (post-quantum) key
/// exchange, identity-authenticated with Ed25519 + ML-DSA-87.
pub const CIPHERSUITE_HYBRID_X25519_MLKEM768: u16 = 0x0002;

// ---------------------------------------------------------------------------
// Ciphersuite registry (with sunset dates)
// ---------------------------------------------------------------------------

/// Metadata for a registered ciphersuite.
///
/// The `sunset` year-month is the point after which clients SHOULD no longer
/// offer the suite. Handshake negotiation always picks the newest non-sunset
/// suite both peers support, so new KEMs can be added and old ones retired
/// without breaking existing clients — the "100-year" protocol-evolution story.
#[derive(Debug, Clone, Copy)]
pub struct Ciphersuite {
    pub id: u16,
    pub name: &'static str,
    pub kem: &'static str,
    pub sig: &'static str,
    pub introduced: &'static str,
    pub sunset: &'static str,
}

/// The registry of known ciphersuites, oldest first.
pub const CIPHERSUITES: &[Ciphersuite] = &[Ciphersuite {
    id: CIPHERSUITE_HYBRID_X25519_MLKEM768,
    name: "hybrid-v2",
    kem: "X25519 + ML-KEM-768",
    sig: "Ed25519 + ML-DSA-87",
    introduced: "2024-01",
    sunset: "2035-12",
}];

/// Look up a ciphersuite by id.
pub fn ciphersuite(id: u16) -> Option<&'static Ciphersuite> {
    CIPHERSUITES.iter().find(|c| c.id == id)
}

/// Whether the ciphersuite is still active at `(year, month)`.
pub fn is_sunset(cs: &Ciphersuite, year: u16, month: u8) -> bool {
    parse_ym(cs.sunset)
        .map(|(y, m)| (year, month) > (y, m))
        .unwrap_or(false)
}

/// The newest active ciphersuite, or `None` if every suite is sunset.
pub fn newest_active(year: u16, month: u8) -> Option<u16> {
    CIPHERSUITES
        .iter()
        .rev()
        .find(|c| !is_sunset(c, year, month))
        .map(|c| c.id)
}

/// Select the newest ciphersuite offered by the peer that is also supported
/// locally and not yet sunset. Returns `None` when there is no overlap.
pub fn negotiate(offered: u16, supported: &[u16], year: u16, month: u8) -> Option<u16> {
    if !supported.contains(&offered) {
        return None;
    }
    let cs = ciphersuite(offered)?;
    if is_sunset(cs, year, month) {
        return None;
    }
    Some(offered)
}

fn parse_ym(s: &str) -> Option<(u16, u8)> {
    let (y, m) = s.split_once('-')?;
    Some((y.parse().ok()?, m.parse().ok()?))
}

const TAG_AUTH_INITIATOR: u8 = 0x11;
const TAG_AUTH_RESPONDER: u8 = 0x12;

const VERSION_LEN: usize = 2;
const CIPHERSUITE_LEN: usize = 2;
const X25519_PK_LEN: usize = 32;
const KEM_EK_LEN: usize = 1184;
const KEM_CT_LEN: usize = 1088;
const IDENTITY_PK_LEN: usize = 2624;
const TRANSCRIPT_LEN: usize = 32;
const SIGNATURE_LEN: usize = 4691;

const AUTH_INITIATOR_HELLO_LEN: usize =
    1 + VERSION_LEN + CIPHERSUITE_LEN + X25519_PK_LEN + KEM_EK_LEN + IDENTITY_PK_LEN
        + TRANSCRIPT_LEN + SIGNATURE_LEN;

const AUTH_RESPONDER_HELLO_LEN: usize =
    1 + VERSION_LEN + CIPHERSUITE_LEN + X25519_PK_LEN + KEM_CT_LEN + IDENTITY_PK_LEN
        + TRANSCRIPT_LEN + SIGNATURE_LEN;

fn transcript(tag: u8, version: u16, suite: u16, body: &[u8], identity_pk: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&[tag]);
    h.update(&version.to_le_bytes());
    h.update(&suite.to_le_bytes());
    h.update(body);
    h.update(identity_pk);
    h.finalize().into()
}

/// First flight (initiator → responder), identity-authenticated.
#[derive(Clone)]
pub struct AuthInitiatorHello {
    pub version: u16,
    pub ciphersuite: u16,
    pub hello: InitiatorHello,
    pub identity_pk: HybridVerifyingKey,
    pub transcript: [u8; 32],
    pub signature: HybridSignature,
}

/// Second flight (responder → initiator), identity-authenticated.
#[derive(Clone)]
pub struct AuthResponderHello {
    pub version: u16,
    pub ciphersuite: u16,
    pub hello: ResponderHello,
    pub identity_pk: HybridVerifyingKey,
    pub transcript: [u8; 32],
    pub signature: HybridSignature,
}

impl AuthInitiatorHello {
    /// Build the signed initiator flight from ephemeral initiator + identity.
    pub fn build(init: &Initiator, version: u16, ciphersuite: u16, sk: &HybridSigningKey) -> Self {
        let hello = init.hello();
        let identity_pk = sk.verifying_key();
        let id_bytes = identity_pk.to_bytes();
        let transcript = transcript(TAG_AUTH_INITIATOR, version, ciphersuite, &hello.to_wire(), &id_bytes);
        let signature = sk.sign(&transcript);
        Self { version, ciphersuite, hello, identity_pk, transcript, signature }
    }

    /// Serialize to wire bytes.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(AUTH_INITIATOR_HELLO_LEN);
        out.push(TAG_AUTH_INITIATOR);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.ciphersuite.to_le_bytes());
        out.extend_from_slice(self.hello.to_wire().as_slice());
        out.extend_from_slice(&self.identity_pk.to_bytes());
        out.extend_from_slice(&self.transcript);
        out.extend_from_slice(&self.signature.to_bytes());
        out
    }

    /// Deserialize from [`Self::to_wire`] output.
    pub fn from_wire(data: &[u8]) -> Option<Self> {
        if data.len() != AUTH_INITIATOR_HELLO_LEN || data[0] != TAG_AUTH_INITIATOR {
            return None;
        }
        let mut off = 1;
        let version = u16::from_le_bytes(data[off..off + 2].try_into().ok()?);
        off += VERSION_LEN;
        let ciphersuite = u16::from_le_bytes(data[off..off + 2].try_into().ok()?);
        off += CIPHERSUITE_LEN;
        let hello = InitiatorHello::from_wire(&data[off..off + X25519_PK_LEN + KEM_EK_LEN])?;
        off += X25519_PK_LEN + KEM_EK_LEN;
        let identity_pk = HybridVerifyingKey::from_bytes(&data[off..off + IDENTITY_PK_LEN])?;
        off += IDENTITY_PK_LEN;
        let mut transcript = [0u8; TRANSCRIPT_LEN];
        transcript.copy_from_slice(&data[off..off + TRANSCRIPT_LEN]);
        off += TRANSCRIPT_LEN;
        let signature = HybridSignature::from_bytes(&data[off..off + SIGNATURE_LEN])?;
        Some(Self { version, ciphersuite, hello, identity_pk, transcript, signature })
    }

    /// Recompute the transcript and verify the identity signature.
    pub fn verify(&self) -> bool {
        let tr = transcript(
            TAG_AUTH_INITIATOR,
            self.version,
            self.ciphersuite,
            &self.hello.to_wire(),
            &self.identity_pk.to_bytes(),
        );
        tr == self.transcript && self.identity_pk.verify(&self.transcript, &self.signature)
    }
}

impl AuthResponderHello {
    /// Build the signed responder flight from the ephemeral hello + identity.
    pub fn build(hello: &ResponderHello, version: u16, ciphersuite: u16, sk: &HybridSigningKey) -> Self {
        let identity_pk = sk.verifying_key();
        let id_bytes = identity_pk.to_bytes();
        let transcript = transcript(TAG_AUTH_RESPONDER, version, ciphersuite, &hello.to_wire(), &id_bytes);
        let signature = sk.sign(&transcript);
        Self { version, ciphersuite, hello: hello.clone(), identity_pk, transcript, signature }
    }

    /// Serialize to wire bytes.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(AUTH_RESPONDER_HELLO_LEN);
        out.push(TAG_AUTH_RESPONDER);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.ciphersuite.to_le_bytes());
        out.extend_from_slice(self.hello.to_wire().as_slice());
        out.extend_from_slice(&self.identity_pk.to_bytes());
        out.extend_from_slice(&self.transcript);
        out.extend_from_slice(&self.signature.to_bytes());
        out
    }

    /// Deserialize from [`Self::to_wire`] output.
    pub fn from_wire(data: &[u8]) -> Option<Self> {
        if data.len() != AUTH_RESPONDER_HELLO_LEN || data[0] != TAG_AUTH_RESPONDER {
            return None;
        }
        let mut off = 1;
        let version = u16::from_le_bytes(data[off..off + 2].try_into().ok()?);
        off += VERSION_LEN;
        let ciphersuite = u16::from_le_bytes(data[off..off + 2].try_into().ok()?);
        off += CIPHERSUITE_LEN;
        let hello = ResponderHello::from_wire(&data[off..off + X25519_PK_LEN + KEM_CT_LEN])?;
        off += X25519_PK_LEN + KEM_CT_LEN;
        let identity_pk = HybridVerifyingKey::from_bytes(&data[off..off + IDENTITY_PK_LEN])?;
        off += IDENTITY_PK_LEN;
        let mut transcript = [0u8; TRANSCRIPT_LEN];
        transcript.copy_from_slice(&data[off..off + TRANSCRIPT_LEN]);
        off += TRANSCRIPT_LEN;
        let signature = HybridSignature::from_bytes(&data[off..off + SIGNATURE_LEN])?;
        Some(Self { version, ciphersuite, hello, identity_pk, transcript, signature })
    }

    /// Recompute the transcript and verify the identity signature.
    pub fn verify(&self) -> bool {
        let tr = transcript(
            TAG_AUTH_RESPONDER,
            self.version,
            self.ciphersuite,
            &self.hello.to_wire(),
            &self.identity_pk.to_bytes(),
        );
        tr == self.transcript && self.identity_pk.verify(&self.transcript, &self.signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::Responder;

    fn test_signing_key() -> HybridSigningKey {
        HybridSigningKey::from_bip39_seed(&[7u8; 64])
    }

    #[test]
    fn ciphersuite_registry_is_consistent() {
        // Ids are unique; sunset comes after introduction; ids are monotonic.
        for (i, cs) in CIPHERSUITES.iter().enumerate() {
            assert!(CIPHERSUITES[i..].iter().skip(1).all(|o| o.id != cs.id), "unique ids");
            let (iy, im) = parse_ym(cs.introduced).expect("valid introduced");
            let (sy, sm) = parse_ym(cs.sunset).expect("valid sunset");
            assert!((sy, sm) > (iy, im), "sunset after introduction");
        }
        // The current suite is active today and negotiable.
        let now = crate::common::now_ym();
        assert!(!is_sunset(&CIPHERSUITES[0], now.0, now.1));
        assert_eq!(negotiate(CIPHERSUITE_HYBRID_X25519_MLKEM768, &[CIPHERSUITE_HYBRID_X25519_MLKEM768], now.0, now.1),
                   Some(CIPHERSUITE_HYBRID_X25519_MLKEM768));
        assert_eq!(newest_active(now.0, now.1), Some(CIPHERSUITE_HYBRID_X25519_MLKEM768));
        // Unsupported and sunset suites are not negotiable.
        assert_eq!(negotiate(0x0001, &[CIPHERSUITE_HYBRID_X25519_MLKEM768], now.0, now.1), None);
        assert_eq!(negotiate(CIPHERSUITE_HYBRID_X25519_MLKEM768, &[], now.0, now.1), None);
        assert!(is_sunset(&CIPHERSUITES[0], 2036, 1));
    }

    #[test]
    fn initiator_flight_roundtrip_and_verify() {
        let init = Initiator::new();
        let sk = test_signing_key();
        let flight = AuthInitiatorHello::build(&init, PROTOCOL_VERSION, CIPHERSUITE_HYBRID_X25519_MLKEM768, &sk);
        assert!(flight.verify());
        let wire = flight.to_wire();
        assert_eq!(wire.len(), AUTH_INITIATOR_HELLO_LEN);
        let back = AuthInitiatorHello::from_wire(&wire).expect("must deserialize");
        assert_eq!(back.to_wire(), wire);
        assert!(back.verify());
    }

    #[test]
    fn responder_flight_roundtrip_and_verify() {
        let init = Initiator::new();
        let hello = init.hello();
        let (resp, _key) = Responder::new().respond(&hello);
        let sk = test_signing_key();
        let flight = AuthResponderHello::build(&resp, PROTOCOL_VERSION, CIPHERSUITE_HYBRID_X25519_MLKEM768, &sk);
        assert!(flight.verify());
        let wire = flight.to_wire();
        assert_eq!(wire.len(), AUTH_RESPONDER_HELLO_LEN);
        let back = AuthResponderHello::from_wire(&wire).expect("must deserialize");
        assert!(back.verify());
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let init = Initiator::new();
        let sk = test_signing_key();
        let flight = AuthInitiatorHello::build(&init, PROTOCOL_VERSION, CIPHERSUITE_HYBRID_X25519_MLKEM768, &sk);
        let mut wire = flight.to_wire();
        // Flip a bit in the signature region.
        let sig_start = AUTH_INITIATOR_HELLO_LEN - SIGNATURE_LEN;
        wire[sig_start + 10] ^= 0xff;
        let tampered = AuthInitiatorHello::from_wire(&wire).expect("parses");
        assert!(!tampered.verify());
    }

    #[test]
    fn wrong_identity_signature_is_rejected() {
        let init = Initiator::new();
        let sk1 = test_signing_key();
        let sk2 = HybridSigningKey::from_bip39_seed(&[8u8; 64]);
        let flight = AuthInitiatorHello::build(&init, PROTOCOL_VERSION, CIPHERSUITE_HYBRID_X25519_MLKEM768, &sk1);
        // Swap the identity pk to sk2's while keeping sk1's signature.
        let mut clone = flight;
        clone.identity_pk = sk2.verifying_key();
        assert!(!clone.verify());
    }
}