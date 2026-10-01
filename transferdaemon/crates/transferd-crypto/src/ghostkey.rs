//! Ghost keys: anonymous, verifiable identities (the idea of Freenet's Ghost Keys, freenet/web).
//!
//! An issuer (a relay operator, a community, anyone running `transferd-cli ghostkey issuer-new`) vouches that a
//! person passed some gate — a donation, an invite, proof of work, a meeting — without ever learning which key it
//! vouched for. The person makes an Ed25519 key, *blinds* it, the issuer signs the blinded value, and the person
//! *unblinds* the signature into a certificate any party can check against the issuer's public key. The issuer
//! cannot link the certificate it later sees back to the signing it did (RFC 9474 blind RSA signatures).
//!
//! What a certificate gives TransferD: relays and contacts can rate-limit, prioritise or require *some* vouched
//! identity (anti-spam, anti-Sybil) with no account, no phone number and no link to the person's real TransferD
//! identity. Each issuer key stands for one tier (e.g. one donation level), so the tier is in which key signed.
//!
//! Construction: RSABSSA-SHA384-PSS-Randomized (RFC 9474 §4, §5): the message is a 32-byte random prefix, then
//! `"transferd-ghostkey-v1" || tier || ed25519 public key`; EMSA-PSS with SHA-384, MGF1-SHA-384 and a 48-byte salt.
//! Finalised signatures are checked with the `rsa` crate's own RSASSA-PSS verifier, so a certificate is an ordinary
//! PSS signature any RSA library verifies.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use num_bigint_dig::{BigUint, ModInverse, RandBigInt};
use num_traits::{One, Zero};
use rand::RngCore;
use rsa::pkcs8::{DecodePublicKey, EncodePublicKey};
use rsa::traits::PublicKeyParts;
use rsa::{Pss, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha384};

pub const DOMAIN: &[u8] = b"transferd-ghostkey-v1";
const SALT_LEN: usize = 48;
const PREFIX_LEN: usize = 32;
const HASH_LEN: usize = 48;

#[derive(Debug, thiserror::Error)]
pub enum GhostKeyError {
    #[error("RSA: {0}")]
    Rsa(#[from] rsa::Error),
    #[error("the issuer key must be 2048 to 4096 bits (got {0})")]
    KeySize(usize),
    #[error("the message is too long for this issuer key")]
    MessageTooLong,
    #[error("a blinded value has the wrong length (expected {expected} bytes, got {got})")]
    Length { expected: usize, got: usize },
    #[error("the issuer's signature does not check out (a wrong issuer key, or tampering)")]
    BadIssuerSignature,
    #[error("the certificate is not valid for this issuer")]
    InvalidCertificate,
    #[error("the ghost key's signature does not check out")]
    BadSignature,
    #[error("encoding: {0}")]
    Encoding(String),
}

// ---- RFC 9474 pieces ------------------------------------------------------------------------------------------------ //

fn mgf1(seed: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + HASH_LEN);
    let mut counter: u32 = 0;
    while out.len() < len {
        let mut h = Sha384::new();
        h.update(seed);
        h.update(counter.to_be_bytes());
        out.extend_from_slice(&h.finalize());
        counter += 1;
    }
    out.truncate(len);
    out
}

/// EMSA-PSS-ENCODE (RFC 8017 §9.1.1) with SHA-384, MGF1-SHA-384, a 48-byte salt.
fn emsa_pss_encode(msg: &[u8], em_bits: usize, rng: &mut impl RngCore) -> Result<Vec<u8>, GhostKeyError> {
    let em_len = em_bits.div_ceil(8);
    let m_hash = Sha384::digest(msg);
    if em_len < HASH_LEN + SALT_LEN + 2 {
        return Err(GhostKeyError::MessageTooLong);
    }
    let mut salt = [0u8; SALT_LEN];
    rng.fill_bytes(&mut salt);
    let mut h = Sha384::new();
    h.update([0u8; 8]);
    h.update(m_hash);
    h.update(salt);
    let h = h.finalize();
    let ps_len = em_len - SALT_LEN - HASH_LEN - 2;
    let mut db = vec![0u8; ps_len];
    db.push(0x01);
    db.extend_from_slice(&salt);
    let mask = mgf1(&h, em_len - HASH_LEN - 1);
    for (d, m) in db.iter_mut().zip(mask) {
        *d ^= m;
    }
    let zero_bits = 8 * em_len - em_bits;
    db[0] &= 0xFF >> zero_bits;
    let mut em = db;
    em.extend_from_slice(&h);
    em.push(0xBC);
    Ok(em)
}

fn i2osp(x: &BigUint, len: usize) -> Result<Vec<u8>, GhostKeyError> {
    let b = x.to_bytes_be();
    if b.len() > len {
        return Err(GhostKeyError::MessageTooLong);
    }
    let mut out = vec![0u8; len - b.len()];
    out.extend_from_slice(&b);
    Ok(out)
}

/// The issuer's public key as num-bigint-dig values (rsa 0.9 hands out its own BigUint, the same type).
fn n_e(pk: &RsaPublicKey) -> (BigUint, BigUint) {
    (BigUint::from_bytes_be(&pk.n().to_bytes_be()), BigUint::from_bytes_be(&pk.e().to_bytes_be()))
}

fn ghost_message(tier: &str, ghost_pub: &[u8; 32]) -> Vec<u8> {
    let mut m = DOMAIN.to_vec();
    m.push(tier.len() as u8);
    m.extend_from_slice(tier.as_bytes());
    m.extend_from_slice(ghost_pub);
    m
}

// ---- the issuer ------------------------------------------------------------------------------------------------------ //

/// An issuer key for one tier. Keep the private part offline or on the relay; publish [`IssuerPublic`].
pub struct Issuer {
    key: RsaPrivateKey,
    pub public: IssuerPublic,
}

/// What everyone needs to check certificates: the RSA public key, its tier and a short id.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IssuerPublic {
    pub name: String,
    pub tier: String,
    /// SubjectPublicKeyInfo DER
    pub spki: Vec<u8>,
}

impl IssuerPublic {
    pub fn rsa(&self) -> Result<RsaPublicKey, GhostKeyError> {
        RsaPublicKey::from_public_key_der(&self.spki).map_err(|e| GhostKeyError::Encoding(e.to_string()))
    }
    /// blake3 of the SPKI, first 8 bytes in hex: how certificates name their issuer.
    pub fn id(&self) -> String {
        hex::encode(&blake3::hash(&self.spki).as_bytes()[..8])
    }
}

impl Issuer {
    pub fn generate(name: &str, tier: &str, bits: usize) -> Result<Self, GhostKeyError> {
        if !(2048..=4096).contains(&bits) {
            return Err(GhostKeyError::KeySize(bits));
        }
        if tier.len() > 64 {
            return Err(GhostKeyError::Encoding("a tier is at most 64 bytes".into()));
        }
        let key = RsaPrivateKey::new(&mut rand::thread_rng(), bits)?;
        Self::from_private(name, tier, key)
    }

    pub fn from_private(name: &str, tier: &str, key: RsaPrivateKey) -> Result<Self, GhostKeyError> {
        let spki = key.to_public_key().to_public_key_der().map_err(|e| GhostKeyError::Encoding(e.to_string()))?.into_vec();
        Ok(Self { key, public: IssuerPublic { name: name.into(), tier: tier.into(), spki } })
    }

    pub fn private_key(&self) -> &RsaPrivateKey {
        &self.key
    }

    /// The issuer's secret file: `transferd-ghostissuer-v1:<name>\n<tier>\n<hex PKCS#8 DER>`. Keep it private.
    pub fn to_secret_text(&self) -> Result<String, GhostKeyError> {
        use rsa::pkcs8::EncodePrivateKey;
        let der = self.key.to_pkcs8_der().map_err(|e| GhostKeyError::Encoding(e.to_string()))?;
        Ok(format!("transferd-ghostissuer-v1:{}\n{}\n{}\n", self.public.name, self.public.tier, hex::encode(der.as_bytes())))
    }

    pub fn from_secret_text(s: &str) -> Result<Self, GhostKeyError> {
        use rsa::pkcs8::DecodePrivateKey;
        let body = s.trim().strip_prefix("transferd-ghostissuer-v1:").ok_or_else(|| GhostKeyError::Encoding("not an issuer secret".into()))?;
        let mut lines = body.lines();
        let (Some(name), Some(tier), Some(der)) = (lines.next(), lines.next(), lines.next()) else {
            return Err(GhostKeyError::Encoding("an issuer secret has a name, a tier and a key".into()));
        };
        let der = hex::decode(der.trim()).map_err(|e| GhostKeyError::Encoding(e.to_string()))?;
        let key = RsaPrivateKey::from_pkcs8_der(&der).map_err(|e| GhostKeyError::Encoding(e.to_string()))?;
        Self::from_private(name, tier, key)
    }
}

impl IssuerPublic {
    /// `transferd-ghostissuerpub-v1:<hex of bincode>`: what an issuer publishes.
    pub fn to_text(&self) -> String {
        format!("transferd-ghostissuerpub-v1:{}", hex::encode(bincode::serialize(self).expect("an issuer key serialises")))
    }

    pub fn from_text(s: &str) -> Result<Self, GhostKeyError> {
        let body = s.trim().strip_prefix("transferd-ghostissuerpub-v1:").ok_or_else(|| GhostKeyError::Encoding("not an issuer public key".into()))?;
        bincode::deserialize(&hex::decode(body).map_err(|e| GhostKeyError::Encoding(e.to_string()))?)
            .map_err(|e| GhostKeyError::Encoding(e.to_string()))
    }
}

impl BlindState {
    /// The pending request (secret: the blinding inverse and the ghost key's own secret travel together, kept by the
    /// person only): `transferd-ghostpending-v1:<hex>`.
    pub fn to_text(&self, key: &GhostKey) -> String {
        let parts: (Vec<u8>, Vec<u8>, usize, [u8; 32]) = (self.inv.to_bytes_be(), self.msg.clone(), self.k, key.secret());
        format!("transferd-ghostpending-v1:{}", hex::encode(bincode::serialize(&parts).expect("state serialises")))
    }

    pub fn from_text(s: &str) -> Result<(Self, GhostKey), GhostKeyError> {
        let body = s.trim().strip_prefix("transferd-ghostpending-v1:").ok_or_else(|| GhostKeyError::Encoding("not a pending ghost key request".into()))?;
        let (inv, msg, k, secret): (Vec<u8>, Vec<u8>, usize, [u8; 32]) =
            bincode::deserialize(&hex::decode(body).map_err(|e| GhostKeyError::Encoding(e.to_string()))?)
                .map_err(|e| GhostKeyError::Encoding(e.to_string()))?;
        Ok((Self { inv: BigUint::from_bytes_be(&inv), msg, k }, GhostKey::from_secret(secret)))
    }
}

impl Issuer {

    /// BlindSign (RFC 9474 §4.3): the raw RSA operation on a value the issuer cannot read, checked before release.
    pub fn sign_blinded(&self, blinded: &[u8]) -> Result<Vec<u8>, GhostKeyError> {
        let k = self.key.size();
        if blinded.len() != k {
            return Err(GhostKeyError::Length { expected: k, got: blinded.len() });
        }
        let m = rsa::BigUint::from_bytes_be(blinded);
        if &m >= self.key.n() {
            return Err(GhostKeyError::MessageTooLong);
        }
        let s = rsa::hazmat::rsa_decrypt_and_check(&self.key, Some(&mut rand::thread_rng()), &m)?;
        // the check RFC 9474 asks for: s^e == m, so a fault never leaks the key
        if rsa::hazmat::rsa_encrypt(&self.key.to_public_key(), &s)? != m {
            return Err(GhostKeyError::BadIssuerSignature);
        }
        i2osp(&BigUint::from_bytes_be(&s.to_bytes_be()), k)
    }
}

// ---- the person ------------------------------------------------------------------------------------------------------ //

/// The ghost key itself: an Ed25519 key the person keeps; its certificate says an issuer vouched for it.
pub struct GhostKey {
    signing: SigningKey,
}

/// Between asking and finishing: the secret blinding inverse and the randomised message. Never sent anywhere.
pub struct BlindState {
    inv: BigUint,
    msg: Vec<u8>,
    k: usize,
}

/// A finished certificate: shareable, checkable by anyone with the issuer's public key.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GhostCertificate {
    pub issuer_id: String,
    pub tier: String,
    pub ghost_public: [u8; 32],
    /// RFC 9474's random message prefix (part of what was signed)
    pub prefix: [u8; PREFIX_LEN],
    pub signature: Vec<u8>,
}

impl GhostKey {
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        Self { signing: SigningKey::from_bytes(&seed) }
    }

    pub fn from_secret(secret: [u8; 32]) -> Self {
        Self { signing: SigningKey::from_bytes(&secret) }
    }

    pub fn secret(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    pub fn public(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// Blind (RFC 9474 §4.2, randomized variant): what to send the issuer, and the state to keep.
    pub fn blind_request(&self, issuer: &IssuerPublic) -> Result<(Vec<u8>, BlindState), GhostKeyError> {
        let pk = issuer.rsa()?;
        let (n, e) = n_e(&pk);
        let k = pk.size();
        let mut rng = rand::thread_rng();
        let mut prefix = [0u8; PREFIX_LEN];
        rng.fill_bytes(&mut prefix);
        let mut msg = prefix.to_vec();
        msg.extend_from_slice(&ghost_message(&issuer.tier, &self.public()));
        let em = emsa_pss_encode(&msg, n.bits() - 1, &mut rng)?;
        let m = BigUint::from_bytes_be(&em);
        loop {
            let r = rng.gen_biguint_range(&BigUint::one(), &n);
            let Some(inv) = r.clone().mod_inverse(&n).and_then(|i| i.to_biguint()) else { continue };
            if inv.is_zero() {
                continue;
            }
            let z = (&m * r.modpow(&e, &n)) % &n;
            return Ok((i2osp(&z, k)?, BlindState { inv, msg, k }));
        }
    }

    /// Finalize (RFC 9474 §4.4): unblind the issuer's answer and check it is a valid PSS signature.
    pub fn finish(&self, issuer: &IssuerPublic, state: BlindState, blind_sig: &[u8]) -> Result<GhostCertificate, GhostKeyError> {
        if blind_sig.len() != state.k {
            return Err(GhostKeyError::Length { expected: state.k, got: blind_sig.len() });
        }
        let pk = issuer.rsa()?;
        let (n, _) = n_e(&pk);
        let z = BigUint::from_bytes_be(blind_sig);
        let s = (z * &state.inv) % &n;
        let signature = i2osp(&s, state.k)?;
        let mut prefix = [0u8; PREFIX_LEN];
        prefix.copy_from_slice(&state.msg[..PREFIX_LEN]);
        let cert = GhostCertificate { issuer_id: issuer.id(), tier: issuer.tier.clone(), ghost_public: self.public(), prefix, signature };
        cert.verify(issuer).map_err(|_| GhostKeyError::BadIssuerSignature)?;
        Ok(cert)
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing.sign(message).to_bytes()
    }
}

impl GhostCertificate {
    /// Is this a key the issuer vouched for (at its tier)?
    pub fn verify(&self, issuer: &IssuerPublic) -> Result<(), GhostKeyError> {
        if self.issuer_id != issuer.id() || self.tier != issuer.tier {
            return Err(GhostKeyError::InvalidCertificate);
        }
        let pk = issuer.rsa()?;
        let mut msg = self.prefix.to_vec();
        msg.extend_from_slice(&ghost_message(&self.tier, &self.ghost_public));
        let hashed = Sha384::digest(&msg);
        pk.verify(Pss::new_with_salt::<Sha384>(SALT_LEN), &hashed, &self.signature).map_err(|_| GhostKeyError::InvalidCertificate)
    }

    /// A message signed by the ghost key this certificate vouches for.
    pub fn verify_signed(&self, issuer: &IssuerPublic, message: &[u8], signature: &[u8; 64]) -> Result<(), GhostKeyError> {
        self.verify(issuer)?;
        let vk = VerifyingKey::from_bytes(&self.ghost_public).map_err(|_| GhostKeyError::InvalidCertificate)?;
        vk.verify(message, &ed25519_dalek::Signature::from_bytes(signature)).map_err(|_| GhostKeyError::BadSignature)
    }

    /// A text form for files and messages: `transferd-ghostcert-v1:<hex of bincode>`.
    pub fn to_text(&self) -> String {
        format!("transferd-ghostcert-v1:{}", hex::encode(bincode::serialize(self).expect("a certificate serialises")))
    }

    pub fn from_text(s: &str) -> Result<Self, GhostKeyError> {
        let body = s.trim().strip_prefix("transferd-ghostcert-v1:").ok_or_else(|| GhostKeyError::Encoding("not a ghost key certificate".into()))?;
        let bytes = hex::decode(body).map_err(|e| GhostKeyError::Encoding(e.to_string()))?;
        bincode::deserialize(&bytes).map_err(|e| GhostKeyError::Encoding(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;

    fn issuer() -> &'static Issuer {
        static I: OnceLock<Issuer> = OnceLock::new();
        I.get_or_init(|| Issuer::generate("test relay", "supporter", 2048).unwrap())
    }

    #[test]
    fn issue_and_verify_a_ghost_key() {
        let iss = issuer();
        let me = GhostKey::generate();
        let (blinded, state) = me.blind_request(&iss.public).unwrap();
        let blind_sig = iss.sign_blinded(&blinded).unwrap();
        let cert = me.finish(&iss.public, state, &blind_sig).unwrap();
        cert.verify(&iss.public).unwrap();
        let sig = me.sign(b"hello relay");
        cert.verify_signed(&iss.public, b"hello relay", &sig).unwrap();
        assert!(cert.verify_signed(&iss.public, b"other message", &sig).is_err());
        let back = GhostCertificate::from_text(&cert.to_text()).unwrap();
        assert_eq!(back, cert);
    }

    #[test]
    fn the_issuer_never_sees_the_key() {
        let iss = issuer();
        let me = GhostKey::generate();
        let (b1, _) = me.blind_request(&iss.public).unwrap();
        let (b2, _) = me.blind_request(&iss.public).unwrap();
        assert_ne!(b1, b2, "every request is blinded afresh");
        assert!(!b1.windows(32).any(|w| w == me.public()), "the key is not visible in the request");
    }

    #[test]
    fn forged_or_mismatched_certificates_fail() {
        let iss = issuer();
        let other = Issuer::generate("someone else", "supporter", 2048).unwrap();
        let me = GhostKey::generate();
        let (blinded, state) = me.blind_request(&iss.public).unwrap();
        let cert = me.finish(&iss.public, state, &iss.sign_blinded(&blinded).unwrap()).unwrap();
        assert!(cert.verify(&other.public).is_err(), "another issuer's key");
        let mut swapped = cert.clone();
        swapped.ghost_public = GhostKey::generate().public();
        assert!(swapped.verify(&iss.public).is_err(), "a different ghost key under the same signature");
        let mut retiered = cert.clone();
        retiered.tier = "gold".into();
        assert!(retiered.verify(&iss.public).is_err());
        let (blinded, state) = me.blind_request(&iss.public).unwrap();
        if let Ok(w) = other.sign_blinded(&blinded) {
            assert!(me.finish(&iss.public, state, &w).is_err(), "a signature by the wrong issuer");
        }
        assert!(iss.sign_blinded(&[1, 2, 3]).is_err(), "a wrong-length value");
    }

    #[test]
    fn the_files_round_trip() {
        let iss = issuer();
        let again = Issuer::from_secret_text(&iss.to_secret_text().unwrap()).unwrap();
        assert_eq!(again.public, iss.public);
        assert_eq!(IssuerPublic::from_text(&iss.public.to_text()).unwrap(), iss.public);
        let me = GhostKey::generate();
        let (blinded, state) = me.blind_request(&iss.public).unwrap();
        let (state, me2) = BlindState::from_text(&state.to_text(&me)).unwrap();
        assert_eq!(me2.public(), me.public());
        let cert = me2.finish(&iss.public, state, &again.sign_blinded(&blinded).unwrap()).unwrap();
        cert.verify(&iss.public).unwrap();
    }

    #[test]
    fn issuer_key_size_is_bounded() {
        assert!(matches!(Issuer::generate("x", "t", 1024), Err(GhostKeyError::KeySize(1024))));
    }
}
