//! Ghost key admission: a relay that admits only identities some issuer vouched for (anti-spam, anti-Sybil), without
//! learning who they are (transferd_crypto::ghostkey, the freenet/web Ghost Keys idea).
//!
//! A recipient registers with [`GhostRegisterMsg`]: its usual registration (PoW still applies), its ghost key
//! certificate, and the ghost key's signature over [`binding`] (this session token and sequence number). The relay
//! checks the certificate against its trusted issuers and the signature against the certificate's key, and caps how
//! many live sessions one ghost key may hold here. The certificate never reveals the person's TransferD identity.
//!
//! Operator flags (relayd): `--ghost-issuer <file>` (repeatable; files from `transferd-cli ghostkey issuer-new`),
//! `--require-ghost` (plain registrations are refused), `--ghost-sessions <n>` (default 8).

use crate::protocol::GhostRegisterMsg;
use transferd_crypto::ghostkey::{GhostCertificate, GhostKey, IssuerPublic};

pub const BINDING_DOMAIN: &[u8] = b"transferd-relay-ghost-v1";

/// What a ghost key signs to register a session: the domain, the session token and the sequence number.
pub fn binding(token: &[u8; 32], seq: u32) -> Vec<u8> {
    let mut m = BINDING_DOMAIN.to_vec();
    m.extend_from_slice(token);
    m.extend_from_slice(&seq.to_le_bytes());
    m
}

#[derive(Clone, Debug)]
pub struct GhostPolicy {
    pub issuers: Vec<IssuerPublic>,
    pub required: bool,
    pub max_sessions_per_key: usize,
}

impl Default for GhostPolicy {
    fn default() -> Self {
        Self { issuers: Vec::new(), required: false, max_sessions_per_key: 8 }
    }
}

impl GhostPolicy {
    /// Load issuer files (`transferd-ghostissuerpub-v1:...`).
    pub fn from_files(paths: &[String], required: bool, max_sessions_per_key: usize) -> Result<Self, String> {
        let mut issuers = Vec::new();
        for p in paths {
            let text = std::fs::read_to_string(p).map_err(|e| format!("{p}: {e}"))?;
            issuers.push(IssuerPublic::from_text(&text).map_err(|e| format!("{p}: {e}"))?);
        }
        if required && issuers.is_empty() {
            return Err("--require-ghost needs at least one --ghost-issuer".into());
        }
        Ok(Self { issuers, required, max_sessions_per_key: max_sessions_per_key.max(1) })
    }

    /// The ghost key a registration proves, if it does.
    pub fn admit(&self, msg: &GhostRegisterMsg) -> Result<[u8; 32], String> {
        if self.issuers.is_empty() {
            return Err("this relay trusts no ghost key issuer".into());
        }
        let cert: GhostCertificate = bincode::deserialize(&msg.certificate).map_err(|_| "not a ghost key certificate".to_string())?;
        let issuer = self.issuers.iter().find(|i| i.id() == cert.issuer_id).ok_or("the certificate's issuer is not trusted here")?;
        let sig: [u8; 64] = msg.signature.as_slice().try_into().map_err(|_| "a ghost key signature is 64 bytes".to_string())?;
        cert.verify_signed(issuer, &binding(&msg.register.session_token, msg.register.seq), &sig).map_err(|e| e.to_string())?;
        Ok(cert.ghost_public)
    }
}

/// The client side: wrap a registration with a ghost key certificate.
pub fn ghost_register(register: crate::protocol::RegisterMsg, cert: &GhostCertificate, key: &GhostKey) -> GhostRegisterMsg {
    let signature = key.sign(&binding(&register.session_token, register.seq)).to_vec();
    GhostRegisterMsg { register, certificate: bincode::serialize(cert).expect("a certificate serialises"), signature }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::RegisterMsg;
    use crate::relay::{Relay, RelayError};
    use std::sync::OnceLock;
    use transferd_crypto::ghostkey::Issuer;

    fn issuer() -> &'static Issuer {
        static I: OnceLock<Issuer> = OnceLock::new();
        I.get_or_init(|| Issuer::generate("relay test", "member", 2048).unwrap())
    }

    fn vouched() -> (GhostKey, GhostCertificate) {
        let me = GhostKey::generate();
        let (blinded, state) = me.blind_request(&issuer().public).unwrap();
        let cert = me.finish(&issuer().public, state, &issuer().sign_blinded(&blinded).unwrap()).unwrap();
        (me, cert)
    }

    fn relay(required: bool, cap: usize) -> Relay {
        let mut r = Relay::new(0, 60, 1024);
        r.set_ghost_policy(GhostPolicy { issuers: vec![issuer().public.clone()], required, max_sessions_per_key: cap });
        r
    }

    fn addr() -> std::net::SocketAddr {
        "127.0.0.1:9".parse().unwrap()
    }

    fn reg(t: u8, seq: u32) -> RegisterMsg {
        RegisterMsg { session_token: [t; 32], pow_nonce: 0, seq }
    }

    #[test]
    fn a_vouched_key_registers_and_plain_ones_need_not_when_optional() {
        let (me, cert) = vouched();
        let mut r = relay(false, 8);
        r.register_ghost(&ghost_register(reg(1, 1), &cert, &me), addr()).unwrap();
        r.register(&reg(2, 1), addr()).unwrap();
    }

    #[test]
    fn required_means_plain_registrations_are_refused() {
        let (me, cert) = vouched();
        let mut r = relay(true, 8);
        assert!(matches!(r.register(&reg(3, 1), addr()), Err(RelayError::GhostRequired)));
        r.register_ghost(&ghost_register(reg(3, 1), &cert, &me), addr()).unwrap();
    }

    #[test]
    fn a_seen_certificate_cannot_be_reused_by_someone_else() {
        let (_me, cert) = vouched();
        let thief = GhostKey::generate();
        let mut r = relay(true, 8);
        let e = r.register_ghost(&ghost_register(reg(4, 1), &cert, &thief), addr()).unwrap_err();
        assert!(matches!(e, RelayError::GhostRejected(_)), "{e}");
        // and a signature for one token does not register another
        let (me, cert) = vouched();
        let mut msg = ghost_register(reg(5, 1), &cert, &me);
        msg.register.session_token = [6; 32];
        assert!(r.register_ghost(&msg, addr()).is_err());
    }

    #[test]
    fn untrusted_issuers_are_refused() {
        let other = Issuer::generate("elsewhere", "member", 2048).unwrap();
        let me = GhostKey::generate();
        let (blinded, state) = me.blind_request(&other.public).unwrap();
        let cert = me.finish(&other.public, state, &other.sign_blinded(&blinded).unwrap()).unwrap();
        let mut r = relay(true, 8);
        assert!(r.register_ghost(&ghost_register(reg(7, 1), &cert, &me), addr()).is_err());
    }

    #[test]
    fn one_ghost_key_holds_a_bounded_number_of_sessions() {
        let (me, cert) = vouched();
        let mut r = relay(true, 2);
        r.register_ghost(&ghost_register(reg(10, 1), &cert, &me), addr()).unwrap();
        r.register_ghost(&ghost_register(reg(11, 1), &cert, &me), addr()).unwrap();
        assert!(r.register_ghost(&ghost_register(reg(12, 1), &cert, &me), addr()).is_err());
        // refreshing a session it already holds is fine
        r.register_ghost(&ghost_register(reg(10, 2), &cert, &me), addr()).unwrap();
    }
}
