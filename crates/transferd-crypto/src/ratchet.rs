//! Double ratchet — per-message forward + future secrecy.
//!
//! Established on top of the authenticated hybrid handshake: the session key
//! becomes the ratchet ROOT. Each message is encrypted under a fresh key
//! derived from a BLAKE3 KDF chain, so compromising one message key reveals
//! neither earlier nor later messages (forward secrecy). Every `RATCHET_INTERVAL`
//! sends, the sender performs an X25519 DH ratchet that mixes a fresh ephemeral
//! secret into the root, so even a leaked session key cannot decrypt messages
//! sent after the compromise (future secrecy). The recipient ratchets on
//! seeing a new ratchet public key, keeping both sides in lock-step.
//!
//! ## Post-quantum future secrecy
//! Each DH ratchet step ALSO performs an ML-KEM-768 encapsulation: the sender
//! generates a fresh ML-KEM keypair, encapsulates a random secret to the
//! peer's ML-KEM public key, and mixes the resulting shared secret into the
//! root alongside the X25519 DH output (`root = KDF(root, x25519_ss ‖ kem_ss)`).
//! An attacker holding every classical secret (X25519 keys + root) — but not
//! the ML-KEM secrets — cannot derive keys from messages sent after a DH
//! ratchet: the quantum component protects future secrecy exactly as the
//! handshake's hybrid key exchange protects the session itself.
//!
//! ## Wire format
//! The ratchet envelope wraps the application `WireMsg`:
//!
//! ```text
//! RatchetMessage:
//!   ratchet_pk  Option<[u8; 32]>    // X25519 pk; set on first send + DH steps
//!   kem_ek      Option<Vec<u8>>     // ML-KEM-768 ek (1184 B); set alongside
//!   kem_ct      Option<Vec<u8>>     // ML-KEM-768 ct (1088 B); set on DH steps
//!   chain_index u64                 // send-chain position (nonce derivation)
//!   nonce       [u8; 12]
//!   tag         [u8; 16]
//!   ciphertext  Vec<u8>             // AES-256-GCM of the serialized WireMsg
//! ```
//!
//! ## Ordering assumption
//! The transport (single lane + GSN reassembly + retransmit) delivers in
//! order, so the ratchet does not need skipped-key storage; chains advance
//! once per message. This is documented so a future unordered transport
//! knows it must add skipped-message keys.

use aes_gcm::aead::{Aead, KeyInit, Nonce};
use aes_gcm::Aes256Gcm;
use ml_kem::{
    B32, Decapsulate, Seed,
    ml_kem_768::{Ciphertext as MlCt768, DecapsulationKey as MlDk768, EncapsulationKey as MlEk768},
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const CTX_CHAIN: &str = "TransferDaemon-v3-ratchet-chain";
const CTX_MESSAGE_KEY: &str = "TransferDaemon-v3-ratchet-message-key";
const CTX_ROOT_MIX: &str = "TransferDaemon-v3-ratchet-root-mix";
const CTX_DH: &str = "TransferDaemon-v3-ratchet-dh";
const CTX_KEM: &str = "TransferDaemon-v3-ratchet-kem";
const CTX_INIT_SEND: &str = "TransferDaemon-v3-ratchet-init-send";
const CTX_INIT_RECV: &str = "TransferDaemon-v3-ratchet-init-recv";

/// How many sends before the sender performs a DH ratchet step.
pub const RATCHET_INTERVAL: u32 = 10;

// ── ML-KEM-768 helpers (same rand_core-bypass pattern as the handshake) ─────

fn fresh_kem() -> (MlDk768, MlEk768) {
    let mut raw_seed = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut raw_seed);
    let seed: Seed = raw_seed.into();
    let dk = MlDk768::from_seed(seed);
    let ek = dk.encapsulation_key().clone();
    (dk, ek)
}

fn kem_ek_bytes(ek: &MlEk768) -> Vec<u8> {
    let b: kem::Key<MlEk768> = <MlEk768 as kem::KeyExport>::to_bytes(ek);
    let slice: &[u8] = b.as_ref();
    slice.to_vec()
}

fn kem_ek_from_bytes(b: &[u8]) -> Option<MlEk768> {
    let key: kem::Key<MlEk768> = b.try_into().ok()?;
    <MlEk768 as kem::TryKeyInit>::new(&key).ok()
}

fn kem_ct_bytes(ct: &MlCt768) -> Vec<u8> {
    let slice: &[u8] = ct.as_ref();
    slice.to_vec()
}

fn kem_ct_from_bytes(b: &[u8]) -> Option<MlCt768> {
    b.try_into().ok()
}

/// Encapsulate a fresh random secret to `peer_ek`, returning the ciphertext
/// and shared secret (post-quantum future-secrecy component of a DH step).
fn kem_encapsulate(peer_ek: &MlEk768) -> (MlCt768, Vec<u8>) {
    let mut raw_m = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw_m);
    let m: B32 = raw_m.into();
    let (ct, ss) = peer_ek.encapsulate_deterministic(&m);
    let slice: &[u8] = ss.as_ref();
    (ct, slice.to_vec())
}

/// A single message-key KDF chain (the symmetric half of the ratchet).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RatchetChain {
    chain_key: Zeroizing<[u8; 32]>,
    index: u64,
}

impl RatchetChain {
    /// Initialise a chain from a 32-byte seed with domain separation.
    fn init(seed: &[u8; 32], context: &str) -> Self {
        Self {
            chain_key: Zeroizing::new(blake3::derive_key(context, seed)),
            index: 0,
        }
    }

    /// Advance the chain and return the message key for this step.
    fn step(&mut self) -> ([u8; 32], u64) {
        let message_key = blake3::derive_key(CTX_MESSAGE_KEY, self.chain_key.as_slice());
        let next = blake3::derive_key(CTX_CHAIN, self.chain_key.as_slice());
        self.chain_key.zeroize();
        *self.chain_key = next;
        let idx = self.index;
        self.index += 1;
        (message_key, idx)
    }
}

/// The encrypted per-message envelope that travels inside a transport chunk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatchetMessage {
    /// New X25519 ratchet public key (set on first send + DH steps).
    #[serde(default)]
    pub ratchet_pk: Option<[u8; 32]>,
    /// New ML-KEM-768 encapsulation key (1184 bytes) — published alongside
    /// `ratchet_pk` so the peer can encapsulate to it on its own DH steps.
    #[serde(default)]
    pub kem_ek: Option<Vec<u8>>,
    /// ML-KEM-768 ciphertext (1088 bytes) — present when the sender took a DH
    /// step (the KEM shared secret is mixed into the root).
    #[serde(default)]
    pub kem_ct: Option<Vec<u8>>,
    pub chain_index: u64,
    pub nonce: [u8; 12],
    pub tag: [u8; 16],
    pub ciphertext: Vec<u8>,
}

/// The double ratchet state for one peer direction pair.
///
/// `is_initiator` controls the initial chain assignment so the initiator's
/// send chain matches the responder's recv chain.
pub struct DoubleRatchet {
    root_key: Zeroizing<[u8; 32]>,
    send_chain: RatchetChain,
    recv_chain: RatchetChain,
    my_dh_secret: Zeroizing<StaticSecret>,
    my_dh_pk: [u8; 32],
    peer_dh_pk: [u8; 32],
    peer_dh_pk_known: bool,
    /// Our ML-KEM decapsulation key (rotated on each DH step).
    my_kem_dk: Option<MlDk768>,
    /// Our ML-KEM encapsulation key (published to the peer).
    my_kem_ek: Option<MlEk768>,
    /// The peer's ML-KEM encapsulation key (learned from its ratchet pks).
    peer_kem_ek: Option<MlEk768>,
    peer_kem_known: bool,
    sends_since_dh: u32,
    sent_any: bool,
    is_initiator: bool,
}

impl DoubleRatchet {
    /// Initialise from the handshake session key (the root key).
    pub fn new(root_key: &[u8; 32], is_initiator: bool) -> Self {
        let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let my_pk: [u8; 32] = X25519PublicKey::from(&secret).to_bytes();
        let (my_kem_dk, my_kem_ek) = fresh_kem();
        // The initiator sends with the "send" chain; the responder sends with
        // the "recv" chain, so the two peers' chains align.
        let (send_ctx, recv_ctx) = Self::chain_contexts(is_initiator);
        Self {
            root_key: Zeroizing::new(*root_key),
            send_chain: RatchetChain::init(root_key, send_ctx),
            recv_chain: RatchetChain::init(root_key, recv_ctx),
            my_dh_secret: Zeroizing::new(secret),
            my_dh_pk: my_pk,
            peer_dh_pk: [0u8; 32],
            peer_dh_pk_known: false,
            my_kem_dk: Some(my_kem_dk),
            my_kem_ek: Some(my_kem_ek),
            peer_kem_ek: None,
            peer_kem_known: false,
            sends_since_dh: 0,
            sent_any: false,
            is_initiator,
        }
    }

    /// Chain contexts for a role: the initiator sends on the "send" chain, the
    /// responder sends on the "recv" chain (mirrored so both peers align).
    fn chain_contexts(is_initiator: bool) -> (&'static str, &'static str) {
        if is_initiator {
            (CTX_INIT_SEND, CTX_INIT_RECV)
        } else {
            (CTX_INIT_RECV, CTX_INIT_SEND)
        }
    }

    /// The current ratchet public key (sent with a DH step, or for debugging).
    pub fn ratchet_public_key(&self) -> [u8; 32] {
        self.my_dh_pk
    }

    /// Debug state for diagnosing decrypt mismatches across peers.
    pub fn debug_state(&self) -> String {
        format!(
            "root={}.. pk_known={} sent_any={} send_idx={} recv_idx={} my_pk={}..",
            Self::hex2(&self.root_key.as_slice()[..2]),
            self.peer_dh_pk_known,
            self.sent_any,
            self.send_chain.index,
            self.recv_chain.index,
            Self::hex2(&self.my_dh_pk[..2]),
        )
    }

    fn hex2(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
}
fn derive_new_root(&mut self, dh_shared: &[u8; 32], kem_shared: Option<&[u8]>) {
        // Mix the DH (and, when present, the ML-KEM) output into the root via a
        // fresh KDF keyed by the old root. An attacker without the KEM shared
        // secret cannot reproduce the new root even with all classical secrets.
        let dh_out = blake3::derive_key(CTX_DH, dh_shared);
        let kem_out = kem_shared.map(|k| blake3::derive_key(CTX_KEM, k));
        let mut input = Zeroizing::new(Vec::with_capacity(
            32 + dh_out.len() + kem_out.as_ref().map_or(0, |k| k.len()),
        ));
        input.extend_from_slice(self.root_key.as_slice());
        input.extend_from_slice(&dh_out);
        if let Some(ko) = kem_out.as_ref() {
            input.extend_from_slice(ko);
        }
        let new_root = blake3::derive_key(CTX_ROOT_MIX, input.as_slice());
        self.root_key.zeroize();
        *self.root_key = new_root;
    }

    /// Take a send-side DH ratchet step: generate a fresh ephemeral secret,
    /// mix `DH(new_secret, peer_pk)` AND a fresh ML-KEM encapsulation into the
    /// root, and reset the send chain. Requires the peer's ratchet key to be
    /// known. Returns the ML-KEM ciphertext to publish with the message.
    fn dh_step_send(&mut self) -> Option<Vec<u8>> {
        let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let pk: [u8; 32] = X25519PublicKey::from(&secret).to_bytes();
        let shared = secret.diffie_hellman(&X25519PublicKey::from(self.peer_dh_pk));
        // Post-quantum component: fresh ML-KEM keypair + encapsulate to the
        // peer's published encapsulation key.
        let (kem_ct, kem_ss) = if let Some(peer_ek) = &self.peer_kem_ek {
            let (dk, ek) = fresh_kem();
            let (ct, ss) = kem_encapsulate(peer_ek);
            self.my_kem_dk = Some(dk);
            self.my_kem_ek = Some(ek);
            (Some(kem_ct_bytes(&ct)), Some(ss))
        } else {
            (None, None)
        };
        self.derive_new_root(shared.as_bytes(), kem_ss.as_deref());
        self.my_dh_secret.zeroize();
        *self.my_dh_secret = secret;
        self.my_dh_pk = pk;
        let (send_ctx, _) = Self::chain_contexts(self.is_initiator);
        self.send_chain = RatchetChain::init(&self.root_key, send_ctx);
        self.sends_since_dh = 0;
        kem_ct
    }

    /// Take a receive-side DH ratchet step when a new peer pk + KEM ciphertext
    /// arrive: mix `DH(my_secret, new_peer_pk)` and the KEM shared secret into
    /// the root and reset the recv chain.
    fn dh_step_recv(&mut self, new_peer_pk: [u8; 32], kem_ct: Option<&[u8]>) {
        let shared = self.my_dh_secret.diffie_hellman(&X25519PublicKey::from(new_peer_pk));
        let kem_ss = kem_ct
            .and_then(kem_ct_from_bytes)
            .and_then(|ct| self.my_kem_dk.as_ref().map(|dk| dk.decapsulate(&ct)))
            .map(|ss| {
                let slice: &[u8] = ss.as_ref();
                slice.to_vec()
            });
        self.derive_new_root(shared.as_bytes(), kem_ss.as_deref());
        self.peer_dh_pk = new_peer_pk;
        let (_, recv_ctx) = Self::chain_contexts(self.is_initiator);
        self.recv_chain = RatchetChain::init(&self.root_key, recv_ctx);
    }

    /// Encrypt `plaintext` under a fresh message key, returning the envelope.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<RatchetMessage, String> {
        // First message: publish our initial ratchet key (X25519 + ML-KEM) so
        // the peer can track future DH steps (no root change yet - chains come
        // from the root). Thereafter: take a DH step every RATCHET_INTERVAL
        // sends once the peer's key is known.
        let mut ratchet_pk = None;
        let mut kem_ek = None;
        let mut kem_ct = None;
        if !self.sent_any {
            self.sent_any = true;
            ratchet_pk = Some(self.my_dh_pk);
            if let Some(ek) = &self.my_kem_ek {
                kem_ek = Some(kem_ek_bytes(ek));
            }
        } else if self.sends_since_dh >= RATCHET_INTERVAL && self.peer_dh_pk_known {
            kem_ct = self.dh_step_send();
            ratchet_pk = Some(self.my_dh_pk);
            if let Some(ek) = &self.my_kem_ek {
                kem_ek = Some(kem_ek_bytes(ek));
            }
        }

        let (message_key, idx) = self.send_chain.step();
        self.sends_since_dh += 1;
        let mut msg = self.encrypt_with(&message_key, idx, plaintext, ratchet_pk)?;
        msg.kem_ek = kem_ek;
        msg.kem_ct = kem_ct;
        Ok(msg)
    }

    fn encrypt_with(
        &self,
        message_key: &[u8; 32],
        idx: u64,
        plaintext: &[u8],
        ratchet_pk: Option<[u8; 32]>,
    ) -> Result<RatchetMessage, String> {
        let cipher = Aes256Gcm::new_from_slice(message_key).map_err(|e| format!("ratchet key: {e}"))?;
        let nonce = nonce_for(idx);
        let aead_nonce = Nonce::<Aes256Gcm>::from_slice(&nonce);
        let mut ct = cipher
            .encrypt(aead_nonce, plaintext)
            .map_err(|e| format!("ratchet encrypt failed: {e:?}"))?;
        // aes-gcm appends the 16-byte tag; split it off.
        let tag: [u8; 16] = ct.split_off(ct.len() - 16).try_into().unwrap_or([0u8; 16]);
        Ok(RatchetMessage {
            ratchet_pk,
            kem_ek: None,
            kem_ct: None,
            chain_index: idx,
            nonce,
            tag,
            ciphertext: ct,
        })
    }

    /// Decrypt an envelope, ratcheting the recv chain first if it carries a
    /// new ratchet public key (and an ML-KEM ciphertext to mix into the root).
    pub fn decrypt(&mut self, msg: &RatchetMessage) -> Result<Vec<u8>, String> {
        if let Some(pk) = msg.ratchet_pk {
            if !self.peer_dh_pk_known {
                // First sight of the peer's key: record it without changing the
                // root (the initial chains are derived from the handshake root).
                self.peer_dh_pk = pk;
                self.peer_dh_pk_known = true;
                if let Some(ek) = msg.kem_ek.as_deref().and_then(kem_ek_from_bytes) {
                    self.peer_kem_ek = Some(ek);
                    self.peer_kem_known = true;
                }
            } else if pk != self.peer_dh_pk {
                self.dh_step_recv(pk, msg.kem_ct.as_deref());
                if let Some(ek) = msg.kem_ek.as_deref().and_then(kem_ek_from_bytes) {
                    self.peer_kem_ek = Some(ek);
                }
            }
        }
        // Advance the recv chain to the message's index (in-order transport).
        let mut mk = [0u8; 32];
        for _ in 0..=msg.chain_index.saturating_sub(self.recv_chain.index).min(1_000_000) {
            let (k, i) = self.recv_chain.step();
            if i == msg.chain_index {
                mk = k;
                break;
            }
        }
        let cipher = Aes256Gcm::new_from_slice(&mk).map_err(|e| format!("ratchet key: {e}"))?;
        let aead_nonce = Nonce::<Aes256Gcm>::from_slice(&msg.nonce);
        let mut ct = msg.ciphertext.clone();
        ct.extend_from_slice(&msg.tag);
        cipher
            .decrypt(aead_nonce, ct.as_slice())
            .map_err(|_| "ratchet decrypt: authentication failed".to_string())
    }
}

/// Deterministic per-message nonce from the chain index (fresh key each step,
/// so a fixed-derivation nonce is safe — matching the lane's scheme).
fn nonce_for(idx: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&idx.to_be_bytes());
    n
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> [u8; 32] {
        [0x42u8; 32]
    }

    #[test]
    fn chains_advance_independently() {
        let mut chain = RatchetChain::init(&root(), CTX_INIT_SEND);
        let (k1, i1) = chain.step();
        let (k2, i2) = chain.step();
        assert_eq!(i1, 0);
        assert_eq!(i2, 1);
        assert_ne!(k1, k2);
    }

    #[test]
    fn single_message_roundtrip_carries_initial_key() {
        let mut alice = DoubleRatchet::new(&root(), true);
        let mut bob = DoubleRatchet::new(&root(), false);

        // First message publishes Alice's initial ratchet key.
        let msg = alice.encrypt(b"hello ratchet").unwrap();
        assert!(msg.ratchet_pk.is_some(), "first message publishes the ratchet key");
        let plain = bob.decrypt(&msg).unwrap();
        assert_eq!(plain, b"hello ratchet");

        // Bob's first reply publishes his key so Alice can ratchet later.
        let reply = bob.encrypt(b"hello back").unwrap();
        assert!(reply.ratchet_pk.is_some());
        assert_eq!(alice.decrypt(&reply).unwrap(), b"hello back");
    }

    #[test]
    fn multi_message_roundtrip_without_dh_steps() {
        let mut alice = DoubleRatchet::new(&root(), true);
        let mut bob = DoubleRatchet::new(&root(), false);
        // Exchange initial keys.
        bob.decrypt(&alice.encrypt(b"init").unwrap()).unwrap();
        alice.decrypt(&bob.encrypt(b"init-reply").unwrap()).unwrap();

        for i in 0..(RATCHET_INTERVAL - 1) {
            let payload = format!("message-{i}").into_bytes();
            let msg = alice.encrypt(&payload).unwrap();
            assert!(msg.ratchet_pk.is_none());
            let plain = bob.decrypt(&msg).unwrap();
            assert_eq!(plain, payload);
        }
    }

    #[test]
    fn dh_ratchet_resets_and_reciprocates_bidirectionally() {
        let mut alice = DoubleRatchet::new(&root(), true);
        let mut bob = DoubleRatchet::new(&root(), false);

        let mut saw_dh_step = false;
        let mut n = 0u64;
        for _round in 0..4 {
            for i in 0..RATCHET_INTERVAL {
                let payload = format!("a-{n}-{i}").into_bytes();
                let msg = alice.encrypt(&payload).unwrap();
                if msg.ratchet_pk.is_some() && !alice.peer_dh_pk_known {
                    // First message only - Alice hasn't seen Bob's key yet.
                    assert_eq!(n, 0, "first message carries the initial key");
                }
                if msg.ratchet_pk.is_some() && alice.peer_dh_pk_known {
                    saw_dh_step = true;
                }
                assert_eq!(bob.decrypt(&msg).unwrap(), payload, "a-{n}-{i} must survive");
            }
            // Bob replies (his first reply publishes his key, which lets
            // Alice's counter-based DH ratchet begin).
            let reply = format!("b-{n}").into_bytes();
            let rmsg = bob.encrypt(&reply).unwrap();
            assert_eq!(alice.decrypt(&rmsg).unwrap(), reply);
            n += 1;
        }
        assert!(saw_dh_step, "a real DH ratchet step must have occurred");
    }

    #[test]
    fn tampered_message_is_rejected() {
        let mut alice = DoubleRatchet::new(&root(), true);
        let mut bob = DoubleRatchet::new(&root(), false);
        bob.decrypt(&alice.encrypt(b"init").unwrap()).unwrap();
        alice.decrypt(&bob.encrypt(b"init-reply").unwrap()).unwrap();

        let mut msg = alice.encrypt(b"secret").unwrap();
        msg.ciphertext[0] ^= 0xff;
        assert!(bob.decrypt(&msg).is_err(), "tampered ciphertext must fail auth");
    }

    #[test]
    fn compromised_root_cannot_decrypt_after_dh_ratchet() {
        // Future secrecy: once a DH ratchet has occurred, a ratchet built from
        // the ORIGINAL (compromised) root cannot decrypt post-ratchet messages.
        let mut alice = DoubleRatchet::new(&root(), true);
        let mut bob = DoubleRatchet::new(&root(), false);
        bob.decrypt(&alice.encrypt(b"init").unwrap()).unwrap();
        alice.decrypt(&bob.encrypt(b"init-reply").unwrap()).unwrap();

        // Force a DH step on Alice's side, capturing the message that carries it.
        let mut post = None;
        for _ in 0..RATCHET_INTERVAL {
            let msg = alice.encrypt(b"pre-ratchet").unwrap();
            if msg.ratchet_pk.is_some() {
                post = Some(msg.clone());
            }
            assert_eq!(bob.decrypt(&msg).unwrap(), b"pre-ratchet");
        }
        let post = post.expect("a DH step must have occurred");
        assert!(post.ratchet_pk.is_some());

        // A fresh ratchet with the ORIGINAL root must fail to decrypt it.
        let mut attacker = DoubleRatchet::new(&root(), false);
        // It learns the published key but cannot reconstruct the DH-mixed root.
        assert!(attacker.decrypt(&post).is_err(), "compromised root cannot decrypt post-ratchet traffic");
    }

    #[test]
    fn role_asymmetry_matches_chains() {
        let mut initiator = DoubleRatchet::new(&root(), true);
        let mut responder = DoubleRatchet::new(&root(), false);

        // Initiator->Responder works (initiator send chain == responder recv).
        let msg = initiator.encrypt(b"from initiator").unwrap();
        assert_eq!(responder.decrypt(&msg).unwrap(), b"from initiator");

        // Responder->Initiator works (responder send chain == initiator recv).
        let msg2 = responder.encrypt(b"from responder").unwrap();
        assert_eq!(initiator.decrypt(&msg2).unwrap(), b"from responder");
    }

    #[test]
    fn first_messages_publish_mlkem_keys() {
        let mut alice = DoubleRatchet::new(&root(), true);
        let mut bob = DoubleRatchet::new(&root(), false);
        let m1 = alice.encrypt(b"a").unwrap();
        assert!(m1.kem_ek.is_some(), "first message publishes the ML-KEM ek");
        bob.decrypt(&m1).unwrap();
        let m2 = bob.encrypt(b"b").unwrap();
        assert!(m2.kem_ek.is_some());
        alice.decrypt(&m2).unwrap();
    }

    #[test]
    fn pq_dh_step_carries_kem_ciphertext_and_decrypts() {
        let mut alice = DoubleRatchet::new(&root(), true);
        let mut bob = DoubleRatchet::new(&root(), false);
        bob.decrypt(&alice.encrypt(b"a1").unwrap()).unwrap();
        alice.decrypt(&bob.encrypt(b"b1").unwrap()).unwrap();

        let mut saw_kem_ct = false;
        for i in 0..(RATCHET_INTERVAL + 2) {
            let m = alice.encrypt(format!("a{i}").as_bytes()).unwrap();
            if m.kem_ct.is_some() {
                assert!(m.kem_ek.is_some(), "DH step publishes a fresh ML-KEM ek");
                saw_kem_ct = true;
            }
            assert_eq!(bob.decrypt(&m).unwrap(), format!("a{i}").as_bytes());
        }
        assert!(saw_kem_ct, "a DH ratchet step must carry an ML-KEM ciphertext");
    }

    #[test]
    fn kem_mix_blocks_classical_only_future_secrecy() {
        // Post-quantum future secrecy: an attacker holding ALL classical
        // material (the pre-ratchet root + the X25519 DH shared secret) cannot
        // reproduce the post-DH root, because the real root also mixes an
        // ML-KEM shared secret it does not have. Therefore its message keys
        // differ from the real ones.
        let dh_ss = [6u8; 32];
        let mut real = DoubleRatchet::new(&root(), true);
        let mut classical = DoubleRatchet::new(&root(), true);
        real.derive_new_root(&dh_ss, Some(&[9u8; 32]));
        classical.derive_new_root(&dh_ss, None);
        assert_ne!(real.root_key.as_slice(), classical.root_key.as_slice());
        // A DH step resets the send chain from the new root; do the same here
        // so the message keys reflect the (different) roots.
        let (send_ctx, _) = DoubleRatchet::chain_contexts(true);
        real.send_chain = RatchetChain::init(&real.root_key, send_ctx);
        classical.send_chain = RatchetChain::init(&classical.root_key, send_ctx);
        let (real_key, _) = real.send_chain.step();
        let (classical_key, _) = classical.send_chain.step();
        assert_ne!(real_key, classical_key, "classical-only keys must differ from the KEM-mixed keys");
    }
}