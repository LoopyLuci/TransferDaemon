//! Writes `vectors/crypto.json`: fixed inputs with the outputs the reference implementation gives
//! for them. The Python and TypeScript implementations check their own results against this file.
//!
//! Run from the repository root:
//!
//!     cargo run -p transferd-crypto --example gen_crypto_vectors -- vectors/crypto.json
//!
//! Everything here is deterministic except the handshake flights, which carry fresh ephemeral keys
//! on every run. Those vectors are checked for their signatures, not for fixed bytes.

use std::fmt::Write as _;

use ml_kem::{
    B32, Decapsulate, Seed,
    ml_kem_768::{DecapsulationKey as MlDk768, EncapsulationKey as MlEk768},
};
use transferd_crypto::auth_handshake::{
    AuthInitiatorHello, AuthResponderHello, CIPHERSUITE_HYBRID_X25519_MLKEM768, PROTOCOL_VERSION,
};
use transferd_crypto::handshake::{Initiator, Responder};
use transferd_crypto::identity::HybridSigningKey;

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// A recognisable, non-trivial byte pattern.
fn pattern<const N: usize>(tag: u8) -> [u8; N] {
    let mut out = [0u8; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(tag);
    }
    out
}

fn main() {
    let out_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "vectors/crypto.json".to_string());

    // --- BLAKE3 -----------------------------------------------------------------------------
    let blake_input = pattern::<100>(1);
    let blake_hash = blake3::hash(&blake_input);
    let blake_key = pattern::<32>(2);
    let blake_keyed = blake3::keyed_hash(&blake_key, &blake_input);
    let kdf_context = "TransferDaemon-overlay-c2s-v1";
    let kdf_input = pattern::<32>(3);
    let kdf_out = blake3::derive_key(kdf_context, &kdf_input);

    // --- ML-KEM-768 (FIPS 203) ----------------------------------------------------------------
    let kem_seed_bytes = pattern::<64>(4);
    let kem_seed: Seed = kem_seed_bytes.into();
    let dk = MlDk768::from_seed(kem_seed);
    let ek: MlEk768 = dk.encapsulation_key().clone();
    let ek_bytes = <MlEk768 as kem::KeyExport>::to_bytes(&ek);
    let m_bytes = pattern::<32>(5);
    let m: B32 = m_bytes.into();
    let (ct, ss) = ek.encapsulate_deterministic(&m);
    let ss_check = dk.decapsulate(&ct);
    let (ss_a, ss_b): (&[u8], &[u8]) = (ss.as_ref(), ss_check.as_ref());
    assert_eq!(ss_a, ss_b, "reference ML-KEM must round-trip");

    // --- Hybrid identity (Ed25519 + ML-DSA-87) ------------------------------------------------
    let id_seed = pattern::<64>(6);
    let sk = HybridSigningKey::from_bip39_seed(&id_seed);
    let vk = sk.verifying_key().to_bytes();
    let node_id = hex(&vk[..32]);
    let relay_token = blake3::derive_key("transferd-overlay-relay-token-v1", node_id.as_bytes());
    let fingerprint = blake3::derive_key("TransferDaemon-overlay-key-fingerprint-v1", &vk);
    let sign_message = b"transferd identity vector";
    let hybrid_sig = sk.sign(sign_message).to_bytes();
    let ed_message = b"transferd ed25519 vector";
    let ed_sig = sk.sign_ed25519(ed_message);

    // --- Handshake flights ------------------------------------------------------------------
    let a_seed = pattern::<64>(8);
    let b_seed = pattern::<64>(9);
    let a = HybridSigningKey::from_bip39_seed(&a_seed);
    let b = HybridSigningKey::from_bip39_seed(&b_seed);
    let a_node = hex(&a.verifying_key().to_bytes()[..32]);
    let b_node = hex(&b.verifying_key().to_bytes()[..32]);
    let init = Initiator::new();
    let init_flight = AuthInitiatorHello::build(
        &init,
        PROTOCOL_VERSION,
        CIPHERSUITE_HYBRID_X25519_MLKEM768,
        &a,
    )
    .to_wire();
    let (resp_hello, _key) = Responder::new().respond(&init.hello());
    let resp_flight = AuthResponderHello::build(
        &resp_hello,
        PROTOCOL_VERSION,
        CIPHERSUITE_HYBRID_X25519_MLKEM768,
        &b,
    )
    .to_wire();
    let mut tampered = resp_flight.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;

    let json = format!(
        r#"{{
  "blake3": {{
    "hash": {{"input": "{bi}", "output": "{bh}"}},
    "keyed": {{"key": "{bk}", "input": "{bi}", "output": "{bkd}"}},
    "derive_key": {{"context": "{ctx}", "input": "{kin}", "output": "{kout}"}}
  }},
  "mlkem768": {{
    "seed": "{ks}",
    "encapsulation_key": "{ek}",
    "m": "{mm}",
    "ciphertext": "{ct}",
    "shared_secret": "{ss}"
  }},
  "identity": {{
    "seed": "{ids}",
    "node_id": "{nid}",
    "hybrid_public_key": "{hpk}",
    "relay_token": "{rt}",
    "key_fingerprint": "{fp}",
    "sign": {{"message": "{sm}", "signature": "{hs}"}},
    "ed25519_sign": {{"message": "{em}", "signature": "{es}"}}
  }},
  "handshake": {{
    "initiator": {{"seed": "{as_}", "node_id": "{anode}", "flight": "{ifl}"}},
    "responder": {{"seed": "{bs}", "node_id": "{bnode}", "flight": "{rfl}"}},
    "tampered_responder_flight": "{tfl}"
  }}
}}
"#,
        bi = hex(&blake_input),
        bh = hex(blake_hash.as_bytes()),
        bk = hex(&blake_key),
        bkd = hex(blake_keyed.as_bytes()),
        ctx = kdf_context,
        kin = hex(&kdf_input),
        kout = hex(&kdf_out),
        ks = hex(&kem_seed_bytes),
        ek = hex(ek_bytes.as_ref()),
        mm = hex(&m_bytes),
        ct = hex(ct.as_ref()),
        ss = hex(ss.as_ref()),
        ids = hex(&id_seed),
        nid = node_id,
        hpk = hex(&vk),
        rt = hex(&relay_token),
        fp = hex(&fingerprint),
        sm = hex(sign_message),
        hs = hex(&hybrid_sig),
        em = hex(ed_message),
        es = hex(&ed_sig),
        as_ = hex(&a_seed),
        anode = a_node,
        ifl = hex(&init_flight),
        bs = hex(&b_seed),
        bnode = b_node,
        rfl = hex(&resp_flight),
        tfl = hex(&tampered),
    );

    if let Some(dir) = std::path::Path::new(&out_path).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    std::fs::write(&out_path, json).expect("write vectors");
    println!("wrote {out_path}");
}
