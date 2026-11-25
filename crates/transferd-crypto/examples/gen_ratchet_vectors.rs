//! Writes `vectors/ratchet.json`: the message keys and envelopes a double ratchet gives for a fixed root.
//! The Python and TypeScript ratchets open these messages with the same root, so the chain derivation, the nonce
//! and the AES-256-GCM envelope are checked against the reference.
//!
//! The sender never gets a reply here, so it never takes a DH step: every message comes off the send chain, which is
//! fixed by the root. The DH steps are random (fresh X25519 and ML-KEM keys) and are tested by round trips instead.
//!
//! Run from the repository root:
//!
//!     cargo run -p transferd-crypto --example gen_ratchet_vectors -- vectors/ratchet.json

use std::fmt::Write as _;

use transferd_crypto::ratchet::DoubleRatchet;

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn opt(bytes: Option<&[u8]>) -> String {
    match bytes {
        Some(b) => format!("\"{}\"", hex(b)),
        None => "null".into(),
    }
}

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| "vectors/ratchet.json".into());
    let root: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));

    let mut alice = DoubleRatchet::new(&root, true);
    let mut entries = Vec::new();
    for i in 0..25u32 {
        let plaintext = format!("ratchet message {i}").into_bytes();
        let msg = alice.encrypt(&plaintext).expect("encrypt");
        assert!(msg.kem_ct.is_none(), "no DH step without a reply");
        entries.push(format!(
            "    {{\"plaintext\": \"{}\", \"chain_index\": {}, \"ratchet_pk\": {}, \"kem_ek\": {}, \"nonce\": \"{}\", \"tag\": \"{}\", \"ciphertext\": \"{}\"}}",
            hex(&plaintext),
            msg.chain_index,
            opt(msg.ratchet_pk.as_ref().map(|p| p.as_slice())),
            opt(msg.kem_ek.as_deref()),
            hex(&msg.nonce),
            hex(&msg.tag),
            hex(&msg.ciphertext),
        ));
    }

    let json = format!("{{\n  \"root\": \"{}\",\n  \"messages\": [\n{}\n  ]\n}}\n", hex(&root), entries.join(",\n"));
    if let Some(dir) = std::path::Path::new(&path).parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).expect("create the vectors directory");
    }
    std::fs::write(&path, json).expect("write the ratchet vectors");
    println!("wrote {path}");
}
