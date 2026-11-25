//! Writes `vectors/ghost.json`: a ghost key certificate from a fresh issuer, and a relay registration that carries it.
//! The Python and TypeScript implementations check their certificate and their relay codec against this file.
//!
//! Run from the repository root:
//!
//!     cargo run -p relayd --example gen_ghost_vectors -- vectors/ghost.json
//!
//! The issuer key, the ghost key and the blinding are fresh on every run, so the file is checked for what it says
//! (the certificate verifies, the registration's signature verifies), not for fixed bytes. `ghost_secret` is a test
//! fixture: it is the seed of a throwaway ghost key.

use std::fmt::Write as _;

use relayd::ghost::{binding, ghost_register};
use relayd::protocol::RegisterMsg;
use transferd_crypto::ghostkey::{GhostKey, Issuer};

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| "vectors/ghost.json".into());

    let issuer = Issuer::generate("test relay", "supporter", 2048).expect("a 2048-bit issuer key");
    let me = GhostKey::generate();
    let (blinded, state) = me.blind_request(&issuer.public).expect("blind");
    let blind_sig = issuer.sign_blinded(&blinded).expect("the issuer signs the blinded value");
    let cert = me.finish(&issuer.public, state, &blind_sig).expect("unblind and check");
    cert.verify(&issuer.public).expect("the certificate verifies");

    let token: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(13).wrapping_add(5));
    let (pow_nonce, seq) = (7u64, 3u32);
    let msg = ghost_register(RegisterMsg { session_token: token, pow_nonce, seq }, &cert, &me);
    let body = bincode::serialize(&msg).expect("the registration serialises");
    let cert_bytes = bincode::serialize(&cert).expect("the certificate serialises");
    let bound = binding(&token, seq);

    let json = format!(
        "{{\n\
  \"issuer\": {{\"name\": \"{name}\", \"tier\": \"{tier}\", \"id\": \"{id}\", \"spki\": \"{spki}\", \"public_text\": \"{public_text}\"}},\n\
  \"ghost_secret\": \"{secret}\",\n\
  \"certificate\": {{\"text\": \"{cert_text}\", \"bincode\": \"{cert_bincode}\", \"issuer_id\": \"{id}\", \"tier\": \"{tier}\", \"ghost_public\": \"{ghost_public}\", \"prefix\": \"{prefix}\", \"signature\": \"{sig}\"}},\n\
  \"registration\": {{\"session_token\": \"{token}\", \"pow_nonce\": {pow_nonce}, \"seq\": {seq}, \"binding\": \"{bound}\", \"signature\": \"{reg_sig}\", \"body\": \"{body}\"}}\n\
}}\n",
        name = issuer.public.name,
        tier = issuer.public.tier,
        id = issuer.public.id(),
        spki = hex(&issuer.public.spki),
        public_text = issuer.public.to_text(),
        secret = hex(&me.secret()),
        cert_text = cert.to_text(),
        cert_bincode = hex(&cert_bytes),
        ghost_public = hex(&cert.ghost_public),
        prefix = hex(&cert.prefix),
        sig = hex(&cert.signature),
        token = hex(&token),
        bound = hex(&bound),
        reg_sig = hex(&msg.signature),
        body = hex(&body),
    );

    if let Some(dir) = std::path::Path::new(&path).parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).expect("create the vectors directory");
    }
    std::fs::write(&path, json).expect("write the ghost vectors");
    println!("wrote {path}");
}
