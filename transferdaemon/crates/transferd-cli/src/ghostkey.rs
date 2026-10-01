//! `transferd-cli ghostkey ...`: anonymous, vouched-for identities (transferd_crypto::ghostkey), offline: no daemon.
//!
//!   ghostkey issuer-new <name> <tier> <file-prefix> [--bits 3072]
//!       writes <prefix>.issuer-secret (keep it private) and <prefix>.issuer (publish it)
//!   ghostkey request <issuer-file> <pending-file>
//!       makes a ghost key, prints the blinded request for the issuer, keeps the pending state (private)
//!   ghostkey sign <issuer-secret-file> <blinded-hex>
//!       the issuer's side: prints the blind signature (it never learns the key it vouches for)
//!   ghostkey finish <issuer-file> <pending-file> <blind-signature-hex> <out-file>
//!       unblinds into a certificate; writes the certificate and the ghost key's secret to <out-file>
//!   ghostkey verify <issuer-file> <certificate-text | certificate-file>

use serde_json::{json, Value};
use std::path::Path;
use transferd_crypto::ghostkey::{BlindState, GhostCertificate, GhostKey, Issuer, IssuerPublic};

fn read(path: &str) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))
}

fn write_private(path: &Path, text: &str) -> Result<(), String> {
    if path.exists() {
        return Err(format!("{} exists; not overwriting it", path.display()));
    }
    std::fs::write(path, text).map_err(|e| format!("{}: {e}", path.display()))
}

fn arg_or_file(s: &str) -> Result<String, String> {
    if Path::new(s).is_file() { read(s) } else { Ok(s.to_string()) }
}

pub fn run(rest: &[String]) -> Result<Value, String> {
    let need = |n: usize, usage: &str| if rest.len() < n { Err(format!("usage: transferd-cli ghostkey {usage}")) } else { Ok(()) };
    let e = |x: transferd_crypto::ghostkey::GhostKeyError| x.to_string();
    match rest.first().map(String::as_str) {
        Some("issuer-new") => {
            need(4, "issuer-new <name> <tier> <file-prefix> [--bits 3072]")?;
            let bits = rest.iter().position(|a| a == "--bits").and_then(|i| rest.get(i + 1)).and_then(|b| b.parse().ok()).unwrap_or(3072);
            let iss = Issuer::generate(&rest[1], &rest[2], bits).map_err(e)?;
            let secret = format!("{}.issuer-secret", rest[3]);
            let public = format!("{}.issuer", rest[3]);
            write_private(Path::new(&secret), &iss.to_secret_text().map_err(e)?)?;
            write_private(Path::new(&public), &(iss.public.to_text() + "\n"))?;
            Ok(json!({"issuer": iss.public.id(), "name": iss.public.name, "tier": iss.public.tier, "bits": bits,
                      "secret_file": secret, "public_file": public}))
        }
        Some("request") => {
            need(3, "request <issuer-file> <pending-file>")?;
            let issuer = IssuerPublic::from_text(&read(&rest[1])?).map_err(e)?;
            let me = GhostKey::generate();
            let (blinded, state) = me.blind_request(&issuer).map_err(e)?;
            write_private(Path::new(&rest[2]), &state.to_text(&me))?;
            Ok(json!({"issuer": issuer.id(), "tier": issuer.tier, "pending_file": rest[2],
                      "blinded_request": hex_encode(&blinded),
                      "next": "send blinded_request to the issuer; they answer with `ghostkey sign`"}))
        }
        Some("sign") => {
            need(3, "sign <issuer-secret-file> <blinded-hex>")?;
            let iss = Issuer::from_secret_text(&read(&rest[1])?).map_err(e)?;
            let blinded = hex_decode(&arg_or_file(&rest[2])?)?;
            Ok(json!({"issuer": iss.public.id(), "blind_signature": hex_encode(&iss.sign_blinded(&blinded).map_err(e)?)}))
        }
        Some("finish") => {
            need(5, "finish <issuer-file> <pending-file> <blind-signature-hex> <out-file>")?;
            let issuer = IssuerPublic::from_text(&read(&rest[1])?).map_err(e)?;
            let (state, me) = BlindState::from_text(&read(&rest[2])?).map_err(e)?;
            let sig = hex_decode(&arg_or_file(&rest[3])?)?;
            let cert = me.finish(&issuer, state, &sig).map_err(e)?;
            write_private(Path::new(&rest[4]), &format!("{}\ntransferd-ghostsecret-v1:{}\n", cert.to_text(), hex_encode(&me.secret())))?;
            let _ = std::fs::remove_file(&rest[2]);
            Ok(json!({"issuer": issuer.id(), "tier": cert.tier, "ghost_key": hex_encode(&cert.ghost_public),
                      "certificate": cert.to_text(), "saved": rest[4]}))
        }
        Some("verify") => {
            need(3, "verify <issuer-file> <certificate>")?;
            let issuer = IssuerPublic::from_text(&read(&rest[1])?).map_err(e)?;
            let text = arg_or_file(&rest[2])?;
            let line = text.lines().find(|l| l.starts_with("transferd-ghostcert-v1:")).unwrap_or(text.trim());
            let cert = GhostCertificate::from_text(line).map_err(e)?;
            cert.verify(&issuer).map_err(e)?;
            Ok(json!({"valid": true, "issuer": issuer.id(), "issuer_name": issuer.name, "tier": cert.tier,
                      "ghost_key": hex_encode(&cert.ghost_public)}))
        }
        _ => Err("ghostkey issuer-new | request | sign | finish | verify (see `transferd-cli help`)".into()),
    }
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) || !s.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err("expected hex".into());
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string())).collect()
}
