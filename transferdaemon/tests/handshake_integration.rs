use transferd_crypto::{
    DmiDecryptor, DmiEncryptor,
    handshake::{Initiator, Responder},
};

/// Both sides must derive the same session key.
#[test]
fn test_handshake_key_agreement() {
    let initiator = Initiator::new();
    let responder = Responder::new();

    let hello = initiator.hello();
    let (resp_hello, resp_key) = responder.respond(&hello);
    let init_key = initiator.finalize(resp_hello);

    assert_eq!(
        init_key.as_bytes(),
        resp_key.as_bytes(),
        "session keys must match on both sides"
    );
    println!("Handshake key-agreement test passed.");
}

/// Two independent handshakes must produce different session keys (forward secrecy).
#[test]
fn test_handshake_sessions_differ() {
    let (init1, resp1) = run_handshake();
    let (init2, resp2) = run_handshake();

    assert_ne!(init1.as_bytes(), init2.as_bytes(), "keys must differ across sessions");
    assert_ne!(resp1.as_bytes(), resp2.as_bytes(), "keys must differ across sessions");
    println!("Session-uniqueness test passed.");
}

fn run_handshake() -> (
    transferd_crypto::handshake::SessionKey,
    transferd_crypto::handshake::SessionKey,
) {
    let init = Initiator::new();
    let resp = Responder::new();
    let hello = init.hello();
    let (resp_hello, resp_key) = resp.respond(&hello);
    let init_key = init.finalize(resp_hello);
    (init_key, resp_key)
}

/// End-to-end: perform a handshake, then use the session keys to encrypt/decrypt.
#[test]
fn test_handshake_then_encrypt_decrypt() {
    let init = Initiator::new();
    let resp = Responder::new();
    let hello = init.hello();
    let (resp_hello, resp_key) = resp.respond(&hello);
    let init_key = init.finalize(resp_hello);

    // Sender uses initiator's key; receiver uses responder's key (they are equal).
    let mut encryptor = DmiEncryptor::from_session_key(&init_key);
    let decryptor = DmiDecryptor::from_session_key(&resp_key);

    let plaintext = b"Post-quantum zero-copy transfer payload.";
    let mut ct = vec![0u8; plaintext.len()];

    let result = unsafe { encryptor.encrypt_fused(plaintext, &mut ct, 42, 0, &[]) };

    let recovered_hash = decryptor
        .decrypt_verify(&mut ct, &result.nonce, &result.gcm_tag, &[])
        .expect("decrypt_verify must succeed");

    assert_eq!(&ct, plaintext.as_ref(), "plaintext must be recovered");
    assert_eq!(recovered_hash, result.blake3_hash, "BLAKE3 hash must match");

    println!("Handshake-then-encrypt-decrypt test passed.");
}
