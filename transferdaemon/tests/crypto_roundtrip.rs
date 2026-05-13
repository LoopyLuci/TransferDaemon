use ring_channel::{Consumer, Doorbell, MappedRegion, Producer};
use transferd_crypto::{DmiDecryptor, DmiEncryptor};
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

/// End-to-end test: encrypt into a MappedRegion via Producer, read back via Consumer,
/// decrypt with DmiDecryptor, and assert the plaintext matches the original.
#[tokio::test]
async fn test_aes256gcm_encrypt_decrypt_roundtrip() {
    let descriptor_count = 64usize;
    let data_size = 512 * 1024; // 512 KiB

    let region = Arc::new(
        MappedRegion::new_mirrored(descriptor_count, data_size).expect("MappedRegion"),
    );
    let doorbell = Arc::new(Doorbell::new().expect("Doorbell"));
    let prod_idx = Arc::new(AtomicU64::new(0));
    let cons_idx = Arc::new(AtomicU64::new(0));

    let mut producer = Producer::new(
        region.clone(), doorbell.clone(),
        prod_idx.clone(), cons_idx.clone(),
        descriptor_count,
    );
    let mut consumer = Consumer::new(
        region.clone(), doorbell.clone(),
        prod_idx.clone(), cons_idx.clone(),
        descriptor_count,
    );

    // Fixed 32-byte AES key (in production, derived from the KEM handshake).
    let key: [u8; 32] = [0x42u8; 32];
    let mut encryptor = DmiEncryptor::new(&key);
    let decryptor = DmiDecryptor::new(&key);

    let gsn: u64 = 7;
    let epoch: u8 = 0;
    let plaintext = b"Hello, TransferDaemon! This is an AES-256-GCM roundtrip test payload.";

    // Build AAD matching what DmiSenderLane produces.
    let mut aad = [0u8; 16];
    aad[..8].copy_from_slice(&gsn.to_le_bytes());
    aad[8..16].copy_from_slice(&(gsn + plaintext.len() as u64).to_le_bytes());

    // --- Producer: encrypt directly into the grant buffer. ---
    let mut grant = producer.reserve_grant(plaintext.len()).await.expect("reserve_grant");
    let dst = unsafe { grant.as_slice_mut() };
    let result = unsafe { encryptor.encrypt_fused(plaintext, dst, gsn, epoch, &aad) };

    producer.commit_grant(
        grant,
        gsn,
        gsn + plaintext.len() as u64,
        &result.nonce,
        &result.gcm_tag,
        &result.blake3_hash,
        epoch,
    );

    // --- Consumer: read the ciphertext and descriptor. ---
    let read_grant = consumer.read_grant().await.expect("read_grant");
    assert_eq!(read_grant.desc.gsn_start, gsn);
    assert_eq!(read_grant.desc.key_epoch, epoch);
    assert_eq!(read_grant.desc.nonce, result.nonce);
    assert_eq!(read_grant.desc.gcm_tag, result.gcm_tag);
    assert_eq!(read_grant.desc.blake3_hash, result.blake3_hash);

    // Copy ciphertext out of the read grant for in-place decryption.
    let mut ct = read_grant.buf.to_vec();
    let nonce = read_grant.desc.nonce;
    let tag = read_grant.desc.gcm_tag;
    consumer.release_grant();

    // --- Decryptor: verify tag and recover plaintext. ---
    let recovered_hash = decryptor
        .decrypt_verify(&mut ct, &nonce, &tag, &aad)
        .expect("decrypt_verify");

    assert_eq!(&ct, plaintext.as_ref(), "decrypted plaintext must match original");

    // BLAKE3 of recovered plaintext must match the hash stored in the descriptor.
    assert_eq!(recovered_hash, result.blake3_hash, "BLAKE3 hash mismatch");

    println!("AES-256-GCM roundtrip test passed.");
}

/// Verify that a tampered ciphertext fails authentication.
#[tokio::test]
async fn test_tampered_ciphertext_rejected() {
    let key: [u8; 32] = [0x99u8; 32];
    let encryptor_key = key;
    let decryptor = DmiDecryptor::new(&key);
    let mut encryptor = DmiEncryptor::new(&encryptor_key);

    let plaintext = b"secret data";
    let mut buf = vec![0u8; plaintext.len()];
    let gsn = 1u64;
    let epoch = 0u8;
    let aad = [];

    let result = unsafe { encryptor.encrypt_fused(plaintext, &mut buf, gsn, epoch, &aad) };

    // Flip one bit in the ciphertext.
    buf[0] ^= 0x01;

    let err = decryptor.decrypt_verify(&mut buf, &result.nonce, &result.gcm_tag, &aad);
    assert!(err.is_err(), "tampered ciphertext must not authenticate");
    println!("Tamper-detection test passed.");
}
