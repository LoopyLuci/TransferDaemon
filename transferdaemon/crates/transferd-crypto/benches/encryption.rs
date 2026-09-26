use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_encryption(c: &mut Criterion) {
    let key = [0x42u8; 32];
    let plaintext = vec![0xABu8; 65536]; // 64KB

    c.bench_function("aes_gcm_encrypt_64kb", |b| {
        b.iter(|| {
            let (nonce, ciphertext) = aes_gcm::aead::Aead::encrypt(
                &aes_gcm::Aes256Gcm::new_from_slice(&key).unwrap(),
                &aes_gcm::Nonce::from_slice(&[0u8; 12]),
                black_box(&plaintext),
            )
            .unwrap();
            black_box(ciphertext)
        })
    });
}

criterion_group!(benches, bench_encryption);
criterion_main!(benches);
