//! Benchmarks for the transport data path: the AES-256-GCM lane crypto
//! (DMI fused encrypt/decrypt, which is what `TcpLane`/`RelayLane` use) and
//! the `WireChunk` envelope codec. Run with `cargo bench -p transferd-core`.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use transferd_core::transport::WireChunk;
use transferd_crypto::{DmiDecryptor, DmiEncryptor};

fn bench_lane_encrypt(c: &mut Criterion) {
    let key = [0x42u8; 32];
    let enc = DmiEncryptor::new(&key);
    let nonce = DmiEncryptor::nonce_for(1, 0);

    for size in [1024usize, 16 * 1024, 64 * 1024] {
        let mut buf = vec![0xABu8; size];
        c.bench_function(&format!("lane_encrypt_{size}_bytes"), |b| {
            b.iter(|| {
                let mut v = black_box(buf.clone());
                let tag = enc.encrypt_detached(&mut v, &nonce, &[0u8; 8]).unwrap();
                black_box((v, tag))
            })
        });
    }
}

fn bench_lane_decrypt(c: &mut Criterion) {
    let key = [0x42u8; 32];
    let enc = DmiEncryptor::new(&key);
    let dec = DmiDecryptor::new(&key);
    let nonce = DmiEncryptor::nonce_for(1, 0);

    for size in [1024usize, 16 * 1024, 64 * 1024] {
        let mut ct = vec![0xABu8; size];
        let tag = enc.encrypt_detached(&mut ct, &nonce, &[0u8; 8]).unwrap();
        let aad = (ct.len() as u64).to_le_bytes();
        c.bench_function(&format!("lane_decrypt_{size}_bytes"), |b| {
            b.iter(|| {
                let mut v = black_box(ct.clone());
                let ok = dec.decrypt_verify(&mut v, &nonce, &tag, &aad).is_ok();
                black_box((v, ok))
            })
        });
    }
}

fn bench_wire_chunk_codec(c: &mut Criterion) {
    for size in [256usize, 4096, 64 * 1024] {
        let chunk = WireChunk {
            gsn: 42,
            session_id: [7u8; 16],
            payload: vec![0xCDu8; size],
            key_epoch: 0,
            qos_critical: true,
        };
        c.bench_function(&format!("wire_chunk_encode_{size}"), |b| {
            b.iter(|| black_box(bincode::serialize(&chunk).unwrap()))
        });
        let encoded = bincode::serialize(&chunk).unwrap();
        c.bench_function(&format!("wire_chunk_decode_{size}"), |b| {
            b.iter(|| black_box(bincode::deserialize::<WireChunk>(&encoded).unwrap()))
        });
    }
}

criterion_group!(
    benches,
    bench_lane_encrypt,
    bench_lane_decrypt,
    bench_wire_chunk_codec
);
criterion_main!(benches);