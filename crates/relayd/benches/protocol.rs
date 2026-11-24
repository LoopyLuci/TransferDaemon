use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_protocol_encode_decode(c: &mut Criterion) {
    let payload = vec![0xABu8; 1400]; // Typical UDP MTU
    let msg = relayd::protocol::ForwardMsg {
        session_token: [0u8; 32],
        pow_nonce: 0,
        sender_seq: 0,
        ciphertext: payload,
    };

    c.bench_function("relay_encode_forward_msg", |b| {
        b.iter(|| {
            let encoded = relayd::protocol::encode(
                relayd::protocol::Tag::Forward,
                black_box(&msg),
            )
            .unwrap();
            black_box(encoded)
        })
    });
}

criterion_group!(benches, bench_protocol_encode_decode);
criterion_main!(benches);
