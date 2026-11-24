use ring_channel::{Consumer, Doorbell, MappedRegion, Producer};
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

#[tokio::test]
async fn test_zero_copy_continuity() {
    let descriptor_count = 128usize;
    let data_size = 256 * 1024; // 256 KiB

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

    let plaintext = b"V-BUS-ZERO-COPY-PAYLOAD";
    let hash_full = blake3::hash(plaintext);
    let mut prefix = [0u8; 8];
    prefix.copy_from_slice(&hash_full.as_bytes()[..8]);

    let mut grant = producer.reserve_grant(plaintext.len()).await.unwrap();
    unsafe { grant.as_slice_mut().copy_from_slice(plaintext); }
    producer.commit_grant_plain(grant, 1, 1 + plaintext.len() as u64, &prefix, 0);

    let read_grant = consumer.read_grant().await.expect("read_grant");
    assert_eq!(read_grant.buf, plaintext.as_ref());
    assert_eq!(read_grant.desc.gsn_start, 1);
    consumer.release_grant();

    println!("Zero-copy test passed.");
}
