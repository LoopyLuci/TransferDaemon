use transferd_core::receiver::{InsertResult, ReassemblyWindow};
use transferd_core::transport::Chunk;
use transferd_core::types::{Gsn, SessionId};
use bytes::Bytes;
use std::collections::HashMap;

fn make_chunk(gsn: u64, session_id: SessionId) -> Chunk {
    Chunk {
        gsn: Gsn(gsn),
        session_id,
        payload: Bytes::from(vec![0u8; 64]),
        key_epoch: 0,
        qos_critical: false,
    }
}

#[test]
fn test_critical_gap_nack_and_recovery() {
    let session_id = SessionId([0; 16]);
    let mut window = ReassemblyWindow::new(session_id, 100);
    let mut retransmit: HashMap<u64, Chunk> = HashMap::new();

    // Send chunks 0..50, drop GSN 10.
    for i in 0..50u64 {
        let chunk = make_chunk(i, session_id);
        retransmit.insert(i, chunk.clone());
        if i == 10 { continue; }
        let result = window.insert(chunk);
        if i < 10 {
            assert!(matches!(result, InsertResult::Delivered(_)), "chunk {i}");
        } else {
            assert!(matches!(result, InsertResult::Gap(_)), "chunk {i} gap");
        }
    }

    assert!(window.is_critical_gap(), "expected critical gap");
    let nack = window.generate_nack();
    assert_eq!(nack.missing_gsn, Gsn(10));

    // Retransmit the missing chunk.
    let recovered = retransmit[&10].clone();
    match window.insert(recovered) {
        InsertResult::Delivered(base) => assert_eq!(base, Gsn(50)),
        other => panic!("expected Delivered(50), got {other:?}"),
    }

    assert!(!window.is_critical_gap());
    println!("Lossy-transfer test passed.");
}
