//! End-to-end relay integration tests.
//!
//! `relayd` is a binary crate, so we test its logic through inline test doubles that
//! mirror the key algorithms. The relay unit tests (in relay.rs / pow.rs) cover the
//! struct internals; this file covers cross-cutting concerns:
//!   • ZK token derivation
//!   • PoW solve + verify round-trip
//!   • Full register → forward → receive cycle via an inline relay harness

use std::collections::HashMap;
use std::net::SocketAddr;

// ---------------------------------------------------------------------------
// ZK token derivation
// ---------------------------------------------------------------------------

fn derive_token(session_key: &[u8; 32], relay_id: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(32 + relay_id.len());
    input.extend_from_slice(session_key);
    input.extend_from_slice(relay_id);
    blake3::derive_key("TransferDaemon-v1-relay-token", &input)
}

#[test]
fn test_derive_token_differs_by_key() {
    let token_a = derive_token(&[0xAAu8; 32], b"relay-1");
    let token_b = derive_token(&[0xBBu8; 32], b"relay-1");
    assert_ne!(token_a, token_b, "different session keys must produce different tokens");
    println!("ZK token-derivation test passed.");
}

#[test]
fn test_derive_token_differs_by_relay_id() {
    let key = [0x42u8; 32];
    let t1 = derive_token(&key, b"relay-1");
    let t2 = derive_token(&key, b"relay-2");
    assert_ne!(t1, t2, "same key, different relay → different token");
}

// ---------------------------------------------------------------------------
// PoW helpers (mirror pow.rs)
// ---------------------------------------------------------------------------

fn pow_verify(difficulty: u32, challenge: &[u8; 16], token: &[u8; 32], nonce: u64) -> bool {
    let mut h = blake3::Hasher::new();
    h.update(challenge);
    h.update(token);
    h.update(&nonce.to_le_bytes());
    let hash = h.finalize();
    let bytes = hash.as_bytes();
    let full = (difficulty / 8) as usize;
    let tail = difficulty % 8;
    for b in &bytes[..full.min(bytes.len())] {
        if *b != 0 { return false; }
    }
    if tail > 0 && full < bytes.len() {
        bytes[full] >> (8 - tail) == 0
    } else {
        true
    }
}

fn pow_solve(challenge: &[u8; 16], token: &[u8; 32], difficulty: u32) -> Option<u64> {
    (0u64..10_000_000).find(|&n| pow_verify(difficulty, challenge, token, n))
}

#[test]
fn test_pow_roundtrip_12bit() {
    use std::time::Instant;
    let challenge = [0x13u8; 16];
    let token = [0x42u8; 32];
    let t0 = Instant::now();
    let nonce = pow_solve(&challenge, &token, 12).expect("12-bit PoW must be solvable");
    println!("12-bit PoW: nonce={nonce} in {:?}", t0.elapsed());
    assert!(pow_verify(12, &challenge, &token, nonce));
}

#[test]
fn test_pow_difficulty_zero_trivial() {
    assert!(pow_verify(0, &[0u8; 16], &[0u8; 32], 0));
}

// ---------------------------------------------------------------------------
// Inline relay harness
// ---------------------------------------------------------------------------

struct TestRelay {
    table: HashMap<[u8; 32], SocketAddr>,
    max_payload: usize,
}

impl TestRelay {
    fn new(max_payload: usize) -> Self {
        Self { table: HashMap::new(), max_payload }
    }

    fn register(&mut self, token: [u8; 32], addr: SocketAddr) -> Result<(), &'static str> {
        self.table.insert(token, addr);
        Ok(())
    }

    fn forward(&self, token: [u8; 32], payload: &[u8]) -> Result<SocketAddr, &'static str> {
        if payload.len() > self.max_payload { return Err("payload too large"); }
        self.table.get(&token).copied().ok_or("token not registered")
    }
}

// ---------------------------------------------------------------------------
// Full cycle tests
// ---------------------------------------------------------------------------

#[test]
fn test_relay_register_and_forward() {
    let mut relay = TestRelay::new(64 * 1024);
    let recipient: SocketAddr = "127.0.0.1:9001".parse().unwrap();
    let token = derive_token(&[0xEEu8; 32], b"relay-local");
    let payload = b"hello-blind-relay";

    relay.register(token, recipient).unwrap();
    let dst = relay.forward(token, payload).expect("forward must succeed");
    assert_eq!(dst, recipient, "relay must route to the registered recipient");
    println!("Relay cycle test passed.");
}

#[test]
fn test_relay_unknown_token_rejected() {
    let relay = TestRelay::new(64 * 1024);
    let err = relay.forward([0x00u8; 32], b"data");
    assert!(err.is_err());
}

#[test]
fn test_relay_payload_too_large_rejected() {
    let mut relay = TestRelay::new(100);
    let token = [0x01u8; 32];
    relay.register(token, "127.0.0.1:9002".parse().unwrap()).unwrap();
    let err = relay.forward(token, &vec![0u8; 101]);
    assert!(err.is_err());
}

#[test]
fn test_relay_multiple_tokens_routed_correctly() {
    let mut relay = TestRelay::new(64 * 1024);
    let addr_a: SocketAddr = "127.0.0.1:9010".parse().unwrap();
    let addr_b: SocketAddr = "127.0.0.1:9011".parse().unwrap();
    let token_a = derive_token(&[0x11u8; 32], b"relay-1");
    let token_b = derive_token(&[0x22u8; 32], b"relay-1");

    relay.register(token_a, addr_a).unwrap();
    relay.register(token_b, addr_b).unwrap();

    assert_eq!(relay.forward(token_a, b"for-a").unwrap(), addr_a);
    assert_eq!(relay.forward(token_b, b"for-b").unwrap(), addr_b);
    println!("Multi-token routing test passed.");
}

/// Verifies end-to-end: derive tokens from a handshake session key, register,
/// forward an "encrypted" payload, and confirm the correct address is returned.
#[test]
fn test_full_pipeline_with_session_key() {
    let session_key = [0xDEu8; 32]; // would come from Initiator::finalize() in production
    let relay_id = b"relayd-node-1";

    let token = derive_token(&session_key, relay_id);
    let mut relay = TestRelay::new(64 * 1024);
    let recipient: SocketAddr = "127.0.0.1:7890".parse().unwrap();

    relay.register(token, recipient).unwrap();

    // Simulate sender forwarding an AES-GCM ciphertext (opaque to relay).
    let fake_ciphertext = vec![0xABu8; 512];
    let dst = relay.forward(token, &fake_ciphertext).unwrap();
    assert_eq!(dst, recipient);

    // The relay never saw the plaintext — it just moved `fake_ciphertext` blindly.
    println!("Session-key-driven relay pipeline test passed.");
}
