//! Core relay state: forwarding table, registration, forwarding, TTL pruning.

use crate::pow::PowChallenge;
use crate::protocol::{ErrorCode, ForwardMsg, KeepaliveMsg, RegisterMsg};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum RelayError {
    #[error("proof-of-work invalid or challenge expired")]
    InvalidPoW,
    #[error("session token not registered")]
    TokenNotFound,
    #[error("payload exceeds maximum size")]
    PayloadTooLarge,
    #[error("sequence number not newer than the previous one (replay?)")]
    SeqReplay,
    #[error("rate limit exceeded for this address")]
    RateLimited,
}

impl RelayError {
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::InvalidPoW      => ErrorCode::InvalidPoW,
            Self::TokenNotFound   => ErrorCode::TokenNotFound,
            Self::PayloadTooLarge => ErrorCode::PayloadTooLarge,
            Self::SeqReplay       => ErrorCode::SeqReplay,
            Self::RateLimited     => ErrorCode::RateLimited,
        }
    }
}

// ---------------------------------------------------------------------------
// Forwarding table entry
// ---------------------------------------------------------------------------

struct Entry {
    addr: SocketAddr,
    expires_at_secs: u64,
    /// Highest `seq` seen on register/keepalive from this token (replay guard).
    last_reg_seq: u32,
    /// Total bytes forwarded to this recipient (for rate limiting / observability).
    bytes_forwarded: u64,
}

// ---------------------------------------------------------------------------
// Relay
// ---------------------------------------------------------------------------

pub struct Relay {
    table: HashMap<[u8; 32], Entry>,
    challenge: PowChallenge,
    difficulty: u32,
    /// How long (secs) a registration stays alive without a KEEPALIVE.
    ttl_secs: u64,
    /// Maximum ciphertext payload the relay will forward.
    max_payload: usize,
    /// Per-source-IP datagram rate limiter.
    rate_limiter: RateLimiter,
}

impl Relay {
    pub fn new(difficulty: u32, ttl_secs: u64, max_payload: usize) -> Self {
        let challenge = PowChallenge::new(difficulty, now_secs() + 60);
        Self {
            table: HashMap::new(),
            challenge,
            difficulty,
            ttl_secs,
            max_payload,
            rate_limiter: RateLimiter::new(30, 300), // ≤ 300 datagrams / 30s per IP
        }
    }

    /// Maximum datagrams allowed per IP within the rate-limit window.
    pub fn set_rate_limit(&mut self, window_secs: u64, max_per_window: u32) {
        self.rate_limiter = RateLimiter::new(window_secs, max_per_window);
    }

    // -----------------------------------------------------------------------
    // Challenge management
    // -----------------------------------------------------------------------

    /// Returns the current challenge. Rotates automatically if expired.
    pub fn current_challenge(&mut self) -> &PowChallenge {
        if self.challenge.is_expired(now_secs()) {
            self.challenge = PowChallenge::new(self.difficulty, now_secs() + 60);
        }
        &self.challenge
    }

    /// Force a challenge rotation (e.g. on load spike).
    pub fn rotate_challenge(&mut self) {
        self.challenge = PowChallenge::new(self.difficulty, now_secs() + 60);
    }

    /// True if a source IP may send another datagram (rate limiter).
    pub fn rate_limited(&mut self, ip: IpAddr) -> bool {
        !self.rate_limiter.allow(ip)
    }

    // -----------------------------------------------------------------------
    // Registration
    // -----------------------------------------------------------------------

    /// Registers a recipient's session token → socket address mapping.
    ///
    /// Idempotent: re-registering with a valid PoW refreshes the TTL.
    pub fn register(&mut self, msg: &RegisterMsg, addr: SocketAddr) -> Result<(), RelayError> {
        if !self.challenge.verify(&msg.session_token, msg.pow_nonce) {
            return Err(RelayError::InvalidPoW);
        }
        let expires_at_secs = now_secs() + self.ttl_secs;
        match self.table.get_mut(&msg.session_token) {
            Some(entry) => {
                // Replay guard: seq must advance for an existing registration.
                if msg.seq <= entry.last_reg_seq {
                    return Err(RelayError::SeqReplay);
                }
                entry.last_reg_seq = msg.seq;
                entry.addr = addr;
                entry.expires_at_secs = expires_at_secs;
            }
            None => {
                self.table.insert(msg.session_token, Entry {
                    addr,
                    expires_at_secs,
                    last_reg_seq: msg.seq,
                    bytes_forwarded: 0,
                });
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Forwarding
    // -----------------------------------------------------------------------

    /// Validates a FORWARD message and returns the destination address.
    ///
    /// The caller is responsible for copying the ciphertext to `dst_addr`.
    pub fn forward(&mut self, msg: &ForwardMsg) -> Result<SocketAddr, RelayError> {
        if msg.ciphertext.len() > self.max_payload {
            return Err(RelayError::PayloadTooLarge);
        }
        if !self.challenge.verify(&msg.session_token, msg.pow_nonce) {
            return Err(RelayError::InvalidPoW);
        }
        let entry = self.table.get_mut(&msg.session_token)
            .ok_or(RelayError::TokenNotFound)?;
        if entry.expires_at_secs <= now_secs() {
            return Err(RelayError::TokenNotFound);
        }
        // No per-message replay guard on FORWARD: a replayed forward merely
        // re-delivers an identical ciphertext, which the endpoint rejects via
        // GCM authentication (reused nonce) or dedups by GSN. Senders may also
        // legitimately use multiple sockets (hub + lane) with independent
        // sequence counters.
        entry.bytes_forwarded += msg.ciphertext.len() as u64;
        Ok(entry.addr)
    }

    // -----------------------------------------------------------------------
    // Keepalive
    // -----------------------------------------------------------------------

    /// Refreshes the TTL for a registered session.
    pub fn keepalive(&mut self, msg: &KeepaliveMsg) -> Result<(), RelayError> {
        if !self.challenge.verify(&msg.session_token, msg.pow_nonce) {
            return Err(RelayError::InvalidPoW);
        }
        let entry = self.table.get_mut(&msg.session_token)
            .ok_or(RelayError::TokenNotFound)?;
        if msg.seq <= entry.last_reg_seq {
            return Err(RelayError::SeqReplay);
        }
        entry.last_reg_seq = msg.seq;
        entry.expires_at_secs = now_secs() + self.ttl_secs;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Housekeeping
    // -----------------------------------------------------------------------

    /// Removes all entries whose TTL has expired. Called by the background pruner task.
    pub fn prune_expired(&mut self) -> usize {
        let now = now_secs();
        let before = self.table.len();
        self.table.retain(|_, entry| entry.expires_at_secs > now);
        before - self.table.len()
    }

    /// Returns the number of active (non-expired) registrations.
    pub fn active_count(&self) -> usize {
        self.table.len()
    }
}

// ---------------------------------------------------------------------------
// Per-IP sliding-window rate limiter
// ---------------------------------------------------------------------------

/// Counts datagrams per source IP within a sliding window.
struct RateLimiter {
    window_secs: u64,
    max_per_window: u32,
    counts: HashMap<IpAddr, (u64, u32)>,
}

impl RateLimiter {
    fn new(window_secs: u64, max_per_window: u32) -> Self {
        Self {
            window_secs,
            max_per_window,
            counts: HashMap::new(),
        }
    }

    /// Returns `true` if the IP may send a datagram now.
    fn allow(&mut self, ip: IpAddr) -> bool {
        let now = now_secs();
        let entry = self.counts.entry(ip).or_insert((now, 0));
        if now.saturating_sub(entry.0) >= self.window_secs {
            *entry = (now, 0);
        }
        if entry.1 >= self.max_per_window {
            false
        } else {
            entry.1 += 1;
            true
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::ForwardMsg;

    fn make_relay() -> Relay {
        Relay::new(0, 90, 64 * 1024) // difficulty=0 so PoW always passes in tests
    }

    fn token(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn addr() -> SocketAddr {
        "127.0.0.1:9000".parse().unwrap()
    }

    #[test]
    fn test_register_and_forward() {
        let mut relay = make_relay();
        let t = token(0xAA);
        let reg = RegisterMsg { session_token: t, pow_nonce: 0, seq: 0 };
        relay.register(&reg, addr()).expect("register");

        let fwd = ForwardMsg {
            session_token: t,
            pow_nonce: 0,
            sender_seq: 1,
            ciphertext: vec![0xBB; 128],
        };
        let dst = relay.forward(&fwd).expect("forward");
        assert_eq!(dst, addr());
    }

    #[test]
    fn test_forward_unknown_token_fails() {
        let mut relay = make_relay();
        let fwd = ForwardMsg {
            session_token: token(0x99),
            pow_nonce: 0,
            sender_seq: 0,
            ciphertext: vec![1, 2, 3],
        };
        assert!(matches!(relay.forward(&fwd), Err(RelayError::TokenNotFound)));
    }

    #[test]
    fn test_payload_too_large_rejected() {
        let mut relay = make_relay();
        let t = token(0x01);
        relay.register(&RegisterMsg { session_token: t, pow_nonce: 0, seq: 0 }, addr()).unwrap();
        let fwd = ForwardMsg {
            session_token: t,
            pow_nonce: 0,
            sender_seq: 0,
            ciphertext: vec![0u8; 64 * 1024 + 1], // one byte over limit
        };
        assert!(matches!(relay.forward(&fwd), Err(RelayError::PayloadTooLarge)));
    }

    #[test]
    fn test_prune_expired() {
        let mut relay = Relay::new(0, 0, 64 * 1024); // TTL=0 → immediately expired
        let t = token(0x77);
        relay.register(&RegisterMsg { session_token: t, pow_nonce: 0, seq: 0 }, addr()).unwrap();
        // Forward should fail (expired)
        let fwd = ForwardMsg { session_token: t, pow_nonce: 0, sender_seq: 0, ciphertext: vec![1] };
        assert!(relay.forward(&fwd).is_err());
        // Prune removes it
        let pruned = relay.prune_expired();
        assert_eq!(pruned, 1);
        assert_eq!(relay.active_count(), 0);
    }

    #[test]
    fn test_keepalive_refreshes_ttl() {
        let mut relay = make_relay();
        let t = token(0x55);
        relay.register(&RegisterMsg { session_token: t, pow_nonce: 0, seq: 0 }, addr()).unwrap();
        relay.keepalive(&KeepaliveMsg { session_token: t, pow_nonce: 0, seq: 1 }).expect("keepalive");
        // After keepalive the entry is still alive
        let fwd = ForwardMsg { session_token: t, pow_nonce: 0, sender_seq: 0, ciphertext: vec![42] };
        assert!(relay.forward(&fwd).is_ok());
    }

    #[test]
    fn test_active_count() {
        let mut relay = make_relay();
        assert_eq!(relay.active_count(), 0);
        relay.register(&RegisterMsg { session_token: token(1), pow_nonce: 0, seq: 0 }, addr()).unwrap();
        relay.register(&RegisterMsg { session_token: token(2), pow_nonce: 0, seq: 0 }, addr()).unwrap();
        assert_eq!(relay.active_count(), 2);
    }

    #[test]
    fn test_register_replay_rejected() {
        let mut relay = make_relay();
        let t = token(0x10);
        relay.register(&RegisterMsg { session_token: t, pow_nonce: 0, seq: 5 }, addr()).unwrap();
        // Replaying the same seq from a different address must be rejected.
        let err = relay.register(&RegisterMsg { session_token: t, pow_nonce: 0, seq: 5 }, "1.2.3.4:9000".parse().unwrap());
        assert!(matches!(err, Err(RelayError::SeqReplay)));
        // An older seq is also rejected.
        let err = relay.register(&RegisterMsg { session_token: t, pow_nonce: 0, seq: 4 }, "1.2.3.4:9000".parse().unwrap());
        assert!(matches!(err, Err(RelayError::SeqReplay)));
    }

    #[test]
    fn test_forward_replayed_delivers_duplicate() {
        let mut relay = make_relay();
        let t = token(0x11);
        relay.register(&RegisterMsg { session_token: t, pow_nonce: 0, seq: 0 }, addr()).unwrap();
        let fwd = ForwardMsg { session_token: t, pow_nonce: 0, sender_seq: 7, ciphertext: vec![1, 2, 3] };
        assert!(relay.forward(&fwd).is_ok());
        // Re-forwarding is allowed: the endpoint dedups identical ciphertext.
        assert!(relay.forward(&fwd).is_ok());
    }

    #[test]
    fn test_keepalive_replay_rejected() {
        let mut relay = make_relay();
        let t = token(0x12);
        relay.register(&RegisterMsg { session_token: t, pow_nonce: 0, seq: 0 }, addr()).unwrap();
        relay.keepalive(&KeepaliveMsg { session_token: t, pow_nonce: 0, seq: 1 }).unwrap();
        let err = relay.keepalive(&KeepaliveMsg { session_token: t, pow_nonce: 0, seq: 1 });
        assert!(matches!(err, Err(RelayError::SeqReplay)));
    }

    #[test]
    fn test_rate_limiter_blocks_after_budget() {
        let mut relay = Relay::new(0, 90, 64 * 1024);
        relay.set_rate_limit(30, 3); // 3 datagrams per 30s per IP
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        assert!(!relay.rate_limited(ip));
        assert!(!relay.rate_limited(ip));
        assert!(!relay.rate_limited(ip));
        assert!(relay.rate_limited(ip), "4th datagram in the window must be blocked");
        // A different IP is unaffected.
        let other: IpAddr = "203.0.113.10".parse().unwrap();
        assert!(!relay.rate_limited(other));
    }
}
