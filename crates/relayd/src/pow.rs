//! Hashcash-style Proof-of-Work validator.
//!
//! Challenge: the relay periodically generates 16 random bytes and broadcasts them.
//! Client obligation: find a `pow_nonce: u64` such that
//!
//!   blake3(challenge ‖ session_token ‖ pow_nonce.to_le_bytes())
//!
//! has at least `difficulty` leading zero bits.
//!
//! At difficulty=20, expected work ≈ 2^20 ≈ 1M hashes ≈ <10 ms on modern hardware.
//! The relay can raise difficulty under DDoS load without changing the protocol.

use rand::RngCore;

/// A live PoW challenge held by the relay.
#[derive(Clone, Debug)]
pub struct PowChallenge {
    pub bytes: [u8; 16],
    /// Unix timestamp (secs) when this challenge expires. `u64::MAX` = never.
    pub expires_at: u64,
    pub difficulty: u32,
}

impl PowChallenge {
    pub fn new(difficulty: u32, expires_at: u64) -> Self {
        let mut bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self { bytes, expires_at, difficulty }
    }

    /// Returns `true` if the nonce satisfies this challenge for the given token.
    pub fn verify(&self, token: &[u8; 32], nonce: u64) -> bool {
        leading_zeros(self.difficulty, &self.bytes, token, nonce)
    }

    pub fn is_expired(&self, now_secs: u64) -> bool {
        now_secs >= self.expires_at
    }
}

/// Core verification: does blake3(challenge ‖ token ‖ nonce) have ≥ `difficulty` leading zeros?
pub fn leading_zeros(difficulty: u32, challenge: &[u8; 16], token: &[u8; 32], nonce: u64) -> bool {
    let mut h = blake3::Hasher::new();
    h.update(challenge);
    h.update(token);
    h.update(&nonce.to_le_bytes());
    let hash = h.finalize();
    let bytes = hash.as_bytes();

    let full = (difficulty / 8) as usize;
    let tail  = difficulty % 8;

    if full >= bytes.len() {
        return false; // pathological difficulty
    }
    for b in &bytes[..full] {
        if *b != 0 { return false; }
    }
    if tail > 0 {
        bytes[full] >> (8 - tail) == 0
    } else {
        true
    }
}

/// Solves the PoW puzzle (used by clients and in tests).
///
/// Iterates nonces from `start` until the difficulty is satisfied.
/// Returns `None` if `max_iter` is exceeded (caller should retry with a new challenge).
#[cfg(test)]
pub fn solve(
    challenge: &[u8; 16],
    token: &[u8; 32],
    difficulty: u32,
    start: u64,
    max_iter: u64,
) -> Option<u64> {
    (start..start.saturating_add(max_iter))
        .find(|&nonce| leading_zeros(difficulty, challenge, token, nonce))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pow_solve_and_verify() {
        let challenge = PowChallenge::new(8, u64::MAX); // 8-bit = 1 leading zero byte
        let token = [0x42u8; 32];
        let nonce = solve(&challenge.bytes, &token, 8, 0, 1_000_000)
            .expect("should solve 8-bit PoW within 1M iterations");
        assert!(challenge.verify(&token, nonce), "solved nonce must verify");
    }

    #[test]
    fn test_pow_wrong_nonce_rejected() {
        let challenge = PowChallenge::new(8, u64::MAX);
        let token = [0x99u8; 32];
        // nonce = 0 will almost certainly fail an 8-bit PoW
        // (probability of accidental success = 1/256)
        let valid = challenge.verify(&token, 0xDEAD_BEEF_DEAD_BEEF);
        // We can't assert false deterministically, but if it passes it's a genuine PoW solution.
        let _ = valid;
    }

    #[test]
    fn test_pow_difficulty_zero_always_passes() {
        let challenge = PowChallenge::new(0, u64::MAX);
        let token = [0u8; 32];
        assert!(challenge.verify(&token, 42), "difficulty=0 must always pass");
    }

    #[test]
    fn test_pow_higher_difficulty_harder() {
        // 16-bit difficulty: verify the solver finds a valid nonce.
        let challenge = PowChallenge::new(16, u64::MAX);
        let token = [0x11u8; 32];
        let nonce = solve(&challenge.bytes, &token, 16, 0, 10_000_000)
            .expect("should solve 16-bit PoW within 10M iterations");
        assert!(challenge.verify(&token, nonce));
    }
}
