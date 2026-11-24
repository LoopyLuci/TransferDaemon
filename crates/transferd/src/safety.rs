//! Safety numbers — the out-of-band fingerprint for verifying a peer.
//!
//! Both parties compute the SAME number from their two hybrid identity keys,
//! so two people can read the number aloud (or compare it on a second channel)
//! to confirm there is no man-in-the-middle.

/// Compute the Signal-style safety number for a pair of hybrid identity keys.
///
/// `our` and `peer` are hex-encoded 2624-byte hybrid public keys
/// (`ed25519_pk ‖ ml_dsa_87_pk`). The digest is `BLAKE3(lo ‖ hi)` where the two
/// keys are sorted canonically, so both parties derive the SAME number
/// regardless of who called first.
///
/// Returns 12 groups of 5 digits separated by spaces (e.g. `12345 67890 ...`),
/// or `None` when either key is not valid hex.
pub fn safety_number(our: &str, peer: &str) -> Option<String> {
    let a = hex::decode(our).ok()?;
    let b = hex::decode(peer).ok()?;
    let (first, second) = if a <= b { (&a, &b) } else { (&b, &a) };
    let mut input = Vec::with_capacity(first.len() + second.len());
    input.extend_from_slice(first);
    input.extend_from_slice(second);
    let digest = blake3::hash(&input);

    // Deterministic digit stream: 60 bytes = digest ‖ hash(digest)[..28], so we
    // get 60 digits → 12 groups of 5.
    let mut seed = Vec::with_capacity(60);
    seed.extend_from_slice(digest.as_bytes());
    let second = blake3::hash(digest.as_bytes());
    seed.extend_from_slice(&second.as_bytes()[..28]);

    let mut digits = String::with_capacity(71);
    for (i, b) in seed.iter().enumerate() {
        if i % 5 == 0 && i > 0 {
            digits.push(' ');
        }
        digits.push(char::from(b'0' + (b % 10)));
    }
    Some(digits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safety_number_is_symmetric() {
        let a = "aa".repeat(1312); // 2624 bytes of hex 'aa'
        let b = "bb".repeat(1312);
        assert_eq!(safety_number(&a, &b), safety_number(&b, &a));
    }

    #[test]
    fn safety_number_format() {
        let a = "aa".repeat(1312);
        let b = "bb".repeat(1312);
        let s = safety_number(&a, &b).expect("valid hex");
        assert_eq!(s.len(), 71); // 60 digits + 11 spaces
        assert_eq!(s.split(' ').count(), 12);
        assert!(s.chars().all(|c| c == ' ' || c.is_ascii_digit()));
    }

    #[test]
    fn safety_number_rejects_invalid_hex() {
        assert!(safety_number("zz", &"aa".repeat(1312)).is_none());
        assert!(safety_number(&"aa".repeat(1312), "nothex").is_none());
    }

    #[test]
    fn safety_number_changes_with_identity() {
        let a1 = "aa".repeat(1312);
        let a2 = "ab".repeat(1312);
        let b = "bb".repeat(1312);
        assert_ne!(safety_number(&a1, &b), safety_number(&a2, &b));
    }
}