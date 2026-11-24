# Transferd Cryptography

This document summarizes the cryptographic constructions used by Transferd. It is normative where it describes wire-visible material (key derivation labels, transcript contents, nonce construction).

## Identity

- Hybrid signing key: Ed25519 + ML-DSA-87.
- Node ID = lowercase hex of the 32-byte Ed25519 public key.
- Long-term keys are derived from a 64-byte seed that implementations must protect (hardware-backed storage preferred).

## Handshake

Authenticated hybrid key exchange:

- Classical: X25519
- Post-quantum: ML-KEM-768
- Identity authentication: Ed25519 + ML-DSA-87 signature over a BLAKE3 transcript of the handshake messages.

Shared secret = BLAKE3(X25519_shared ‖ ML-KEM_shared).

Ciphersuite identifier `0x0002` is reserved for this combination. New combinations receive new identifiers.

## Tunnel Keys

Directional keys are derived with BLAKE3-derive_key:

```
k_c2s = BLAKE3-derive_key("TransferDaemon-overlay-c2s-v1", secret)
k_s2c = BLAKE3-derive_key("TransferDaemon-overlay-s2c-v1", secret)
```

AES-256-GCM with:

```
nonce = key[0..4] ‖ counter (u64 BE)
aad   = length (u32 BE) ‖ counter (u64 BE)
```

Counter starts at 0 and increments per frame. Replay window is 4096 wide.

## Hole-Punch Keys

```
material  = id (u64 BE) ‖ initiator_nonce ‖ responder_nonce
probe_key = BLAKE3-derive_key("transferd-overlay-punch-probe-v1", material)
link_key  = BLAKE3-derive_key("transferd-overlay-punch-link-v1", material)
```

Probe MAC = first 16 bytes of BLAKE3-keyed(probe_key, probe_bytes_without_mac).

## Invite Signature

Signature covers BLAKE3 of all other invite fields under the context string `"TransferDaemon-overlay-invite-v1"`.

## Relay Token

```
token = BLAKE3-derive_key("transferd-overlay-relay-token-v1", node_id)
```

## Security Arguments (Informal)

- Breaking the shared secret requires breaking both X25519 and ML-KEM-768.
- Impersonation requires forging either Ed25519 or ML-DSA-87 (hybrid).
- Relays observe only tokens and size-padded ciphertext; they cannot decrypt or link sessions beyond the token.
- Replay and reordering are prevented by the counter + AAD + replay window.
- Nonces for hole punching never leave the encrypted session, so only the two participants can derive the probe and link keys.

Implementations must zeroize key material and should prefer hardware-backed storage for long-term seeds where available.
