"""Hybrid identity: Ed25519 and ML-DSA-87, derived from a 64-byte seed.

- The Ed25519 key comes from the first 32 bytes of the seed.
- The ML-DSA-87 key comes from `BLAKE3-derive_key("TransferDaemon-v1-mldsa87-seed", seed)`.
- The node id is the lowercase hex of the Ed25519 public key (64 characters).
- The hybrid public key is `ed25519_pk (32) || ml_dsa_87_pk (2592)`: 2624 bytes.
- A hybrid signature is `ed25519_sig (64) || ml_dsa_87_sig (4627)`: 4691 bytes. Both halves must
  verify, and the ML-DSA half is bound to the context `TransferDaemon-v1-hybrid-sign`.
"""

from __future__ import annotations

import os
import re

from .crypto import (
    ML_DSA_SIGN_CONTEXT,
    blake3_derive_key,
    ed25519_sign,
    ed25519_verify,
    mldsa_from_seed,
    mldsa_public,
    mldsa_sign,
    mldsa_verify,
    ed25519_public,
)
from .errors import TransferdError

ED25519_PK_LEN = 32
ML_DSA_87_PK_LEN = 2592
HYBRID_PK_LEN = ED25519_PK_LEN + ML_DSA_87_PK_LEN  # 2624
ED25519_SIG_LEN = 64
ML_DSA_87_SIG_LEN = 4627
HYBRID_SIG_LEN = ED25519_SIG_LEN + ML_DSA_87_SIG_LEN  # 4691

MLDSA_SEED_CONTEXT = "TransferDaemon-v1-mldsa87-seed"
RELAY_TOKEN_CONTEXT = "transferd-overlay-relay-token-v1"
FINGERPRINT_CONTEXT = "TransferDaemon-overlay-key-fingerprint-v1"

_NODE_ID = re.compile(r"^[0-9a-f]{64}$")


class HybridIdentity:
    """A node's signing identity. Keep the seed secret: it is the identity."""

    def __init__(self, seed: bytes, name: str = "") -> None:
        if len(seed) != 64:
            raise TransferdError("an identity seed is 64 bytes")
        self.seed = bytes(seed)
        self.name = name
        self.ed25519_public_key = ed25519_public(self.seed[:32])
        self._ml_private = mldsa_from_seed(blake3_derive_key(MLDSA_SEED_CONTEXT, self.seed))
        self.public_key = self.ed25519_public_key + mldsa_public(self._ml_private)
        self.node_id = self.ed25519_public_key.hex()

    @classmethod
    def generate(cls, name: str = "") -> "HybridIdentity":
        return cls(os.urandom(64), name)

    def sign(self, message: bytes) -> bytes:
        """A hybrid signature over `message`."""
        return ed25519_sign(self.seed[:32], message) + mldsa_sign(
            self._ml_private, message, ML_DSA_SIGN_CONTEXT
        )

    def sign_ed25519(self, message: bytes) -> bytes:
        """The Ed25519 half alone. Anyone can check it against the node id."""
        return ed25519_sign(self.seed[:32], message)

    def relay_token(self) -> bytes:
        return relay_token_for(self.node_id)


def relay_token_for(node_id: str) -> bytes:
    """The 32-byte token a node registers with a relay. It is derived from the node id's text."""
    return blake3_derive_key(RELAY_TOKEN_CONTEXT, node_id.encode("ascii"))


def key_fingerprint(hybrid_public_key: bytes) -> bytes:
    """What an invite carries in place of the 2624-byte key."""
    return blake3_derive_key(FINGERPRINT_CONTEXT, hybrid_public_key)


def check_node_id(node_id: str) -> None:
    if not _NODE_ID.match(node_id):
        raise TransferdError("a node id is 64 lowercase hex characters")


def verify_hybrid(public_key: bytes, message: bytes, signature: bytes, context: bytes = ML_DSA_SIGN_CONTEXT) -> bool:
    """Both halves of a hybrid signature must verify. Uses the ordinary Ed25519 check, as the reference does."""
    if len(public_key) != HYBRID_PK_LEN or len(signature) != HYBRID_SIG_LEN:
        return False
    ed_ok = ed25519_verify(public_key[:ED25519_PK_LEN], message, signature[:ED25519_SIG_LEN])
    ml_ok = mldsa_verify(public_key[ED25519_PK_LEN:], message, signature[ED25519_SIG_LEN:], context)
    return ed_ok and ml_ok


__all__ = [
    "HybridIdentity",
    "relay_token_for",
    "key_fingerprint",
    "check_node_id",
    "verify_hybrid",
    "HYBRID_PK_LEN",
    "HYBRID_SIG_LEN",
    "ED25519_PK_LEN",
    "ED25519_SIG_LEN",
    "ML_DSA_87_PK_LEN",
    "ML_DSA_87_SIG_LEN",
]
