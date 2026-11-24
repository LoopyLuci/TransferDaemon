"""Primitives: BLAKE3, X25519, Ed25519, AES-256-GCM, ML-KEM-768 and ML-DSA-87.

The post-quantum primitives follow FIPS 203 and FIPS 204. `cryptography` provides them, and the
reference's signing context and key derivation are applied on top here.

`ed25519_verify_strict` reproduces the reference's strict check (`verify_strict` in ed25519-dalek):
on top of the signature equation it rejects a non-canonical `S`, and a public key or `R` that has
small order. The invite signature uses it; the handshake uses the ordinary check, as the reference
does.
"""

from __future__ import annotations

from typing import Optional, Tuple

import blake3 as _blake3
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa, mlkem, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import TransferdError

# --- BLAKE3 ---------------------------------------------------------------------------------------


def blake3_hash(data: bytes) -> bytes:
    return _blake3.blake3(data).digest()


def blake3_keyed(key: bytes, data: bytes) -> bytes:
    return _blake3.blake3(data, key=key).digest()


def blake3_derive_key(context: str, material: bytes) -> bytes:
    return _blake3.blake3(material, derive_key_context=context).digest()


# --- X25519 ---------------------------------------------------------------------------------------


def x25519_generate() -> x25519.X25519PrivateKey:
    return x25519.X25519PrivateKey.generate()


def x25519_public(private: x25519.X25519PrivateKey) -> bytes:
    return private.public_key().public_bytes_raw()


def x25519_exchange(private: x25519.X25519PrivateKey, peer_public: bytes) -> bytes:
    try:
        return private.exchange(x25519.X25519PublicKey.from_public_bytes(peer_public))
    except ValueError as exc:  # a low-order peer key yields an all-zero secret, which is refused
        raise TransferdError("X25519 exchange produced no secret") from exc


# --- Ed25519 --------------------------------------------------------------------------------------

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _recover_x(y: int, sign: int) -> Optional[int]:
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


def _decode_point(encoding: bytes) -> Optional[Tuple[int, int]]:
    if len(encoding) != 32:
        return None
    y = int.from_bytes(encoding, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= _P:
        return None
    x = _recover_x(y, sign)
    return None if x is None else (x, y)


def _add(p: Tuple[int, int], q: Tuple[int, int]) -> Tuple[int, int]:
    x1, y1 = p
    x2, y2 = q
    t = _D * x1 * x2 * y1 * y2 % _P
    x3 = (x1 * y2 + y1 * x2) * pow((1 + t) % _P, _P - 2, _P) % _P
    y3 = (y1 * y2 + x1 * x2) * pow((1 - t) % _P, _P - 2, _P) % _P
    return (x3, y3)


def _has_small_order(encoding: bytes) -> bool:
    point = _decode_point(encoding)
    if point is None:
        return False  # not a point at all: the signature check rejects it
    p8 = point
    for _ in range(3):  # 8P
        p8 = _add(p8, p8)
    return p8 == (0, 1)


def ed25519_public(seed: bytes) -> bytes:
    return ed25519.Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()


def ed25519_sign(seed: bytes, message: bytes) -> bytes:
    return ed25519.Ed25519PrivateKey.from_private_bytes(seed).sign(message)


def ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """The ordinary Ed25519 check, as used inside the hybrid signature."""
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False


def ed25519_verify_strict(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Reproduces `verify_strict`: canonical S, no small-order public key or R, then the check."""
    if len(public_key) != 32 or len(signature) != 64:
        return False
    r = signature[:32]
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    if _has_small_order(public_key) or _has_small_order(r):
        return False
    return ed25519_verify(public_key, message, signature)


# --- AES-256-GCM ----------------------------------------------------------------------------------


def aes_gcm_seal(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """Returns ciphertext followed by the 16-byte tag."""
    return AESGCM(key).encrypt(nonce, plaintext, aad)


def aes_gcm_open(key: bytes, nonce: bytes, sealed: bytes, aad: bytes) -> bytes:
    try:
        return AESGCM(key).decrypt(nonce, sealed, aad)
    except InvalidTag as exc:
        raise TransferdError("AES-GCM authentication failed") from exc


# --- ML-KEM-768 (FIPS 203) ------------------------------------------------------------------------


def mlkem_keypair(seed: bytes) -> Tuple[mlkem.MLKEM768PrivateKey, bytes]:
    """A decapsulation key from its 64-byte seed, and its 1184-byte encapsulation key."""
    private = mlkem.MLKEM768PrivateKey.from_seed_bytes(seed)
    return private, private.public_key().public_bytes_raw()


def mlkem_encapsulate(encapsulation_key: bytes) -> Tuple[bytes, bytes]:
    """Returns `(shared_secret, ciphertext)`."""
    return mlkem.MLKEM768PublicKey.from_public_bytes(encapsulation_key).encapsulate()


def mlkem_decapsulate(private: mlkem.MLKEM768PrivateKey, ciphertext: bytes) -> bytes:
    return private.decapsulate(ciphertext)


# --- ML-DSA-87 (FIPS 204) -------------------------------------------------------------------------

ML_DSA_SIGN_CONTEXT = b"TransferDaemon-v1-hybrid-sign"


def mldsa_from_seed(xi: bytes) -> mldsa.MLDSA87PrivateKey:
    return mldsa.MLDSA87PrivateKey.from_seed_bytes(xi)


def mldsa_public(private: mldsa.MLDSA87PrivateKey) -> bytes:
    return private.public_key().public_bytes_raw()


def mldsa_sign(private: mldsa.MLDSA87PrivateKey, message: bytes, context: bytes) -> bytes:
    return private.sign(message, context)


def mldsa_verify(public_key: bytes, message: bytes, signature: bytes, context: bytes) -> bool:
    try:
        mldsa.MLDSA87PublicKey.from_public_bytes(public_key).verify(signature, message, context)
        return True
    except (InvalidSignature, ValueError):
        return False
