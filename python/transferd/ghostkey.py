"""Ghost keys: anonymous, verifiable identities (`crates/transferd-crypto/src/ghostkey.rs`).

An issuer vouches that a person passed some gate without ever learning which key it vouched for. The person makes an
Ed25519 key, blinds it (RFC 9474), the issuer signs the blinded value, and the person unblinds the answer into a
certificate that anyone can check against the issuer's public key. A relay that trusts an issuer admits a registration
that carries such a certificate (`admit_ghost`), and learns nothing about who the person is.

Construction: RSABSSA-SHA384-PSS-Randomized. The signed message is a 32-byte random prefix, then
`"transferd-ghostkey-v1" || len(tier) || tier || ghost public key`, under EMSA-PSS with SHA-384, MGF1-SHA-384 and a
48-byte salt. A certificate is therefore an ordinary RSASSA-PSS signature.

Certificates and issuer keys travel as bincode in hex, as the reference writes them. Issuing uses plain modular
exponentiation: unlike the Rust reference it is not blinded against timing, so issue certificates on a machine you trust.
"""

import hashlib
import os
import secrets
from dataclasses import dataclass
from typing import Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from . import bincode
from .crypto import blake3_hash, ed25519_public, ed25519_sign, ed25519_verify
from .errors import TransferdError

DOMAIN = b"transferd-ghostkey-v1"
#: The domain of what a ghost key signs to register a session (`relayd/src/ghost.rs`).
BINDING_DOMAIN = b"transferd-relay-ghost-v1"
SALT_LEN = 48
PREFIX_LEN = 32
HASH_LEN = 48
SIGNATURE_LEN = 64

ISSUER_TEXT = "transferd-ghostissuerpub-v1:"
ISSUER_SECRET_TEXT = "transferd-ghostissuer-v1:"
CERTIFICATE_TEXT = "transferd-ghostcert-v1:"
PENDING_TEXT = "transferd-ghostpending-v1:"


class GhostKeyError(TransferdError):
    """A ghost key, certificate or registration that does not check out."""


def binding(session_token: bytes, seq: int) -> bytes:
    """What a ghost key signs to register a session: the domain, the session token and the sequence number."""
    return BINDING_DOMAIN + session_token + (seq & 0xFFFFFFFF).to_bytes(4, "little")


def ghost_message(tier: str, ghost_public: bytes) -> bytes:
    encoded = tier.encode("utf-8")
    return DOMAIN + bytes([len(encoded)]) + encoded + ghost_public


def _mgf1(seed: bytes, length: int) -> bytes:
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha384(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


def _emsa_pss_encode(msg: bytes, em_bits: int) -> bytes:
    """EMSA-PSS-ENCODE (RFC 8017 section 9.1.1) with SHA-384, MGF1-SHA-384 and a 48-byte salt."""
    em_len = -(-em_bits // 8)
    if em_len < HASH_LEN + SALT_LEN + 2:
        raise GhostKeyError("the message is too long for this issuer key")
    m_hash = hashlib.sha384(msg).digest()
    salt = os.urandom(SALT_LEN)
    h = hashlib.sha384(bytes(8) + m_hash + salt).digest()
    ps_len = em_len - SALT_LEN - HASH_LEN - 2
    db = bytearray(ps_len) + b"\x01" + salt
    mask = _mgf1(h, em_len - HASH_LEN - 1)
    db = bytearray(a ^ b for a, b in zip(db, mask))
    zero_bits = 8 * em_len - em_bits
    db[0] &= 0xFF >> zero_bits
    return bytes(db) + h + b"\xbc"


def _i2osp(x: int, length: int) -> bytes:
    if x >> (8 * length):
        raise GhostKeyError("the message is too long for this issuer key")
    return x.to_bytes(length, "big")


def _big_bytes(x: int) -> bytes:
    """A non-negative integer as minimal big-endian bytes, as num-bigint's `to_bytes_be` writes it."""
    return x.to_bytes(max((x.bit_length() + 7) // 8, 1), "big")


@dataclass(frozen=True)
class IssuerPublic:
    """What everyone needs to check certificates: the RSA public key (SPKI DER), its tier and its name."""

    name: str
    tier: str
    spki: bytes

    def rsa_key(self) -> rsa.RSAPublicKey:
        try:
            return serialization.load_der_public_key(self.spki)  # type: ignore[return-value]
        except (ValueError, TypeError) as exc:
            raise GhostKeyError(f"encoding: {exc}") from exc

    def id(self) -> str:
        """blake3 of the SPKI, first 8 bytes in hex: how certificates name their issuer."""
        return blake3_hash(self.spki)[:8].hex()

    def to_text(self) -> str:
        return ISSUER_TEXT + bincode.encode(lambda w: _write_issuer(w, self)).hex()

    @classmethod
    def from_text(cls, text: str) -> "IssuerPublic":
        body = _strip(text, ISSUER_TEXT, "not an issuer public key")
        return _from_hex(body, lambda r: IssuerPublic(r.string(), r.string(), r.bytes_()))


def _write_issuer(w: bincode.Writer, issuer: IssuerPublic) -> None:
    w.string(issuer.name)
    w.string(issuer.tier)
    w.bytes_(issuer.spki)


def _strip(text: str, prefix: str, message: str) -> str:
    body = text.strip()
    if not body.startswith(prefix):
        raise GhostKeyError(message)
    return body[len(prefix) :]


def _decode(data: bytes, read):
    """Reads one bincode value from `data`, or raises `GhostKeyError`."""
    try:
        return read(bincode.Reader(data))
    except TransferdError as exc:
        raise GhostKeyError(f"encoding: {exc}") from exc


def _from_hex(hex_body: str, read):
    """Reads one bincode value from its hex text, or raises `GhostKeyError`."""
    try:
        data = bytes.fromhex(hex_body)
    except ValueError as exc:
        raise GhostKeyError(f"encoding: {exc}") from exc
    return _decode(data, read)


class Issuer:
    """An issuer key for one tier. Keep the private part offline or on the relay; publish `public`."""

    def __init__(self, key: rsa.RSAPrivateKey, public: IssuerPublic) -> None:
        self._key = key
        self.public = public

    @classmethod
    def generate(cls, name: str, tier: str, bits: int) -> "Issuer":
        if not 2048 <= bits <= 4096:
            raise GhostKeyError(f"the issuer key must be 2048 to 4096 bits (got {bits})")
        if len(tier.encode("utf-8")) > 64:
            raise GhostKeyError("a tier is at most 64 bytes")
        return cls.from_private(name, tier, rsa.generate_private_key(65537, bits))

    @classmethod
    def from_private(cls, name: str, tier: str, key: rsa.RSAPrivateKey) -> "Issuer":
        spki = key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return cls(key, IssuerPublic(name, tier, spki))

    def to_secret_text(self) -> str:
        """The issuer's secret file: `transferd-ghostissuer-v1:<name>`, the tier, and the key as hex PKCS#8 DER."""
        der = self._key.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        return f"{ISSUER_SECRET_TEXT}{self.public.name}\n{self.public.tier}\n{der.hex()}\n"

    @classmethod
    def from_secret_text(cls, text: str) -> "Issuer":
        body = _strip(text, ISSUER_SECRET_TEXT, "not an issuer secret")
        lines = body.strip().splitlines()
        if len(lines) < 3:
            raise GhostKeyError("an issuer secret has a name, a tier and a key")
        try:
            key = serialization.load_der_private_key(bytes.fromhex(lines[2].strip()), password=None)
        except (ValueError, TypeError) as exc:
            raise GhostKeyError(f"encoding: {exc}") from exc
        return cls.from_private(lines[0], lines[1], key)  # type: ignore[arg-type]

    def sign_blinded(self, blinded: bytes) -> bytes:
        """BlindSign (RFC 9474 section 4.3): the RSA private operation on a value the issuer cannot read."""
        numbers = self._key.private_numbers()
        n, e, d = numbers.public_numbers.n, numbers.public_numbers.e, numbers.d
        k = (n.bit_length() + 7) // 8
        if len(blinded) != k:
            raise GhostKeyError(f"a blinded value has the wrong length (expected {k} bytes, got {len(blinded)})")
        m = int.from_bytes(blinded, "big")
        if m >= n:
            raise GhostKeyError("the message is too long for this issuer key")
        s = pow(m, d, n)
        # the check RFC 9474 asks for: s^e == m, so a fault never leaks the key
        if pow(s, e, n) != m:
            raise GhostKeyError("the issuer's signature does not check out (a wrong issuer key, or tampering)")
        return _i2osp(s, k)


class GhostKey:
    """The ghost key itself: an Ed25519 key the person keeps; its certificate says an issuer vouched for it."""

    def __init__(self, secret: bytes) -> None:
        if len(secret) != 32:
            raise GhostKeyError("a ghost key secret is 32 bytes")
        self._seed = secret

    @classmethod
    def generate(cls) -> "GhostKey":
        return cls(os.urandom(32))

    def secret(self) -> bytes:
        return self._seed

    def public(self) -> bytes:
        return ed25519_public(self._seed)

    def sign(self, message: bytes) -> bytes:
        return ed25519_sign(self._seed, message)

    def blind_request(self, issuer: IssuerPublic) -> Tuple[bytes, "BlindState"]:
        """Blind (RFC 9474 section 4.2, randomised variant): what to send the issuer, and the state to keep."""
        pk = issuer.rsa_key().public_numbers()
        n, e = pk.n, pk.e
        k = (n.bit_length() + 7) // 8
        prefix = os.urandom(PREFIX_LEN)
        msg = prefix + ghost_message(issuer.tier, self.public())
        m = int.from_bytes(_emsa_pss_encode(msg, n.bit_length() - 1), "big")
        while True:
            r = _random_below(n)
            try:
                inv = pow(r, -1, n)
            except ValueError:
                continue  # not invertible modulo n: draw again
            z = (m * pow(r, e, n)) % n
            return _i2osp(z, k), BlindState(inv=inv, msg=msg, k=k)

    def finish(self, issuer: IssuerPublic, state: "BlindState", blind_sig: bytes) -> "GhostCertificate":
        """Finalize (RFC 9474 section 4.4): unblind the issuer's answer and check it is a valid PSS signature."""
        if len(blind_sig) != state.k:
            raise GhostKeyError(f"a blinded value has the wrong length (expected {state.k} bytes, got {len(blind_sig)})")
        n = issuer.rsa_key().public_numbers().n
        s = (int.from_bytes(blind_sig, "big") * state.inv) % n
        cert = GhostCertificate(
            issuer_id=issuer.id(),
            tier=issuer.tier,
            ghost_public=self.public(),
            prefix=state.msg[:PREFIX_LEN],
            signature=_i2osp(s, state.k),
        )
        try:
            cert.verify(issuer)
        except GhostKeyError as exc:
            raise GhostKeyError("the issuer's signature does not check out (a wrong issuer key, or tampering)") from exc
        return cert


def _random_below(n: int) -> int:
    """A uniform integer in [1, n)."""
    return secrets.randbelow(n - 1) + 1


@dataclass(frozen=True)
class BlindState:
    """Between asking and finishing: the blinding inverse and the randomised message. Never sent anywhere."""

    inv: int
    msg: bytes
    k: int

    def to_text(self, key: GhostKey) -> str:
        """The pending request, `transferd-ghostpending-v1:<hex>`. Its secrets stay with the person."""
        body = bincode.encode(
            lambda w: (w.bytes_(_big_bytes(self.inv)), w.bytes_(self.msg), w.u64(self.k), w.raw(key.secret()))
        )
        return PENDING_TEXT + body.hex()

    @classmethod
    def from_text(cls, text: str) -> Tuple["BlindState", GhostKey]:
        body = _strip(text, PENDING_TEXT, "not a pending ghost key request")
        inv, msg, k, secret = _from_hex(body, lambda r: (r.bytes_(), r.bytes_(), r.u64(), r.raw(32)))
        return cls(inv=int.from_bytes(inv, "big"), msg=msg, k=k), GhostKey(secret)


@dataclass(frozen=True)
class GhostCertificate:
    """A finished certificate: shareable, checkable by anyone with the issuer's public key."""

    issuer_id: str
    tier: str
    ghost_public: bytes
    prefix: bytes
    signature: bytes

    def verify(self, issuer: IssuerPublic) -> None:
        """Raises `GhostKeyError` unless this is a key the issuer vouched for, at its tier."""
        if self.issuer_id != issuer.id() or self.tier != issuer.tier:
            raise GhostKeyError("the certificate is not valid for this issuer")
        msg = self.prefix + ghost_message(self.tier, self.ghost_public)
        try:
            issuer.rsa_key().verify(
                self.signature,
                msg,
                padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=SALT_LEN),
                hashes.SHA384(),
            )
        except InvalidSignature as exc:
            raise GhostKeyError("the certificate is not valid for this issuer") from exc

    def verify_signed(self, issuer: IssuerPublic, message: bytes, signature: bytes) -> None:
        """Raises `GhostKeyError` unless the certificate is valid and `signature` is by the ghost key it vouches for."""
        self.verify(issuer)
        if len(signature) != SIGNATURE_LEN or not ed25519_verify(self.ghost_public, message, signature):
            raise GhostKeyError("the ghost key's signature does not check out")

    def encode_bincode(self) -> bytes:
        """The certificate as bincode (what a registration carries)."""
        return bincode.encode(
            lambda w: (
                w.string(self.issuer_id),
                w.string(self.tier),
                w.raw(self.ghost_public),
                w.raw(self.prefix),
                w.bytes_(self.signature),
            )
        )

    @classmethod
    def decode_bincode(cls, data: bytes) -> "GhostCertificate":
        return _decode(data, _read_certificate)

    def to_text(self) -> str:
        return CERTIFICATE_TEXT + self.encode_bincode().hex()

    @classmethod
    def from_text(cls, text: str) -> "GhostCertificate":
        return _from_hex(_strip(text, CERTIFICATE_TEXT, "not a ghost key certificate"), _read_certificate)


def _read_certificate(r: bincode.Reader) -> GhostCertificate:
    return GhostCertificate(
        issuer_id=r.string(),
        tier=r.string(),
        ghost_public=r.raw(32),
        prefix=r.raw(PREFIX_LEN),
        signature=r.bytes_(),
    )


@dataclass(frozen=True)
class GhostPolicy:
    """A relay's ghost key admission: the issuers it trusts. Whether plain registrations are refused, and how many
    sessions one key may hold, are the relay's own state; the policy carries them so a relay can be configured in one
    place."""

    issuers: Tuple[IssuerPublic, ...] = ()
    required: bool = False
    max_sessions_per_key: int = 8


def admit_ghost(
    policy: GhostPolicy, session_token: bytes, seq: int, certificate: bytes, signature: bytes
) -> bytes:
    """The ghost key a registration proves (`GhostPolicy::admit`). Raises `GhostKeyError` when it proves none."""
    if not policy.issuers:
        raise GhostKeyError("this relay trusts no ghost key issuer")
    try:
        cert = GhostCertificate.decode_bincode(certificate)
    except GhostKeyError as exc:
        raise GhostKeyError("not a ghost key certificate") from exc
    issuer = next((i for i in policy.issuers if i.id() == cert.issuer_id), None)
    if issuer is None:
        raise GhostKeyError("the certificate's issuer is not trusted here")
    cert.verify_signed(issuer, binding(session_token, seq), signature)
    return cert.ghost_public
