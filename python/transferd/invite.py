"""Invites (§6): `tdov2:` followed by unpadded base64url of a signed JSON object.

Creating an invite signs its fields with the node's Ed25519 key. Accepting one checks, in order:
the prefix; the size (at most 4 KB once decoded); the expiry; the node id's shape; the signature
(strict Ed25519 over a BLAKE3 digest of every other field); and the fingerprint's length.

The signature covers `BLAKE3(INVITE_CONTEXT || version u16 LE || field(node_id) || field(name) ||
field(key_fingerprint) || u32 LE count || field(relay)... || u32 LE count || field(direct)... ||
expires_at u64 LE || field(nonce))`, where `field(x)` is `u32 LE length || bytes`.
"""

from __future__ import annotations

import base64
import json
import os
import struct
import time
from dataclasses import dataclass
from typing import List, Optional, Tuple

from .crypto import blake3_hash, ed25519_verify_strict
from .errors import InviteError, TransferdError
from .identity import HybridIdentity, check_node_id, key_fingerprint

PREFIX = "tdov2:"
MAX_INVITE_BYTES = 4 * 1024
INVITE_CONTEXT = b"TransferDaemon-overlay-invite-v2"
DEFAULT_TTL_S = 900
MIN_TTL_S = 30
MAX_TTL_S = 86_400


def _field(data: bytes) -> bytes:
    return struct.pack("<I", len(data)) + data


def invite_binding(
    *,
    version: int,
    node_id: str,
    name: str,
    key_fingerprint: str,
    relays: List[str],
    direct: List[str],
    expires_at: int,
    nonce: str,
) -> bytes:
    """The 32-byte digest an invite's signature covers."""
    parts = [
        INVITE_CONTEXT,
        struct.pack("<H", version),
        _field(node_id.encode()),
        _field(name.encode()),
        _field(key_fingerprint.encode()),
        struct.pack("<I", len(relays)),
        b"".join(_field(r.encode()) for r in relays),
        struct.pack("<I", len(direct)),
        b"".join(_field(d.encode()) for d in direct),
        struct.pack("<Q", expires_at),
        _field(nonce.encode()),
    ]
    return blake3_hash(b"".join(parts))


def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def base64url_decode(text: str) -> bytes:
    if any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in text):
        raise InviteError("invite is not valid base64url")
    if len(text) % 4 == 1:
        raise InviteError("invite is not valid base64url")
    padded = text + "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(padded)
    except ValueError as exc:
        raise InviteError("invite is not valid base64url") from exc


@dataclass(frozen=True)
class MadeInvite:
    text: str
    nonce: bytes
    expires_at: int


def make_invite(
    identity: HybridIdentity,
    relays: List[str],
    direct: List[str],
    ttl_s: int = DEFAULT_TTL_S,
    *,
    now: Optional[int] = None,
    nonce: Optional[bytes] = None,
) -> MadeInvite:
    ttl = min(max(ttl_s, MIN_TTL_S), MAX_TTL_S)
    nonce = nonce or os.urandom(16)
    expires_at = (int(time.time()) if now is None else now) + ttl
    fields = dict(
        version=2,
        node_id=identity.node_id,
        name=identity.name,
        key_fingerprint=key_fingerprint(identity.public_key).hex(),
        relays=list(relays),
        direct=list(direct),
        expires_at=expires_at,
        nonce=nonce.hex(),
    )
    binding = invite_binding(**fields)
    signature = identity.sign_ed25519(binding).hex()
    body = {"version": 2, **{k: v for k, v in fields.items() if k != "version"}, "signature": signature}
    text = PREFIX + base64url_encode(json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    return MadeInvite(text=text, nonce=nonce, expires_at=expires_at)


@dataclass(frozen=True)
class VerifiedInvite:
    node_id: str
    name: str
    key_fingerprint: bytes
    nonce: bytes
    relays: Tuple[str, ...] = ()
    direct: Tuple[str, ...] = ()


def accept_invite(text: str, *, now: Optional[int] = None) -> VerifiedInvite:
    """Verify an invite. Raises `InviteError` for anything the reference would refuse."""
    if not text.startswith(PREFIX):
        raise InviteError("an invite starts with tdov2:")
    raw = base64url_decode(text[len(PREFIX):])
    if len(raw) > MAX_INVITE_BYTES:
        raise InviteError("invite is too large")
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InviteError("invite is not a JSON object") from exc
    try:
        version = int(doc["version"])
        node_id = str(doc["node_id"])
        name = str(doc.get("name", ""))
        fingerprint_hex = str(doc["key_fingerprint"])
        relays = [str(r) for r in doc.get("relays", [])]
        direct = [str(d) for d in doc.get("direct", [])]
        expires_at = int(doc["expires_at"])
        nonce_hex = str(doc["nonce"])
        signature_hex = str(doc["signature"])
    except (KeyError, TypeError, ValueError) as exc:
        raise InviteError("invite is missing a field") from exc

    current = int(time.time()) if now is None else now
    if expires_at <= current:
        raise InviteError("invite has expired")
    try:
        check_node_id(node_id)
    except TransferdError as exc:
        raise InviteError(str(exc)) from exc
    public_key = bytes.fromhex(node_id)
    try:
        signature = bytes.fromhex(signature_hex)
    except ValueError as exc:
        raise InviteError("invite signature is malformed") from exc
    if len(signature) != 64:
        raise InviteError("invite signature is malformed")
    binding = invite_binding(
        version=version,
        node_id=node_id,
        name=name,
        key_fingerprint=fingerprint_hex,
        relays=relays,
        direct=direct,
        expires_at=expires_at,
        nonce=nonce_hex,
    )
    if not ed25519_verify_strict(public_key, binding, signature):
        raise InviteError("invite signature does not verify")
    try:
        fingerprint = bytes.fromhex(fingerprint_hex)
        nonce = bytes.fromhex(nonce_hex)
    except ValueError as exc:
        raise InviteError("invite key fingerprint or nonce is malformed") from exc
    if len(fingerprint) != 32:
        raise InviteError("invite key fingerprint is malformed")
    return VerifiedInvite(
        node_id=node_id,
        name=name or node_id[:12],
        key_fingerprint=fingerprint,
        nonce=nonce,
        relays=tuple(relays),
        direct=tuple(direct),
    )


__all__ = [
    "PREFIX",
    "MAX_INVITE_BYTES",
    "make_invite",
    "accept_invite",
    "invite_binding",
    "base64url_encode",
    "base64url_decode",
    "MadeInvite",
    "VerifiedInvite",
]
