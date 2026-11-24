"""The blind relay (§3): relayd's messages, its proof of work, and the overlay's relay payload.

Two layers live here.

**Relay messages** (relayd's protocol). A datagram is a one-byte tag and a bincode body. Clients
send Register, Keepalive, Forward and Locate; the relay answers with Challenge, Ack, Locate and
Error. Two messages share tag 0x06: the relay's `AckMsg` (a 2-byte body) goes to the sender, and
its `DeliveredMsg` (sender seq and ciphertext) goes to the recipient. The 2-byte body is what tells
them apart.

**Relay payloads** (the overlay). The ciphertext a Forward carries is `len u32 LE | prefix u8 |
sender_token [32] | body`, zero-padded to a power of two of at least 64 bytes (the 4-byte length is
included in that size).

Proof of work: `blake3(challenge || token || nonce u64 LE)` must start with `difficulty` zero bits.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import Optional, Tuple

from .bincode import Reader, Writer
from .crypto import blake3_hash
from .errors import DecodeError, TransferdError


class Tag(IntEnum):
    REGISTER = 0x01
    FORWARD = 0x02
    KEEPALIVE = 0x03
    CHALLENGE = 0x04
    ERROR = 0x05
    ACK = 0x06
    REGISTER_GHOST = 0x07
    LOCATE = 0x08


# Error codes travel as the enum's variant index (a u32), in this order.
ERROR_CODES: Tuple[str, ...] = (
    "InvalidPoW",
    "TokenNotFound",
    "TokenAlreadyExists",
    "PayloadTooLarge",
    "RateLimited",
    "SeqReplay",
    "BandwidthExceeded",
    "GhostRequired",
    "GhostRejected",
    "InternalError",
)


def error_code_name(index: int) -> str:
    return ERROR_CODES[index] if 0 <= index < len(ERROR_CODES) else f"Unknown({index})"


# --- Overlay relay payload ------------------------------------------------------------------------

PREFIX_HANDSHAKE = 0x01
PREFIX_DATA = 0x02
PREFIX_HANDSHAKE_REPLY = 0x03


def pad(data: bytes) -> bytes:
    """`len u32 LE || data`, zero-padded to a power of two of at least 64 bytes."""
    power = 64
    while power < len(data) + 4:
        power *= 2
    out = struct.pack("<I", len(data)) + data
    return out + b"\x00" * (power - len(out))


def unpad(data: bytes) -> Optional[Tuple[int, bytes, bytes]]:
    """Returns `(prefix, sender token, body)`, or `None` when the padding does not describe the bytes."""
    if len(data) < 4:
        return None
    (length,) = struct.unpack("<I", data[:4])
    if 4 + length > len(data):
        return None
    body = data[4 : 4 + length]
    if len(body) < 33:
        return None
    return body[0], body[1:33], body[33:]


def encapsulate(prefix: int, sender_token: bytes, body: bytes) -> bytes:
    if len(sender_token) != 32:
        raise TransferdError("a sender token is 32 bytes")
    return pad(bytes([prefix]) + sender_token + body)


# --- Proof of work --------------------------------------------------------------------------------


def pow_ok(difficulty: int, challenge: bytes, token: bytes, nonce: int) -> bool:
    digest = blake3_hash(challenge + token + struct.pack("<Q", nonce))
    full, tail = divmod(difficulty, 8)
    if full >= len(digest):
        return False
    if any(digest[:full]):
        return False
    if tail:
        return digest[full] >> (8 - tail) == 0
    return True


def solve_pow(difficulty: int, challenge: bytes, token: bytes, start: int = 0) -> int:
    nonce = start
    while not pow_ok(difficulty, challenge, token, nonce):
        nonce += 1
    return nonce


# --- Messages -------------------------------------------------------------------------------------


def split(datagram: bytes) -> Optional[Tuple[int, bytes]]:
    if not datagram:
        return None
    try:
        tag = Tag(datagram[0])
    except ValueError:
        return None
    return int(tag), datagram[1:]


def _socket_addr(w: Writer, addr: Tuple[str, int]) -> None:
    ip = ipaddress.ip_address(addr[0])
    if ip.version == 4:
        w.u32(0)
        w.raw(ip.packed)
    else:
        w.u32(1)
        w.raw(ip.packed)
    w.u16(addr[1])


def _read_socket_addr(r: Reader) -> Tuple[str, int]:
    variant = r.u32()
    if variant == 0:
        ip = ipaddress.IPv4Address(r.raw(4))
    elif variant == 1:
        ip = ipaddress.IPv6Address(r.raw(16))
    else:
        raise DecodeError("socket address variant is neither V4 nor V6")
    return str(ip), r.u16()


def _tagged(tag: Tag, write) -> bytes:
    w = Writer()
    write(w)
    return bytes([int(tag)]) + w.getvalue()


def encode_register(session_token: bytes, pow_nonce: int, seq: int) -> bytes:
    return _tagged(Tag.REGISTER, lambda w: (w.raw(session_token), w.u64(pow_nonce), w.u32(seq)))


def encode_keepalive(session_token: bytes, pow_nonce: int, seq: int) -> bytes:
    return _tagged(Tag.KEEPALIVE, lambda w: (w.raw(session_token), w.u64(pow_nonce), w.u32(seq)))


def encode_forward(session_token: bytes, pow_nonce: int, sender_seq: int, ciphertext: bytes) -> bytes:
    return _tagged(
        Tag.FORWARD,
        lambda w: (w.raw(session_token), w.u64(pow_nonce), w.u16(sender_seq), w.bytes_(ciphertext)),
    )


def encode_challenge(challenge: bytes, expires_at: int, difficulty: int) -> bytes:
    return _tagged(Tag.CHALLENGE, lambda w: (w.raw(challenge), w.u64(expires_at), w.u32(difficulty)))


def encode_locate(self_token: bytes, peer_token: bytes, pow_nonce: int, seq: int) -> bytes:
    return _tagged(
        Tag.LOCATE,
        lambda w: (w.raw(self_token), w.raw(peer_token), w.u64(pow_nonce), w.u32(seq)),
    )


def encode_located(self_addr: Tuple[str, int], peer_addr: Optional[Tuple[str, int]], request: int) -> bytes:
    def write(w: Writer) -> None:
        _socket_addr(w, self_addr)
        w.option(peer_addr, _socket_addr)
        w.u32(request)

    return _tagged(Tag.LOCATE, write)


def encode_error(code_index: int, seq: int, detail: str) -> bytes:
    return _tagged(Tag.ERROR, lambda w: (w.u32(code_index), w.u32(seq), w.string(detail)))


def encode_ack(sender_seq: int) -> bytes:
    return _tagged(Tag.ACK, lambda w: w.u16(sender_seq))


def encode_delivered(sender_seq: int, ciphertext: bytes) -> bytes:
    return _tagged(Tag.ACK, lambda w: (w.u16(sender_seq), w.bytes_(ciphertext)))


@dataclass(frozen=True)
class Challenge:
    challenge: bytes
    expires_at: int
    difficulty: int


@dataclass(frozen=True)
class Located:
    self_addr: Tuple[str, int]
    peer_addr: Optional[Tuple[str, int]]
    request: int


@dataclass(frozen=True)
class RelayError:
    code: str
    seq: int
    detail: str


@dataclass(frozen=True)
class Acked:
    sender_seq: int


@dataclass(frozen=True)
class Delivered:
    sender_seq: int
    ciphertext: bytes


def decode_challenge(body: bytes) -> Challenge:
    r = Reader(body)
    return Challenge(challenge=r.raw(16), expires_at=r.u64(), difficulty=r.u32())


def decode_located(body: bytes) -> Located:
    r = Reader(body)
    self_addr = _read_socket_addr(r)
    peer_addr = r.option(_read_socket_addr)
    return Located(self_addr=self_addr, peer_addr=peer_addr, request=r.u32())


def decode_error(body: bytes) -> RelayError:
    r = Reader(body)
    code = error_code_name(r.u32())
    return RelayError(code=code, seq=r.u32(), detail=r.string())


def decode_ack_or_delivered(body: bytes):
    """A tag 0x06 body: two bytes is an `AckMsg`; anything longer is a `DeliveredMsg`."""
    if len(body) == 2:
        return Acked(sender_seq=Reader(body).u16())
    r = Reader(body)
    return Delivered(sender_seq=r.u16(), ciphertext=r.bytes_())


__all__ = [
    "Tag",
    "ERROR_CODES",
    "PREFIX_HANDSHAKE",
    "PREFIX_DATA",
    "PREFIX_HANDSHAKE_REPLY",
    "pad",
    "unpad",
    "encapsulate",
    "pow_ok",
    "solve_pow",
    "split",
    "encode_register",
    "encode_keepalive",
    "encode_forward",
    "encode_challenge",
    "encode_locate",
    "encode_located",
    "encode_error",
    "encode_ack",
    "encode_delivered",
    "decode_challenge",
    "decode_located",
    "decode_error",
    "decode_ack_or_delivered",
]
