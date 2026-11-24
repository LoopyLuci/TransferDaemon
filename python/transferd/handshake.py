"""The authenticated hybrid handshake (§1), protocol version 2, ciphersuite 0x0002.

    initiator flight (8568 bytes):
        tag 0x11 | version u16 LE | ciphersuite u16 LE | x25519_pk (32) | ml_kem_768_ek (1184)
        | identity_pk (2624) | transcript (32) | signature (4691)
    responder flight (8472 bytes): the same, tag 0x12, with the ML-KEM ciphertext (1088) in place
        of the encapsulation key.

The transcript is `BLAKE3(tag || version || suite || hello || identity_pk)`. Each flight's
signature is a hybrid signature over that transcript. The session key is
`BLAKE3-derive_key("TransferDaemon-v1-hybrid-session-key", x25519_ss || mlkem_ss)`.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from typing import Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import x25519

from .crypto import (
    blake3_derive_key,
    blake3_hash,
    mlkem_decapsulate,
    mlkem_encapsulate,
    mlkem_keypair,
    x25519_exchange,
    x25519_generate,
    x25519_public,
)
from .errors import HandshakeError
from .identity import HYBRID_PK_LEN, HYBRID_SIG_LEN, HybridIdentity, verify_hybrid
from .tunnel import LinkKeys, derive_link_keys
from .wire import read_blob, write_blob

TAG_INITIATOR = 0x11
TAG_RESPONDER = 0x12
PROTOCOL_VERSION = 2
CIPHERSUITE_HYBRID = 0x0002

X25519_PK_LEN = 32
KEM_EK_LEN = 1184
KEM_CT_LEN = 1088
TRANSCRIPT_LEN = 32
INITIATOR_HELLO_LEN = X25519_PK_LEN + KEM_EK_LEN  # 1216
RESPONDER_HELLO_LEN = X25519_PK_LEN + KEM_CT_LEN  # 1120
INITIATOR_FLIGHT_LEN = 1 + 2 + 2 + INITIATOR_HELLO_LEN + HYBRID_PK_LEN + TRANSCRIPT_LEN + HYBRID_SIG_LEN  # 8568
RESPONDER_FLIGHT_LEN = 1 + 2 + 2 + RESPONDER_HELLO_LEN + HYBRID_PK_LEN + TRANSCRIPT_LEN + HYBRID_SIG_LEN  # 8472

SESSION_KEY_CONTEXT = "TransferDaemon-v1-hybrid-session-key"


def _transcript(tag: int, version: int, suite: int, hello: bytes, identity_pk: bytes) -> bytes:
    return blake3_hash(
        bytes([tag])
        + version.to_bytes(2, "little")
        + suite.to_bytes(2, "little")
        + hello
        + identity_pk
    )


def hybrid_kdf(x25519_ss: bytes, kem_ss: bytes) -> bytes:
    return blake3_derive_key(SESSION_KEY_CONTEXT, x25519_ss + kem_ss)


@dataclass
class Flight:
    tag: int
    version: int
    suite: int
    hello: bytes
    identity_pk: bytes
    transcript: bytes
    signature: bytes

    def to_wire(self) -> bytes:
        return (
            bytes([self.tag])
            + self.version.to_bytes(2, "little")
            + self.suite.to_bytes(2, "little")
            + self.hello
            + self.identity_pk
            + self.transcript
            + self.signature
        )

    @classmethod
    def parse(cls, data: bytes, tag: int, hello_len: int, flight_len: int) -> "Flight":
        if len(data) != flight_len or data[0] != tag:
            raise HandshakeError("flight is malformed")
        off = 1
        version = int.from_bytes(data[off : off + 2], "little")
        off += 2
        suite = int.from_bytes(data[off : off + 2], "little")
        off += 2
        hello = data[off : off + hello_len]
        off += hello_len
        identity_pk = data[off : off + HYBRID_PK_LEN]
        off += HYBRID_PK_LEN
        transcript = data[off : off + TRANSCRIPT_LEN]
        off += TRANSCRIPT_LEN
        signature = data[off : off + HYBRID_SIG_LEN]
        return cls(tag, version, suite, hello, identity_pk, transcript, signature)

    def verify(self) -> bool:
        """Recompute the transcript, then check the hybrid signature over it."""
        expected = _transcript(self.tag, self.version, self.suite, self.hello, self.identity_pk)
        return expected == self.transcript and verify_hybrid(self.identity_pk, self.transcript, self.signature)

    @property
    def node_id(self) -> str:
        return self.identity_pk[:32].hex()


def _build(tag: int, hello: bytes, identity: HybridIdentity) -> Flight:
    identity_pk = identity.public_key
    transcript = _transcript(tag, PROTOCOL_VERSION, CIPHERSUITE_HYBRID, hello, identity_pk)
    return Flight(tag, PROTOCOL_VERSION, CIPHERSUITE_HYBRID, hello, identity_pk, transcript, identity.sign(transcript))


class InitiatorState:
    """The ephemeral keys an initiator holds between its flight and the answer."""

    def __init__(self, kem_seed: Optional[bytes] = None, x25519_key: Optional[x25519.X25519PrivateKey] = None) -> None:
        self._x25519 = x25519_key or x25519_generate()
        self._kem_private, self._kem_ek = mlkem_keypair(kem_seed or os.urandom(64))

    def hello(self) -> bytes:
        return x25519_public(self._x25519) + self._kem_ek

    def finish(self, responder_hello: bytes) -> bytes:
        """The session key, from the responder's `x25519_pk || ml_kem_ciphertext`."""
        if len(responder_hello) != RESPONDER_HELLO_LEN:
            raise HandshakeError("responder hello has the wrong length")
        x_ss = x25519_exchange(self._x25519, responder_hello[:X25519_PK_LEN])
        kem_ss = mlkem_decapsulate(self._kem_private, responder_hello[X25519_PK_LEN:])
        return hybrid_kdf(x_ss, kem_ss)


def respond(initiator_hello: bytes) -> Tuple[bytes, bytes]:
    """The responder's hello and session key, from the initiator's `x25519_pk || ml_kem_ek`."""
    if len(initiator_hello) != INITIATOR_HELLO_LEN:
        raise HandshakeError("initiator hello has the wrong length")
    private = x25519_generate()
    x_ss = x25519_exchange(private, initiator_hello[:X25519_PK_LEN])
    try:
        kem_ss, ciphertext = mlkem_encapsulate(initiator_hello[X25519_PK_LEN:])
    except ValueError as exc:
        raise HandshakeError("ML-KEM encapsulation key is invalid") from exc
    return x25519_public(private) + ciphertext, hybrid_kdf(x_ss, kem_ss)


@dataclass
class HandshakeResult:
    session_key: bytes
    peer_node_id: str
    peer_hybrid_public_key: bytes
    keys: LinkKeys


async def handshake_initiator(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    identity: HybridIdentity,
    expect_node_id: Optional[str] = None,
) -> HandshakeResult:
    state = InitiatorState()
    flight = _build(TAG_INITIATOR, state.hello(), identity)
    await write_blob(writer, flight.to_wire())
    answer = Flight.parse(await read_blob(reader), TAG_RESPONDER, RESPONDER_HELLO_LEN, RESPONDER_FLIGHT_LEN)
    if not answer.verify():
        raise HandshakeError("responder flight signature does not verify")
    if expect_node_id is not None and answer.node_id != expect_node_id:
        raise HandshakeError(f"we dialled {expect_node_id}, but the peer is {answer.node_id}")
    session_key = state.finish(answer.hello)
    return HandshakeResult(
        session_key=session_key,
        peer_node_id=answer.node_id,
        peer_hybrid_public_key=answer.identity_pk,
        keys=derive_link_keys(session_key),
    )


async def handshake_responder(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    identity: HybridIdentity,
) -> HandshakeResult:
    hello = Flight.parse(await read_blob(reader), TAG_INITIATOR, INITIATOR_HELLO_LEN, INITIATOR_FLIGHT_LEN)
    if not hello.verify():
        raise HandshakeError("initiator flight signature does not verify")
    responder_hello, session_key = respond(hello.hello)
    answer = _build(TAG_RESPONDER, responder_hello, identity)
    await write_blob(writer, answer.to_wire())
    return HandshakeResult(
        session_key=session_key,
        peer_node_id=hello.node_id,
        peer_hybrid_public_key=hello.identity_pk,
        keys=derive_link_keys(session_key).swapped(),
    )


__all__ = [
    "PROTOCOL_VERSION",
    "CIPHERSUITE_HYBRID",
    "INITIATOR_FLIGHT_LEN",
    "RESPONDER_FLIGHT_LEN",
    "Flight",
    "InitiatorState",
    "respond",
    "hybrid_kdf",
    "handshake_initiator",
    "handshake_responder",
    "HandshakeResult",
]
