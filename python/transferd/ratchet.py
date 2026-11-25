"""Double ratchet: per-message forward and future secrecy (`crates/transferd-crypto/src/ratchet.rs`).

Established on top of the authenticated handshake: the session key is the ratchet root. Each message is encrypted under
a key from a BLAKE3 chain, so one leaked message key reveals neither earlier nor later messages (forward secrecy). Every
`RATCHET_INTERVAL` sends, the sender takes a DH step: a fresh X25519 secret and a fresh ML-KEM-768 encapsulation are both
mixed into the root, so a leaked root cannot decrypt what follows (future secrecy, with a post-quantum component).

Ordering: the transport delivers in order, so each chain advances once per message and no skipped-message keys are kept.
"""

import os
from dataclasses import dataclass
from typing import Optional

from .crypto import (
    aes_gcm_open,
    aes_gcm_seal,
    blake3_derive_key,
    mlkem_decapsulate,
    mlkem_encapsulate,
    mlkem_keypair,
    x25519_exchange,
    x25519_generate,
    x25519_public,
)
from .errors import TransferdError

CTX_CHAIN = "TransferDaemon-v3-ratchet-chain"
CTX_MESSAGE_KEY = "TransferDaemon-v3-ratchet-message-key"
CTX_ROOT_MIX = "TransferDaemon-v3-ratchet-root-mix"
CTX_DH = "TransferDaemon-v3-ratchet-dh"
CTX_KEM = "TransferDaemon-v3-ratchet-kem"
CTX_INIT_SEND = "TransferDaemon-v3-ratchet-init-send"
CTX_INIT_RECV = "TransferDaemon-v3-ratchet-init-recv"

#: How many sends before the sender takes a DH step.
RATCHET_INTERVAL = 10
TAG_LEN = 16
KEM_EK_LEN = 1184
KEM_CT_LEN = 1088
#: The most chain steps one message may skip ahead (a bound on a hostile index).
MAX_SKIP = 1_000_000


class RatchetError(TransferdError):
    """A ratchet message that does not decrypt under this ratchet."""


def mix_root(root: bytes, dh_shared: bytes, kem_shared: Optional[bytes] = None) -> bytes:
    """The new root after a DH step: the DH output, and the ML-KEM output when there is one, mixed into the old root
    through a KDF. Without the KEM output the root is what a classical-only attacker can reproduce; with it, it is not."""
    material = root + blake3_derive_key(CTX_DH, dh_shared)
    if kem_shared is not None:
        material += blake3_derive_key(CTX_KEM, kem_shared)
    return blake3_derive_key(CTX_ROOT_MIX, material)


def _chain_contexts(is_initiator: bool) -> tuple:
    """The initiator sends on the "send" chain, the responder on the "recv" chain, so the two peers' chains align."""
    if is_initiator:
        return CTX_INIT_SEND, CTX_INIT_RECV
    return CTX_INIT_RECV, CTX_INIT_SEND


def _nonce_for(index: int) -> bytes:
    """A deterministic per-message nonce from the chain index (each message key is used once, so this is safe)."""
    return bytes(4) + index.to_bytes(8, "big")


def _fresh_kem():
    """A fresh ML-KEM-768 decapsulation key, and its encapsulation key as bytes."""
    return mlkem_keypair(os.urandom(64))


class RatchetChain:
    """One message-key KDF chain: the symmetric half of the ratchet."""

    def __init__(self, seed: bytes, context: str) -> None:
        self._chain_key = blake3_derive_key(context, seed)
        self.index = 0

    def step(self) -> tuple:
        """Advance the chain and return `(message_key, index)` for this step."""
        message_key = blake3_derive_key(CTX_MESSAGE_KEY, self._chain_key)
        self._chain_key = blake3_derive_key(CTX_CHAIN, self._chain_key)
        index = self.index
        self.index += 1
        return message_key, index


@dataclass
class RatchetMessage:
    """The encrypted envelope for one application message. The ratchet fields are set on first sends and DH steps."""

    chain_index: int
    nonce: bytes
    tag: bytes
    ciphertext: bytes
    ratchet_pk: Optional[bytes] = None
    kem_ek: Optional[bytes] = None
    kem_ct: Optional[bytes] = None


class DoubleRatchet:
    """The double ratchet state for one pair of peers. `is_initiator` fixes which chain each side sends on."""

    def __init__(self, root_key: bytes, is_initiator: bool) -> None:
        if len(root_key) != 32:
            raise RatchetError("a ratchet root is 32 bytes")
        self._root = bytes(root_key)
        send_context, recv_context = _chain_contexts(is_initiator)
        self._send = RatchetChain(root_key, send_context)
        self._recv = RatchetChain(root_key, recv_context)
        self._dh_secret = x25519_generate()
        self._dh_pk = x25519_public(self._dh_secret)
        self._kem_dk, self._kem_ek = _fresh_kem()
        self._peer_dh_pk: Optional[bytes] = None
        self._peer_kem_ek: Optional[bytes] = None
        self._sends_since_dh = 0
        self._sent_any = False
        self._is_initiator = is_initiator

    def ratchet_public_key(self) -> bytes:
        """The current X25519 ratchet public key."""
        return self._dh_pk

    def _derive_new_root(self, dh_shared: bytes, kem_shared: Optional[bytes]) -> None:
        self._root = mix_root(self._root, dh_shared, kem_shared)

    def _dh_step_send(self) -> Optional[bytes]:
        """A send-side DH step: a fresh X25519 secret and, when the peer has published one, a fresh ML-KEM
        encapsulation. Returns the ML-KEM ciphertext to publish with the message."""
        secret = x25519_generate()
        pk = x25519_public(secret)
        shared = x25519_exchange(secret, self._peer_dh_pk)
        kem_ct = None
        kem_ss = None
        if self._peer_kem_ek is not None:
            dk, ek = _fresh_kem()
            kem_ss, kem_ct = mlkem_encapsulate(self._peer_kem_ek)
            self._kem_dk, self._kem_ek = dk, ek
        self._derive_new_root(shared, kem_ss)
        self._dh_secret = secret
        self._dh_pk = pk
        send_context, _ = _chain_contexts(self._is_initiator)
        self._send = RatchetChain(self._root, send_context)
        self._sends_since_dh = 0
        return kem_ct

    def _dh_step_recv(self, new_peer_pk: bytes, kem_ct: Optional[bytes]) -> None:
        """A receive-side DH step, when a new peer key arrives: mix the DH and KEM outputs and reset the recv chain."""
        shared = x25519_exchange(self._dh_secret, new_peer_pk)
        kem_ss = None
        if kem_ct is not None and len(kem_ct) == KEM_CT_LEN:
            kem_ss = mlkem_decapsulate(self._kem_dk, kem_ct)
        self._derive_new_root(shared, kem_ss)
        self._peer_dh_pk = new_peer_pk
        _, recv_context = _chain_contexts(self._is_initiator)
        self._recv = RatchetChain(self._root, recv_context)

    def encrypt(self, plaintext: bytes) -> RatchetMessage:
        """Encrypt `plaintext` under a fresh message key. Publishes the ratchet keys on the first send, and takes a DH
        step every `RATCHET_INTERVAL` sends once the peer's key is known."""
        ratchet_pk = None
        kem_ek = None
        kem_ct = None
        if not self._sent_any:
            self._sent_any = True
            ratchet_pk = self._dh_pk
            kem_ek = self._kem_ek
        elif self._sends_since_dh >= RATCHET_INTERVAL and self._peer_dh_pk is not None:
            kem_ct = self._dh_step_send()
            ratchet_pk = self._dh_pk
            kem_ek = self._kem_ek
        message_key, index = self._send.step()
        self._sends_since_dh += 1
        msg = _seal(message_key, index, plaintext, ratchet_pk)
        msg.kem_ek = kem_ek
        msg.kem_ct = kem_ct
        return msg

    def decrypt(self, msg: RatchetMessage) -> bytes:
        """Decrypt an envelope, ratcheting the recv chain first if it carries a new ratchet key."""
        if msg.ratchet_pk is not None:
            if self._peer_dh_pk is None:
                # First sight of the peer's key: record it without changing the root.
                self._peer_dh_pk = msg.ratchet_pk
                if msg.kem_ek is not None and len(msg.kem_ek) == KEM_EK_LEN:
                    self._peer_kem_ek = msg.kem_ek
            elif msg.ratchet_pk != self._peer_dh_pk:
                self._dh_step_recv(msg.ratchet_pk, msg.kem_ct)
                if msg.kem_ek is not None and len(msg.kem_ek) == KEM_EK_LEN:
                    self._peer_kem_ek = msg.kem_ek
        message_key = self._advance_recv(msg.chain_index)
        try:
            return aes_gcm_open(message_key, msg.nonce, msg.ciphertext + msg.tag, b"")
        except TransferdError as exc:
            raise RatchetError("ratchet decrypt: authentication failed") from exc

    def _advance_recv(self, chain_index: int) -> bytes:
        """The message key for `chain_index`, advancing the recv chain to it. Transport is in order, so an index behind
        the chain has no key: the zero key then fails authentication, as the reference's does."""
        steps = min(max(chain_index - self._recv.index, 0), MAX_SKIP) + 1
        for _ in range(steps):
            key, index = self._recv.step()
            if index == chain_index:
                return key
        return bytes(32)


def _seal(message_key: bytes, index: int, plaintext: bytes, ratchet_pk: Optional[bytes]) -> RatchetMessage:
    nonce = _nonce_for(index)
    sealed = aes_gcm_seal(message_key, nonce, plaintext, b"")
    return RatchetMessage(
        chain_index=index,
        nonce=nonce,
        tag=sealed[-TAG_LEN:],
        ciphertext=sealed[:-TAG_LEN],
        ratchet_pk=ratchet_pk,
    )
