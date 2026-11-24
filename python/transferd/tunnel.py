"""The secure tunnel (§2): per-direction keys, sealed frames, and the replay window.

A tunnel frame is `len u32 BE || counter u64 BE || AES-256-GCM(ciphertext || tag)`, where:

- `len` is the plaintext length and `counter` is the frame's counter; together they are the
  associated data, so a frame cannot be truncated, extended or moved;
- the nonce is `key[0..4] || counter (u64 BE)`;
- the receiver accepts a counter only if it is new and inside a 4096-wide window, and it checks the
  window only after the frame authenticates.
"""

from __future__ import annotations

import struct
from collections import deque
from dataclasses import dataclass
from typing import Deque, Optional

from .bincode import Reader  # noqa: F401  (re-exported for symmetry with the other codecs)
from .crypto import aes_gcm_open, aes_gcm_seal, blake3_derive_key
from .errors import TransferdError, TunnelError
from .frames import Frame, FrameReader
from .wire import read_blob, write_blob

C2S_CONTEXT = "TransferDaemon-overlay-c2s-v1"
S2C_CONTEXT = "TransferDaemon-overlay-s2c-v1"
REPLAY_WINDOW = 4096
HEADER_LEN = 12  # len (4) + counter (8)


@dataclass(frozen=True)
class LinkKeys:
    """The keys one link uses: `send` for this side's frames, `recv` for the peer's."""

    send: bytes
    recv: bytes

    def swapped(self) -> "LinkKeys":
        """The mirrored view, for the side that accepted the connection."""
        return LinkKeys(send=self.recv, recv=self.send)


def derive_link_keys(session_key: bytes) -> LinkKeys:
    return LinkKeys(
        send=blake3_derive_key(C2S_CONTEXT, session_key),
        recv=blake3_derive_key(S2C_CONTEXT, session_key),
    )


class FrameCounter:
    """Hands out counters 0, 1, 2, ... A session shares one per direction."""

    __slots__ = ("_next",)

    def __init__(self, start: int = 0) -> None:
        self._next = start

    def next(self) -> int:
        value = self._next
        self._next += 1
        return value


class ReplayWindow:
    """Accepts each counter once, within `width` of the newest one accepted."""

    __slots__ = ("width", "_highest", "_seen")

    def __init__(self, width: int = REPLAY_WINDOW) -> None:
        self.width = width
        self._highest: Optional[int] = None
        self._seen: set[int] = set()

    def accept(self, counter: int) -> bool:
        """Call this only after the frame has authenticated, so a forged counter cannot move it."""
        if self._highest is None:
            self._highest = counter
            self._seen = {counter}
            return True
        if counter > self._highest:
            self._highest = counter
            floor = counter - self.width
            self._seen = {c for c in self._seen if c > floor}
            self._seen.add(counter)
            return True
        if self._highest - counter >= self.width:
            return False
        if counter in self._seen:
            return False
        self._seen.add(counter)
        return True


class Sealer:
    """Seals blobs with one key, drawing counters from a shared counter."""

    __slots__ = ("_key", "_counter")

    def __init__(self, key: bytes, counter: Optional[FrameCounter] = None) -> None:
        if len(key) != 32:
            raise TunnelError("a tunnel key is 32 bytes")
        self._key = key
        self._counter = counter or FrameCounter()

    def seal(self, plaintext: bytes, counter: Optional[int] = None) -> bytes:
        """`counter` is given only by tests that pin the reference's output."""
        if counter is None:
            counter = self._counter.next()
        if len(plaintext) > 0xFFFFFFFF:
            raise TunnelError("frame too large")
        aad = struct.pack(">IQ", len(plaintext), counter)
        nonce = self._key[:4] + struct.pack(">Q", counter)
        return aad + aes_gcm_seal(self._key, nonce, plaintext, aad)


class Opener:
    """Opens sealed frames with one key and checks replays."""

    __slots__ = ("_key", "_window")

    def __init__(self, key: bytes, window: Optional[ReplayWindow] = None) -> None:
        if len(key) != 32:
            raise TunnelError("a tunnel key is 32 bytes")
        self._key = key
        self._window = window or ReplayWindow()

    def open(self, frame: bytes) -> bytes:
        if len(frame) < HEADER_LEN:
            raise TunnelError("tunnel frame is too short")
        aad = frame[:HEADER_LEN]
        length, counter = struct.unpack(">IQ", aad)
        nonce = self._key[:4] + struct.pack(">Q", counter)
        try:
            plaintext = aes_gcm_open(self._key, nonce, frame[HEADER_LEN:], aad)
        except TransferdError as exc:
            raise TunnelError("tunnel frame failed to authenticate") from exc
        if not self._window.accept(counter):
            raise TunnelError("replayed tunnel frame")
        if len(plaintext) != length:
            raise TunnelError("tunnel frame length does not match its header")
        return plaintext


class TunnelReader:
    """Reads overlay frames off a stream. Every frame in a sealed blob is kept, none dropped."""

    __slots__ = ("_opener", "_frames", "_pending")

    def __init__(self, keys: LinkKeys) -> None:
        self._opener = Opener(keys.recv)
        self._frames = FrameReader()
        self._pending: Deque[Frame] = deque()

    async def next_frame(self, reader) -> Frame:
        while not self._pending:
            blob = await read_blob(reader)
            self._pending.extend(self._frames.push(self._opener.open(blob)))
        return self._pending.popleft()


async def write_frame(writer, sealer: Sealer, frame: Frame) -> None:
    await write_blob(writer, sealer.seal(frame.encode()))
