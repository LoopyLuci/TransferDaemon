"""bincode 1.x: the encoding of every frame body and relay message in the Rust reference.

Rules (bincode's default options, little-endian, fixed-width integers):

- integers are fixed width and little-endian; `f64` is its IEEE 754 bytes;
- `bool` is one byte, 0 or 1;
- a length (of a string, a byte vector or any sequence) is a `u64`;
- an `Option` is a one-byte tag (0 for none, 1 for some) followed by the value;
- an enum is a `u32` variant index, not its discriminant;
- a fixed array (`[u8; N]`) is its bytes with no length.

Decoding reads exactly the fields it knows and ignores any bytes after them. That is how an older
build reads a newer build's trailing fields, and why a decoder must not insist the body ends where
its own fields end.
"""

from __future__ import annotations

import struct
from typing import Callable, Optional, TypeVar

from .errors import DecodeError

T = TypeVar("T")


class Writer:
    """Accumulates a bincode encoding."""

    __slots__ = ("_buf",)

    def __init__(self) -> None:
        self._buf = bytearray()

    def u8(self, value: int) -> None:
        self._buf += struct.pack("<B", value)

    def u16(self, value: int) -> None:
        self._buf += struct.pack("<H", value)

    def u32(self, value: int) -> None:
        self._buf += struct.pack("<I", value)

    def u64(self, value: int) -> None:
        self._buf += struct.pack("<Q", value)

    def f64(self, value: float) -> None:
        self._buf += struct.pack("<d", value)

    def boolean(self, value: bool) -> None:
        self.u8(1 if value else 0)

    def raw(self, data: bytes) -> None:
        """A fixed-size array: its bytes, with no length."""
        self._buf += data

    def bytes_(self, data: bytes) -> None:
        """A byte vector: its length as a u64, then the bytes."""
        self.u64(len(data))
        self._buf += data

    def string(self, text: str) -> None:
        self.bytes_(text.encode("utf-8"))

    def option(self, value: Optional[T], write: Callable[["Writer", T], None]) -> None:
        if value is None:
            self.u8(0)
        else:
            self.u8(1)
            write(self, value)

    def seq(self, items, write: Callable[["Writer", T], None]) -> None:
        self.u64(len(items))
        for item in items:
            write(self, item)

    def getvalue(self) -> bytes:
        return bytes(self._buf)


class Reader:
    """Reads a bincode encoding, front to back. Trailing bytes are left unread."""

    __slots__ = ("_data", "_pos")

    def __init__(self, data: bytes) -> None:
        self._data = bytes(data)
        self._pos = 0

    def remaining(self) -> int:
        return len(self._data) - self._pos

    def take(self, n: int) -> bytes:
        if n < 0 or self.remaining() < n:
            raise DecodeError("body ends before its fields do")
        out = self._data[self._pos : self._pos + n]
        self._pos += n
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack("<H", self.take(2))[0]

    def u32(self) -> int:
        return struct.unpack("<I", self.take(4))[0]

    def u64(self) -> int:
        return struct.unpack("<Q", self.take(8))[0]

    def f64(self) -> float:
        return struct.unpack("<d", self.take(8))[0]

    def boolean(self) -> bool:
        value = self.u8()
        if value > 1:
            raise DecodeError("bool byte is neither 0 nor 1")
        return value == 1

    def raw(self, n: int) -> bytes:
        return self.take(n)

    def bytes_(self) -> bytes:
        n = self.u64()
        if n > self.remaining():
            raise DecodeError("a length runs past the end of the body")
        return self.take(n)

    def string(self) -> str:
        try:
            return self.bytes_().decode("utf-8")
        except UnicodeDecodeError as exc:
            raise DecodeError("string is not UTF-8") from exc

    def option(self, read: Callable[["Reader"], T]) -> Optional[T]:
        tag = self.u8()
        if tag == 0:
            return None
        if tag == 1:
            return read(self)
        raise DecodeError("option tag is neither 0 nor 1")

    def seq(self, read: Callable[["Reader"], T]) -> list[T]:
        n = self.u64()
        # Every element takes at least one byte, so a longer claim cannot be honest.
        if n > self.remaining():
            raise DecodeError("a sequence length runs past the end of the body")
        return [read(self) for _ in range(n)]


def encode(write: Callable[[Writer], None]) -> bytes:
    """Run `write` against a fresh writer and return the bytes it produced."""
    w = Writer()
    write(w)
    return w.getvalue()
