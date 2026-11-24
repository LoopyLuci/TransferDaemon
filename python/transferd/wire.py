"""Length-prefixed blobs on a byte stream: `len u32 BE || bytes`.

A handshake flight and a sealed tunnel frame each travel as one blob over a direct TCP link. The
reader refuses a blob longer than `MAX_BLOB`, so a hostile length cannot make it allocate freely.
"""

from __future__ import annotations

import asyncio
import struct

from .errors import TransferdError

MAX_BLOB = 256 * 1024


async def write_blob(writer: asyncio.StreamWriter, body: bytes) -> None:
    if len(body) > 0xFFFFFFFF:
        raise TransferdError("blob too large")
    writer.write(struct.pack(">I", len(body)) + body)
    await writer.drain()


async def read_blob(reader: asyncio.StreamReader) -> bytes:
    (length,) = struct.unpack(">I", await reader.readexactly(4))
    if length > MAX_BLOB:
        raise TransferdError("blob is larger than the tunnel allows")
    return await reader.readexactly(length)
