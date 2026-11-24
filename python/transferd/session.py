"""The opening of a session: a handshake, then the HELLO / HELLO_ACK exchange that agrees a version.

The initiator sends HELLO, advertising its version range and a nonce. The responder answers HELLO_ACK
with the single version both sides support, echoing the nonce. A session that cannot agree is refused
with version 0 and a reason. The stream engine (OPEN, DATA, ACK, ...) runs after this and is not here.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from typing import List, Optional

from . import frames as F
from .errors import SessionError
from .frames import Frame, Hello, HelloAck, HelloExt, ServiceInfo, encode_hello_ext
from .handshake import handshake_initiator, handshake_responder
from .identity import HybridIdentity
from .tunnel import LinkKeys, Sealer, TunnelReader, write_frame

#: The frame version HELLO and HELLO_ACK carry. The negotiated version is in their bodies.
HELLO_FRAME_VERSION = 2


@dataclass
class Session:
    peer_node_id: str
    version: int
    peer_name: str
    peer_services: List[ServiceInfo]
    keys: LinkKeys
    sealer: Sealer
    inbound: TunnelReader
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter


async def connect(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    identity: HybridIdentity,
    *,
    name: str = "",
    expect_node_id: Optional[str] = None,
    nonce: Optional[bytes] = None,
) -> Session:
    """Open a session as the initiator: handshake, then HELLO and its answer."""
    handshake = await handshake_initiator(reader, writer, identity, expect_node_id)
    sealer = Sealer(handshake.keys.send)
    inbound = TunnelReader(handshake.keys)
    nonce = nonce if nonce is not None else os.urandom(16)
    hello = Hello(
        min_version=F.VERSION_MIN,
        max_version=F.VERSION_CURRENT,
        node_id=identity.node_id,
        name=name,
        services=[],
        ext=encode_hello_ext(HelloExt()),
        nonce=nonce,
    )
    await write_frame(writer, sealer, Frame.with_body(HELLO_FRAME_VERSION, F.HELLO, 1, hello))

    answer = await inbound.next_frame(reader)
    if answer.kind != F.HELLO_ACK:
        raise SessionError(f"expected HELLO_ACK, got kind {answer.kind:#04x}")
    ack = answer.decode()
    if ack.nonce != nonce:
        raise SessionError("the answer echoes a different hello nonce")
    if ack.version == 0:
        raise SessionError(f"the peer refused the session: {ack.reason}")
    if ack.node_id != handshake.peer_node_id:
        raise SessionError("the hello answer names a different node than the handshake proved")
    if not F.VERSION_MIN <= ack.version <= F.VERSION_CURRENT:
        raise SessionError(f"the peer agreed to version {ack.version}, outside our range")
    return Session(
        peer_node_id=ack.node_id,
        version=ack.version,
        peer_name=ack.name,
        peer_services=ack.services,
        keys=handshake.keys,
        sealer=sealer,
        inbound=inbound,
        reader=reader,
        writer=writer,
    )


async def accept(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    identity: HybridIdentity,
    *,
    name: str = "",
) -> Session:
    """Open a session as the responder: handshake, then the HELLO and our answer to it."""
    handshake = await handshake_responder(reader, writer, identity)
    sealer = Sealer(handshake.keys.send)
    inbound = TunnelReader(handshake.keys)
    first = await inbound.next_frame(reader)
    if first.kind != F.HELLO:
        raise SessionError(f"expected HELLO, got kind {first.kind:#04x}")
    hello = first.decode()

    reason = ""
    agreed: Optional[int] = None
    if hello.node_id != handshake.peer_node_id:
        reason = f"the hello names {hello.node_id} but the handshake proved {handshake.peer_node_id}"
    else:
        agreed = F.negotiate(hello.min_version, hello.max_version)
        if agreed is None:
            reason = f"no common protocol version: it speaks {hello.min_version}-{hello.max_version}"
    ack = HelloAck(
        version=agreed or 0,
        node_id=identity.node_id,
        name=name,
        services=[],
        nonce=hello.nonce,
        reason=reason,
        ext=b"",
    )
    await write_frame(writer, sealer, Frame.with_body(HELLO_FRAME_VERSION, F.HELLO_ACK, 1, ack))
    if agreed is None:
        raise SessionError(f"refused the session: {reason}")
    return Session(
        peer_node_id=hello.node_id,
        version=agreed,
        peer_name=hello.name,
        peer_services=hello.services,
        keys=handshake.keys,
        sealer=sealer,
        inbound=inbound,
        reader=reader,
        writer=writer,
    )
