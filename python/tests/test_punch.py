"""Hole punching between two nodes on one machine: the probes, the route they open, and the gateway envelope.

Mirrors `typescript/test/punch.test.ts`. Each node is a relay client whose socket is open but never registered: the
client sends nothing to its relay address (the discard port here), it only reads the address its socket uses. The
punch over a relay's candidates is in `test_relay_hub.py`.
"""

import asyncio
import os
import socket

import pytest

from transferd.errors import OverlayError
from transferd.frames import PING, VERSION_CURRENT, Frame
from transferd.link import RouteKind
from transferd.punch import (
    Probe,
    PunchKeys,
    PunchParams,
    PunchTable,
    decode_probe,
    encode_probe,
    gateway_unwrap,
    gateway_wrap,
)
from transferd.relay_client import RelayClient


async def _node(gateway=None):
    client = RelayClient(("127.0.0.1", 9))
    await client.open()
    return client, PunchTable(client, gateway=gateway, relay_is_loopback=True)


async def _next_frame(link, timeout: float = 5.0) -> Frame:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        frame = link.try_recv()
        if frame is not None:
            return frame
        if loop.time() > deadline:
            raise AssertionError("no frame arrived over the punched route")
        await asyncio.sleep(0.005)


def test_a_loopback_punch_opens_a_route_that_carries_frames_both_ways():
    async def main():
        a_client, a_table = await _node()
        b_client, b_table = await _node()
        try:
            keys = PunchKeys.derive(7, os.urandom(32), os.urandom(32))
            a_run = a_table.begin(
                PunchParams(id=7, initiator=True, keys=keys, candidates=[b_client.local_addr], link_id=1)
            )
            b_run = b_table.begin(
                PunchParams(id=7, initiator=False, keys=keys, candidates=[a_client.local_addr], link_id=2)
            )
            a_link, b_link = await asyncio.wait_for(asyncio.gather(a_run.finish(), b_run.finish()), 15)
            assert a_link.kind is RouteKind.HOLEPUNCH
            assert b_link.kind is RouteKind.HOLEPUNCH

            a_link.send(Frame(VERSION_CURRENT, PING, 0, 1, b"from a"))
            assert (await _next_frame(b_link)).body == b"from a"
            b_link.send(Frame(VERSION_CURRENT, PING, 0, 2, b"from b"))
            assert (await _next_frame(a_link)).body == b"from b"
        finally:
            a_client.close()
            b_client.close()

    asyncio.run(main())


def test_a_peer_naming_no_usable_address_is_refused():
    async def main():
        client, table = await _node()
        try:
            # Unspecified, and port 0: neither can be a peer, so nothing is probed.
            params = PunchParams(
                id=9,
                initiator=True,
                keys=PunchKeys.derive(9, b"\x01" * 32, b"\x02" * 32),
                candidates=[("0.0.0.0", 4000), ("127.0.0.1", 0)],
                link_id=3,
            )
            with pytest.raises(OverlayError, match="no usable address"):
                table.begin(params)
        finally:
            client.close()

    asyncio.run(main())


def test_a_probe_through_the_gateway_is_unwrapped_and_answered_through_it():
    async def main():
        # A stand-in gateway: a plain socket that sends and receives what the node sends through it.
        gateway = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        gateway.bind(("127.0.0.1", 0))
        gateway.setblocking(False)
        client, table = await _node(gateway=gateway.getsockname())
        try:
            peer = ("127.0.0.1", 40123)  # an address the peer names; the envelope carries it to the node
            keys = PunchKeys.derive(5, b"\x03" * 32, b"\x04" * 32)
            table.begin(PunchParams(id=5, initiator=False, keys=keys, candidates=[peer], link_id=1))
            probe = encode_probe(keys, Probe(kind="probe", from_initiator=True, id=5, seq=0))
            gateway.sendto(gateway_wrap(peer, probe), client.local_addr)

            data, _ = await asyncio.wait_for(asyncio.get_running_loop().sock_recvfrom(gateway, 2048), 5)
            unwrapped = gateway_unwrap(data)
            assert unwrapped is not None, "the answer comes back through the gateway, wrapped"
            dest, inner = unwrapped
            assert dest == peer, "the answer is addressed to the peer"
            reply = decode_probe(keys, inner)
            assert reply is not None and reply.kind == "reply"
            assert (reply.id, reply.seq, reply.from_initiator) == (5, 0, False)
        finally:
            client.close()
            gateway.close()

    asyncio.run(main())
