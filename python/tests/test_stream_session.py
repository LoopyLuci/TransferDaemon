"""The stream driver over a real TCP connection, with the Python implementation on both ends.

These tests need no reference binary. They cover what the Rust echo peer does not exercise from Python's side: a
stream the peer accepts, a stream it refuses, and several streams interleaved on one session.
"""

import asyncio
import os

import pytest

from transferd.errors import StreamRefused
from transferd.identity import HybridIdentity
from transferd.session import accept, connect
from transferd.stream_session import StreamSession

A_SEED = bytes(range(64))
B_SEED = bytes((i * 5 + 9) & 0xFF for i in range(64))


async def read_all(streams: StreamSession, sid: int) -> bytes:
    out = bytearray()
    while True:
        chunk = await streams.read(sid)
        if not chunk:
            return bytes(out)
        out.extend(chunk)


class Pair:
    """Two stream sessions on one TCP connection: `client` opened it (odd=False), `peer` accepted it (odd=True)."""

    def __init__(self) -> None:
        self.client: StreamSession
        self.peer: StreamSession
        self._writers = []
        self._server = None

    async def __aenter__(self) -> "Pair":
        a = HybridIdentity(A_SEED, "a")
        b = HybridIdentity(B_SEED, "b")
        accepted: asyncio.Future = asyncio.get_running_loop().create_future()

        async def handle(reader, writer):
            self._writers.append(writer)
            session = await accept(reader, writer, b, name="b")
            streams = StreamSession(session, node_id=b.node_id, odd=True)
            streams.start()
            accepted.set_result(streams)

        self._server = await asyncio.start_server(handle, "127.0.0.1", 0)
        port = self._server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        self._writers.append(writer)
        session = await connect(reader, writer, a, name="a", expect_node_id=b.node_id)
        self.client = StreamSession(session, node_id=a.node_id, odd=False)
        self.client.start()
        self.peer = await asyncio.wait_for(accepted, 30)
        return self

    async def __aexit__(self, *exc_info) -> None:
        await self.client.aclose()
        await self.peer.aclose()
        for writer in self._writers:
            writer.close()
        self._server.close()


def test_a_stream_carries_bytes_both_ways_past_the_window():
    async def scenario():
        async with Pair() as pair:
            # An open completes only when the peer accepts it, so the open runs alongside the accept.
            opening = asyncio.ensure_future(pair.client.open("echo"))
            sid, service = await asyncio.wait_for(pair.peer.next_request(), 10)
            assert service == "echo"
            await pair.peer.accept(sid)
            assert await asyncio.wait_for(opening, 10) == sid

            payload = os.urandom(300 * 1024)  # more than the 256 KiB window, so the sender must wait for credit

            async def echo_back() -> bytes:
                got = await read_all(pair.peer, sid)
                await pair.peer.write(sid, got, fin=True)
                return got

            sent = pair.client.write(sid, payload, fin=True)
            echoed, _, returned = await asyncio.wait_for(
                asyncio.gather(read_all(pair.client, sid), sent, echo_back()), 60
            )
            await pair.client.close(sid)
            return payload, returned, echoed

    payload, at_peer, echoed = asyncio.run(scenario())
    assert at_peer == payload, "the peer received every byte, in order"
    assert echoed == payload, "and the echo came back whole"


def test_a_refused_stream_raises_the_refusal_at_the_opener():
    async def scenario():
        async with Pair() as pair:
            opening = asyncio.ensure_future(pair.client.open("nope"))
            sid, service = await asyncio.wait_for(pair.peer.next_request(), 10)
            assert service == "nope"
            await pair.peer.refuse(sid, "no_such_service", "nothing is exposed as nope")
            with pytest.raises(StreamRefused) as refused:
                await asyncio.wait_for(opening, 10)
            return refused.value

    refusal = asyncio.run(scenario())
    assert refusal.code == "no_such_service"
    assert refusal.reason == "nothing is exposed as nope"


def test_several_streams_interleave_on_one_session():
    async def scenario():
        async with Pair() as pair:
            openings = [asyncio.ensure_future(pair.client.open(f"svc{i}")) for i in range(3)]
            for _ in openings:
                sid, _service = await asyncio.wait_for(pair.peer.next_request(), 10)
                await pair.peer.accept(sid)
            ids = [await asyncio.wait_for(opening, 10) for opening in openings]
            payloads = {sid: os.urandom(20000 + 1000 * i) for i, sid in enumerate(ids)}

            async def echo_back(sid: int) -> None:
                got = await read_all(pair.peer, sid)
                await pair.peer.write(sid, got, fin=True)

            tasks = []
            for sid, data in payloads.items():
                tasks.append(pair.client.write(sid, data, fin=True))
                tasks.append(echo_back(sid))
                tasks.append(read_all(pair.client, sid))
            results = await asyncio.wait_for(asyncio.gather(*tasks), 60)
            return payloads, results[2::3]

    payloads, echoed = asyncio.run(scenario())
    assert echoed == list(payloads.values()), "each stream carried its own bytes back, in its own order"
