"""Load balancing across routes: a route is charged for the bytes it still has to clear, a frame that one route refuses
goes out on the next, and a control frame is not held up behind bulk data.

Mirrors `typescript/test/load_balance.test.ts`, which mirrors `crates/transferd-overlay/src/link.rs` and `session.rs`.
"""

import asyncio
import os

from transferd.frames import DATA, FLAG_BULK, VERSION_CURRENT, WINDOW, Frame
from transferd.identity import HybridIdentity
from transferd.link import SEND_QUEUE, MemoryLink, RouteKind, RouteMetrics, TcpLink, ranked_routes
from transferd.overlay import OverlaySession, SessionEvent, SessionSetup, spawn
from transferd.tunnel import derive_link_keys


class RefusingLink(MemoryLink):
    """A route that refuses every frame, as a route whose queue is full does. It counts the attempts."""

    def __init__(self, link_id: int) -> None:
        super().__init__(RouteKind.DIRECT, link_id=link_id)
        self.attempts = 0

    def send(self, frame) -> bool:
        self.attempts += 1
        return False


def setup(me: HybridIdentity, peer: HybridIdentity) -> SessionSetup:
    return SessionSetup(peer_node_id=peer.node_id, peer_name=peer.name, identity=me)


async def next_open(session: OverlaySession, events: asyncio.Queue) -> int:
    """Waits for the next stream the peer asks to open, accepts it, and returns its id."""
    while True:
        event: SessionEvent = await asyncio.wait_for(events.get(), 10)
        if event.kind == "open_request":
            await session.authorize(event.stream, event.service, True)
            return event.stream


async def read_all(session: OverlaySession, stream: int) -> bytes:
    out = bytearray()
    while True:
        chunk = await asyncio.wait_for(session.recv(stream), 30)
        if chunk is None:
            return bytes(out)
        out += chunk


def test_a_routes_cost_charges_its_backlog_in_time_at_its_measured_speed():
    busy = RouteMetrics(rtt_ms=10.0, loss=0.0, mbps=100.0, active=1, outstanding_bytes=1_000_000, up=True)
    # 1 MB is 8 Mbit. At 100 Mbit/s that is 80 ms, on top of the 10 ms round trip.
    assert abs(busy.cost() - 90.0) < 1e-9
    assert RouteMetrics(rtt_ms=10.0, mbps=100.0, up=True).cost() == 10.0


def test_the_route_with_the_smaller_backlog_ranks_first():
    busy, _ = MemoryLink.pair(first_id=1, second_id=1)
    idle, _ = MemoryLink.pair(first_id=2, second_id=2)
    busy.stats.record_rtt(10.0)
    idle.stats.record_rtt(10.0)
    busy.stats.record_data_out(1_000_000)
    assert [link.id for link in ranked_routes([busy, idle])] == [2, 1]


def test_a_frame_that_one_route_refuses_goes_out_on_the_next_route():
    async def main():
        desk_id = HybridIdentity.generate("desktop")
        phone_id = HybridIdentity.generate("phone")
        desk_events: asyncio.Queue = asyncio.Queue()
        refusing = RefusingLink(1)
        working, phone_end = MemoryLink.pair(first_id=2, second_id=2)
        desk = spawn(setup(desk_id, phone_id), [refusing, working], desk_events)
        phone = spawn(setup(phone_id, desk_id), [phone_end], asyncio.Queue())

        upload = os.urandom(200 * 1024)
        download = os.urandom(200 * 1024)
        opening = asyncio.ensure_future(phone.open("cfs"))
        stream = await asyncio.wait_for(next_open(desk, desk_events), 5)
        assert await asyncio.wait_for(opening, 5) == stream

        # The desk's replies (window updates, acknowledgements) try the refusing route first, every time.
        await phone.send(stream, upload, fin=True)
        assert await read_all(desk, stream) == upload, "the desk gets every uploaded byte"

        # The desk's own data falls back the same way.
        await desk.send(stream, download, fin=True)
        assert await read_all(phone, stream) == download, "the phone gets every downloaded byte"

        assert refusing.attempts > 0, "the refusing route was tried before the session fell back"
        await desk.shutdown()
        await phone.shutdown()

    asyncio.run(main())


def test_a_control_frame_is_accepted_while_the_bulk_queue_is_full():
    async def main():
        keys = derive_link_keys(os.urandom(32))
        accepted: asyncio.Queue = asyncio.Queue()

        async def on_connect(reader, writer):
            await accepted.put((reader, writer))

        # The server accepts and never reads, so the sender's socket backs up and its writer stops taking frames.
        server = await asyncio.start_server(on_connect, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        client_reader, client_writer = await asyncio.open_connection("127.0.0.1", port)
        server_reader, server_writer = await asyncio.wait_for(accepted.get(), 5)

        sender = TcpLink(client_reader, client_writer, keys)
        sender.start()

        def bulk(seq: int) -> Frame:
            return Frame(version=VERSION_CURRENT, kind=DATA, flags=FLAG_BULK, seq=seq, body=bytes(64 * 1024))

        # Queue bulk frames without yielding to the loop, so the writer cannot drain any of them while they are added.
        queued = 0
        while sender.send(bulk(queued)):
            queued += 1
        try:
            assert queued == SEND_QUEUE, "the bulk queue holds SEND_QUEUE frames"
            assert sender.send(bulk(queued)) is False, "a bulk frame is refused once the bulk queue is full"

            control = Frame(version=VERSION_CURRENT, kind=WINDOW, flags=0, seq=queued, body=b"")
            assert sender.send(control) is True, "a control frame is still accepted: it has its own queue"
        finally:
            sender.close()
            client_writer.close()
            server_writer.close()
            server.close()

    asyncio.run(main())
