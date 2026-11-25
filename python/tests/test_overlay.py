"""The overlay session: routes, streams and failover, run on in-memory and TCP routes.

The two restart tests are ported from the reference's `session.rs` tests. The others cover what the reference's
engine promises: a stream's bytes arrive whole and in order over one route, bulk data is striped across every route,
a stream survives a route that stops delivering, a refused open reaches the opener, and a session runs over real
sockets after the handshake.
"""

import asyncio
import os

from transferd.errors import Closed, NoSuchService
from transferd.handshake import handshake_initiator, handshake_responder
from transferd.identity import HybridIdentity
from transferd.link import MemoryLink, RouteKind, TcpLink
from transferd.overlay import OverlaySession, SessionEvent, SessionSetup, spawn


class Blackhole(MemoryLink):
    """A route that can stop delivering: once dead, its sends count as sent and never arrive."""

    def __init__(self, kind: RouteKind = RouteKind.DIRECT, *, link_id: int = 1) -> None:
        super().__init__(kind, link_id=link_id)
        self.dead = False

    def send(self, frame) -> bool:
        if self.dead:
            self.stats.record_sent(len(frame.body))
            return True
        return super().send(frame)


def blackhole_pair(link_id: int = 1):
    a, b = Blackhole(link_id=link_id), Blackhole(link_id=link_id)
    a._peer = b
    b._peer = a
    return a, b


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


async def open_stream_pair(link_id: int):
    """A desktop and a phone on one in-memory route, with a stream the phone opened and the desktop accepted."""
    desk_id = HybridIdentity.generate("desktop")
    phone_id = HybridIdentity.generate("phone")
    desk_events: asyncio.Queue = asyncio.Queue()
    a, b = _pair(link_id)
    desk = spawn(setup(desk_id, phone_id), [a], desk_events)
    phone = spawn(setup(phone_id, desk_id), [b], asyncio.Queue())
    opening = asyncio.ensure_future(phone.open("cfs"))
    stream = await asyncio.wait_for(next_open(desk, desk_events), 5)
    assert await asyncio.wait_for(opening, 5) == stream
    return desk, phone, stream


# A session that ends while a read waits is an error to that read. Silence is not the end of a stream: nothing says
# the stream was complete, so the reader must not take it for a finished transfer.
def test_a_read_waiting_when_the_session_ends_fails_rather_than_ending_the_stream():
    async def main():
        desk, phone, stream = await open_stream_pair(3)
        waiting = asyncio.ensure_future(desk.recv(stream))
        await asyncio.sleep(0.05)
        await desk.shutdown()
        try:
            outcome = await asyncio.wait_for(waiting, 5)
        except Closed:
            pass
        else:
            raise AssertionError(f"the read ended the stream instead of failing (got {outcome!r})")
        await phone.shutdown()

    asyncio.run(main())


def test_a_read_waiting_when_the_peer_closes_the_stream_gets_the_end():
    async def main():
        desk, phone, stream = await open_stream_pair(4)
        waiting = asyncio.ensure_future(desk.recv(stream))
        await asyncio.sleep(0.05)
        await phone.close(stream)
        assert await asyncio.wait_for(waiting, 5) is None
        await desk.shutdown()
        await phone.shutdown()

    asyncio.run(main())


def test_a_read_waiting_when_we_close_the_stream_gets_the_end():
    async def main():
        desk, phone, stream = await open_stream_pair(5)
        waiting = asyncio.ensure_future(desk.recv(stream))
        await asyncio.sleep(0.05)
        await desk.close(stream)
        assert await asyncio.wait_for(waiting, 5) is None
        await desk.shutdown()
        await phone.shutdown()

    asyncio.run(main())


def test_a_restarted_peer_is_heard_on_the_session_it_comes_back_to():
    async def main():
        desk_id = HybridIdentity.generate("desktop")
        phone_id = HybridIdentity.generate("phone")
        desk_events: asyncio.Queue = asyncio.Queue()
        old_route, phone_old_end = _pair(1)
        desk = spawn(setup(desk_id, phone_id), [old_route], desk_events)

        # The first phone process opens a stream, and the desktop accepts it.
        phone_first = spawn(setup(phone_id, desk_id), [phone_old_end], asyncio.Queue())
        first = asyncio.ensure_future(phone_first.open("cfs"))
        accepted = await asyncio.wait_for(next_open(desk, desk_events), 5)
        assert accepted is not None
        await asyncio.wait_for(first, 5)

        # The old process is gone, so its route carries nothing more. The desktop's session stays up and takes the
        # restarted phone on a new route.
        old_route.mark_down()
        new_route, phone_new_end = _pair(2)
        await desk.add_link(new_route)
        phone_restarted = spawn(setup(phone_id, desk_id), [phone_new_end], asyncio.Queue())
        second = asyncio.ensure_future(phone_restarted.open("cfs"))
        heard = await asyncio.wait_for(next_open(desk, desk_events), 5)
        assert heard is not None, "the desktop hears the restarted peer's open"
        await asyncio.wait_for(second, 5)

        await desk.shutdown()
        await phone_first.shutdown()
        await phone_restarted.shutdown()

    asyncio.run(main())


def test_a_restarted_peer_first_stream_delivers_its_bytes():
    async def main():
        desk_id = HybridIdentity.generate("desktop")
        phone_id = HybridIdentity.generate("phone")
        desk_events: asyncio.Queue = asyncio.Queue()
        old_route, phone_old_end = _pair(1)
        desk = spawn(setup(desk_id, phone_id), [old_route], desk_events)

        phone_first = spawn(setup(phone_id, desk_id), [phone_old_end], asyncio.Queue())
        opening = asyncio.ensure_future(phone_first.open("cfs"))
        first_stream = await asyncio.wait_for(next_open(desk, desk_events), 5)
        opened = await asyncio.wait_for(opening, 5)
        assert opened == first_stream
        await phone_first.send(first_stream, b"first")
        assert await asyncio.wait_for(desk.recv(first_stream), 5) == b"first", "the desktop reads the first stream"

        # The old process is gone. The desktop keeps its session and takes the restarted phone on a new route.
        await phone_first.shutdown()
        old_route.mark_down()
        new_route, phone_new_end = _pair(2)
        await desk.add_link(new_route)
        phone_restarted = spawn(setup(phone_id, desk_id), [phone_new_end], asyncio.Queue())
        opening = asyncio.ensure_future(phone_restarted.open("cfs"))
        second_stream = await asyncio.wait_for(next_open(desk, desk_events), 5)
        assert await asyncio.wait_for(opening, 5) == second_stream
        await phone_restarted.send(second_stream, b"second")
        assert await asyncio.wait_for(desk.recv(second_stream), 5) == b"second", "the desktop reads the restarted peer's bytes"

        await desk.shutdown()
        await phone_restarted.shutdown()

    asyncio.run(main())


def _pair(link_id: int):
    """A pair of in-memory routes with the same id at both ends, as the reference's tests use."""
    return MemoryLink.pair(first_id=link_id, second_id=link_id)


def test_a_stream_carries_its_bytes_whole_and_in_order_over_one_route():
    async def main():
        desk_id = HybridIdentity.generate("desktop")
        phone_id = HybridIdentity.generate("phone")
        desk_events: asyncio.Queue = asyncio.Queue()
        a, b = _pair(1)
        desk = spawn(setup(desk_id, phone_id), [a], desk_events)
        phone = spawn(setup(phone_id, desk_id), [b], asyncio.Queue())

        payload = os.urandom(300 * 1024)
        opening = asyncio.ensure_future(phone.open("cfs"))
        stream = await asyncio.wait_for(next_open(desk, desk_events), 5)
        assert await asyncio.wait_for(opening, 5) == stream
        await phone.send(stream, payload, fin=True)
        received = await read_all(desk, stream)
        assert received == payload

        await desk.shutdown()
        await phone.shutdown()

    asyncio.run(main())


def test_bulk_data_is_striped_across_every_route():
    async def main():
        desk_id = HybridIdentity.generate("desktop")
        phone_id = HybridIdentity.generate("phone")
        desk_events: asyncio.Queue = asyncio.Queue()
        a1, b1 = _pair(1)
        a2, b2 = _pair(2)
        desk = spawn(setup(desk_id, phone_id), [a1, a2], desk_events)
        phone = spawn(setup(phone_id, desk_id), [b1, b2], asyncio.Queue())

        payload = os.urandom(2 * 1024 * 1024)
        opening = asyncio.ensure_future(phone.open("bulk"))
        stream = await asyncio.wait_for(next_open(desk, desk_events), 5)
        assert await asyncio.wait_for(opening, 5) == stream
        await phone.send(stream, payload, fin=True)
        assert await read_all(desk, stream) == payload
        assert b1.stats.frames_sent() > 0 and b2.stats.frames_sent() > 0, "both routes carried bulk frames"

        await desk.shutdown()
        await phone.shutdown()

    asyncio.run(main())


def test_a_stream_survives_a_route_that_stops_delivering():
    async def main():
        desk_id = HybridIdentity.generate("desktop")
        phone_id = HybridIdentity.generate("phone")
        desk_events: asyncio.Queue = asyncio.Queue()
        good_a, good_b = _pair(2)
        dying_a, dying_b = blackhole_pair(1)
        desk = spawn(setup(desk_id, phone_id), [dying_a, good_a], desk_events)
        phone = spawn(setup(phone_id, desk_id), [dying_b, good_b], asyncio.Queue())

        payload = os.urandom(600 * 1024)
        opening = asyncio.ensure_future(phone.open("cfs"))
        stream = await asyncio.wait_for(next_open(desk, desk_events), 5)
        assert await asyncio.wait_for(opening, 5) == stream

        await phone.send(stream, payload[: 100 * 1024])
        await asyncio.sleep(0.2)
        # The first route now swallows everything, in both directions, the way a dead path does.
        dying_a.dead = True
        dying_b.dead = True
        await phone.send(stream, payload[100 * 1024 :], fin=True)

        received = await asyncio.wait_for(read_all(desk, stream), 60)
        assert received == payload, "every byte arrives, over the route that still works"

        await desk.shutdown()
        await phone.shutdown()

    asyncio.run(main())


def test_routes_are_probed_and_stay_up_while_they_answer():
    async def main():
        desk_id = HybridIdentity.generate("desktop")
        phone_id = HybridIdentity.generate("phone")
        a, b = _pair(1)
        desk = spawn(setup(desk_id, phone_id), [a], asyncio.Queue())
        phone = spawn(setup(phone_id, desk_id), [b], asyncio.Queue())
        assert await desk.ready(5)
        await asyncio.sleep(1.3)
        routes = desk.routes()
        assert len(routes) == 1
        assert routes[0].kind == "direct"
        assert routes[0].active, "a route that answers its probes stays up"
        assert desk.version() == phone.version() != 0

        await desk.shutdown()
        await phone.shutdown()

    asyncio.run(main())


def test_a_refused_open_reaches_the_opener_with_its_reason():
    async def main():
        desk_id = HybridIdentity.generate("desktop")
        phone_id = HybridIdentity.generate("phone")
        desk_events: asyncio.Queue = asyncio.Queue()
        a, b = _pair(1)
        desk = spawn(setup(desk_id, phone_id), [a], desk_events)
        phone = spawn(setup(phone_id, desk_id), [b], asyncio.Queue())

        opening = asyncio.ensure_future(phone.open("missing"))
        while True:
            event = await asyncio.wait_for(desk_events.get(), 5)
            if event.kind == "open_request":
                await desk.authorize(event.stream, event.service, False, "no such service")
                break
        try:
            await asyncio.wait_for(opening, 5)
        except NoSuchService as exc:
            assert exc.service == "missing"
        else:
            raise AssertionError("the refused open should have raised")

        await desk.shutdown()
        await phone.shutdown()

    asyncio.run(main())


def test_a_session_runs_over_real_sockets_after_the_handshake():
    async def main():
        desk_id = HybridIdentity.generate("desktop")
        phone_id = HybridIdentity.generate("phone")
        server_link: asyncio.Future = asyncio.get_running_loop().create_future()

        async def serve(reader, writer):
            result = await handshake_responder(reader, writer, desk_id)
            link = TcpLink(reader, writer, result.keys, kind=RouteKind.DIRECT)
            link.start()
            server_link.set_result(link)

        server = await asyncio.start_server(serve, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            result = await handshake_initiator(reader, writer, phone_id, desk_id.node_id)
            client = TcpLink(reader, writer, result.keys, kind=RouteKind.DIRECT)
            client.start()
            desk_events: asyncio.Queue = asyncio.Queue()
            desk = spawn(setup(desk_id, phone_id), [await asyncio.wait_for(server_link, 5)], desk_events)
            phone = spawn(setup(phone_id, desk_id), [client], asyncio.Queue())

            payload = os.urandom(200 * 1024)
            opening = asyncio.ensure_future(phone.open("cfs"))
            stream = await asyncio.wait_for(next_open(desk, desk_events), 5)
            assert await asyncio.wait_for(opening, 5) == stream
            await phone.send(stream, payload, fin=True)
            assert await read_all(desk, stream) == payload

            await desk.shutdown()
            await phone.shutdown()
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(main())
