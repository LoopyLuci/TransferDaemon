"""The relay path against the reference relay: handshakes, sessions and refusals over relayd.

Build the relay, then point `TRANSFERD_RELAYD` at the executable, as in `test_relay_interop.py`. Without the variable
the tests are skipped. Each test starts its own relayd on a free UDP port, at a low proof-of-work difficulty.
"""

import asyncio
import os
import socket
import subprocess
from pathlib import Path

import pytest

from transferd import relay_hub
from transferd.errors import HandshakeError, OverlayError
from transferd.identity import HybridIdentity, relay_token_for
from transferd.overlay import SessionSetup, spawn
from transferd.frames import PING, VERSION_CURRENT, Frame
from transferd.punch import PunchKeys, PunchParams, addr_text
from transferd.relay_hub import RelayHub

RELAYD = os.environ.get("TRANSFERD_RELAYD", "")

pytestmark = pytest.mark.skipif(
    not RELAYD or not Path(RELAYD).exists(),
    reason="set TRANSFERD_RELAYD to the built relayd binary",
)

DESK_SEED = bytes((i * 5 + 9) & 0xFF for i in range(64))
PHONE_SEED = bytes((i * 3 + 17) & 0xFF for i in range(64))
DIFFICULTY = 12


def _free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


@pytest.fixture
def relay_addr():
    port = _free_udp_port()
    # The relay's per-address rate limit is raised: every node in these tests shares one address, so the default limit
    # (300 datagrams per 30 seconds) would throttle the tests rather than test the overlay. relayd's own tests cover it.
    env = {
        **os.environ,
        "RELAYD_BIND": f"127.0.0.1:{port}",
        "RELAYD_DIFFICULTY": str(DIFFICULTY),
        "RELAYD_RATE_PER_30S": "1000000",
    }
    proc = subprocess.Popen([RELAYD], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        line = proc.stdout.readline()
        assert "listening" in line, proc.stderr.read()
        yield ("127.0.0.1", port)
    finally:
        proc.kill()
        proc.wait()


async def _echo(session, stream: int) -> None:
    """Echo one stream to its end, then end it."""
    while True:
        chunk = await session.recv(stream)
        if chunk is None:
            break
        await session.send(stream, chunk)
    await session.send(stream, b"", fin=True)


async def _serve(session, events: asyncio.Queue) -> None:
    """Answer the streams a peer opens: `echo` is echoed, anything else is refused."""
    while True:
        event = await events.get()
        if event.kind == "open_request":
            if event.service == "echo":
                await session.authorize(event.stream, event.service, True)
                asyncio.ensure_future(_echo(session, event.stream))
            else:
                await session.authorize(event.stream, event.service, False, "no such service")
        elif event.kind in ("down", "refused"):
            return


async def _read_all(session, stream: int) -> bytes:
    out = bytearray()
    while True:
        chunk = await asyncio.wait_for(session.recv(stream), 60)
        if chunk is None:
            return bytes(out)
        out += chunk


def test_a_session_over_the_relay_carries_bytes_both_ways(relay_addr):
    desk = HybridIdentity(DESK_SEED, "desk")
    phone = HybridIdentity(PHONE_SEED, "phone")

    async def main():
        adopted = asyncio.Event()
        sessions: list = []
        servers: list = []

        async def adopt(link, peer_id, peer_key, sender):
            events: asyncio.Queue = asyncio.Queue()
            session = spawn(SessionSetup(peer_node_id=peer_id, peer_name="phone", identity=desk), [link], events)
            sessions.append(session)
            servers.append(asyncio.ensure_future(_serve(session, events)))
            adopted.set()

        desk_hub = RelayHub(relay_addr, relay_token_for(desk.node_id), desk, on_adopt=adopt)
        phone_hub = RelayHub(relay_addr, relay_token_for(phone.node_id), phone)
        await desk_hub.start()
        await phone_hub.start()
        phone_session = None
        try:
            keys, peer_key = await phone_hub.handshake(desk.node_id, relay_token_for(desk.node_id))
            assert peer_key == desk.public_key, "the relay handshake yields the desk's own key"
            link = phone_hub.link(relay_token_for(desk.node_id), keys)
            phone_session = spawn(
                SessionSetup(peer_node_id=desk.node_id, peer_name="desk", identity=phone),
                [link],
                asyncio.Queue(),
            )
            await asyncio.wait_for(adopted.wait(), 30)
            assert await phone_session.ready(30), "the desk answers our hello over the relay"

            payload = os.urandom(200 * 1024)
            stream = await asyncio.wait_for(phone_session.open("echo"), 30)
            await phone_session.send(stream, payload, fin=True)
            assert await _read_all(phone_session, stream) == payload, "every echoed byte matches"
        finally:
            if phone_session is not None:
                await phone_session.shutdown()
            for session in sessions:
                await session.shutdown()
            for server in servers:
                server.cancel()
            await phone_hub.close()
            await desk_hub.close()

    asyncio.run(asyncio.wait_for(main(), 180))


def test_a_handshake_that_reaches_another_node_is_refused(relay_addr):
    desk = HybridIdentity(DESK_SEED, "desk")
    phone = HybridIdentity(PHONE_SEED, "phone")

    async def main():
        desk_hub = RelayHub(relay_addr, relay_token_for(desk.node_id), desk)
        phone_hub = RelayHub(relay_addr, relay_token_for(phone.node_id), phone)
        await desk_hub.start()
        await phone_hub.start()
        try:
            # The token is the desk's, but the node we say we dialled is the phone: the answer names the desk.
            with pytest.raises(HandshakeError):
                await phone_hub.handshake(phone.node_id, relay_token_for(desk.node_id))
        finally:
            await phone_hub.close()
            await desk_hub.close()

    asyncio.run(asyncio.wait_for(main(), 120))


def test_a_peer_the_node_refuses_gets_no_answer(relay_addr, monkeypatch):
    desk = HybridIdentity(DESK_SEED, "desk")
    phone = HybridIdentity(PHONE_SEED, "phone")
    monkeypatch.setattr(relay_hub, "HANDSHAKE_TIMEOUT", 2.0)

    async def main():
        adopted: list = []

        async def adopt(*args):
            adopted.append(args)

        desk_hub = RelayHub(
            relay_addr,
            relay_token_for(desk.node_id),
            desk,
            admit=lambda _node_id, _key: False,
            on_adopt=adopt,
        )
        phone_hub = RelayHub(relay_addr, relay_token_for(phone.node_id), phone)
        await desk_hub.start()
        await phone_hub.start()
        try:
            # A refused flight gets no answer, so the dialler's handshake times out rather than being told why.
            with pytest.raises(OverlayError, match="did not answer"):
                await phone_hub.handshake(desk.node_id, relay_token_for(desk.node_id))
            assert adopted == [], "the node never adopts a refused peer's link"
        finally:
            await phone_hub.close()
            await desk_hub.close()

    asyncio.run(asyncio.wait_for(main(), 120))


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


def _as_addr(text: str):
    """A candidate's `ip:port` text as an address (the node does this when a peer's candidates arrive)."""
    host, port = text.rsplit(":", 1)
    return (host.strip("[]"), int(port))


def test_a_hole_punch_between_two_nodes_on_one_relay_opens_a_route(relay_addr):
    desk = HybridIdentity(DESK_SEED, "desk")
    phone = HybridIdentity(PHONE_SEED, "phone")

    async def main():
        desk_hub = RelayHub(relay_addr, relay_token_for(desk.node_id), desk)
        phone_hub = RelayHub(relay_addr, relay_token_for(phone.node_id), phone)
        await desk_hub.start()
        await phone_hub.start()
        try:
            # Each side learns the other's candidates through the relay, as a node does before it punches.
            desk_candidates = await desk_hub.punch_candidates(relay_token_for(phone.node_id))
            phone_candidates = await phone_hub.punch_candidates(relay_token_for(desk.node_id))
            assert desk_candidates[0].addr == addr_text(desk_hub.client.local_addr), "the relay sees the desk's socket"
            keys = PunchKeys.derive(11, os.urandom(32), os.urandom(32))
            desk_run = desk_hub.punch_begin(
                PunchParams(
                    id=11,
                    initiator=True,
                    keys=keys,
                    candidates=[_as_addr(c.addr) for c in phone_candidates],
                    link_id=21,
                )
            )
            phone_run = phone_hub.punch_begin(
                PunchParams(
                    id=11,
                    initiator=False,
                    keys=keys,
                    candidates=[_as_addr(c.addr) for c in desk_candidates],
                    link_id=22,
                )
            )
            desk_link, phone_link = await asyncio.wait_for(
                asyncio.gather(desk_run.finish(), phone_run.finish()), 20
            )
            desk_link.send(Frame(VERSION_CURRENT, PING, 0, 1, b"punched hello"))
            assert (await _next_frame(phone_link)).body == b"punched hello"
        finally:
            await phone_hub.close()
            await desk_hub.close()

    asyncio.run(asyncio.wait_for(main(), 120))
