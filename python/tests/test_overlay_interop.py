"""The overlay session against the reference's own session engine, in both directions.

`interop_peer overlay-echo` runs the node's session engine (`session.rs`) over TCP and echoes every stream for the
service `echo`. Here Python dials it, opens `echo`, sends 300 KiB and checks the echo. The other direction runs
`interop_peer overlay-stream`, which dials this test's listener, opens `echo`, sends 600 KiB and checks the echo, while
Python plays the echo side through its own session engine. Both directions cover the whole path: the handshake,
the tunnel, the overlay frames and the stream engine, against the reference's implementation of each.

Build the example and point `TRANSFERD_INTEROP_PEER` at it, as in `test_interop.py`. Without the variable the tests
are skipped.
"""

import asyncio
import json
import os
import subprocess
from pathlib import Path

import pytest

from transferd.errors import StreamReset
from transferd.handshake import handshake_initiator, handshake_responder
from transferd.identity import HybridIdentity
from transferd.link import RouteKind, TcpLink
from transferd.overlay import SessionSetup, spawn

PEER = os.environ.get("TRANSFERD_INTEROP_PEER", "")

pytestmark = pytest.mark.skipif(
    not PEER or not Path(PEER).exists(),
    reason="set TRANSFERD_INTEROP_PEER to the built interop_peer example",
)

RUST_SEED = bytes(range(64))
PY_SEED = bytes((i * 7 + 3) & 0xFF for i in range(64))
STREAM_BYTES = 600 * 1024


async def read_all(session, stream: int) -> bytes:
    out = bytearray()
    while True:
        chunk = await asyncio.wait_for(session.recv(stream), 60)
        if chunk is None:
            return bytes(out)
        out += chunk


def test_python_dials_the_reference_overlay_and_gets_its_echo():
    rust = HybridIdentity(RUST_SEED, "rust")
    python = HybridIdentity(PY_SEED, "python")
    proc = subprocess.Popen(
        [PEER, "overlay-echo", "0", RUST_SEED.hex()],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        listening = json.loads(proc.stdout.readline())["listening"]
        host, port = listening.rsplit(":", 1)

        async def main():
            reader, writer = await asyncio.open_connection(host, int(port))
            result = await handshake_initiator(reader, writer, python, rust.node_id)
            link = TcpLink(reader, writer, result.keys, kind=RouteKind.DIRECT)
            link.start()
            session = spawn(
                SessionSetup(peer_node_id=rust.node_id, peer_name="rust", identity=python),
                [link],
                asyncio.Queue(),
            )
            try:
                assert await session.ready(10), "the reference answers our hello"
                stream = await asyncio.wait_for(session.open("echo"), 10)
                payload = os.urandom(300 * 1024)
                await session.send(stream, payload, fin=True)
                assert await read_all(session, stream) == payload, "every echoed byte matches"
            finally:
                await session.shutdown()
                writer.close()

        asyncio.run(asyncio.wait_for(main(), 120))
    finally:
        proc.kill()
        proc.wait()


def test_the_reference_overlay_dials_python_and_python_echoes():
    rust = HybridIdentity(RUST_SEED, "rust")
    python = HybridIdentity(PY_SEED, "python")
    echoed: dict = {}
    sessions: list = []

    async def echo_one(session, stream: int, service: str) -> None:
        if service != "echo":
            return
        total = 0
        while True:
            chunk = await session.recv(stream)
            if chunk is None:
                break
            total += len(chunk)
            await session.send(stream, chunk)
        await session.send(stream, b"", fin=True)
        echoed["bytes"] = total
        echoed["service"] = service

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        result = await handshake_responder(reader, writer, python)
        link = TcpLink(reader, writer, result.keys, kind=RouteKind.DIRECT)
        link.start()
        events: asyncio.Queue = asyncio.Queue()
        session = spawn(SessionSetup(peer_node_id=rust.node_id, peer_name="rust", identity=python), [link], events)
        sessions.append(session)
        try:
            while True:
                event = await events.get()
                if event.kind == "open_request":
                    if event.service != "echo":
                        await session.authorize(event.stream, event.service, False, "no such service")
                        continue
                    await session.authorize(event.stream, event.service, True)
                    asyncio.ensure_future(echo_one(session, event.stream, event.service))
                elif event.kind in ("down", "refused"):
                    return
        finally:
            writer.close()

    async def run():
        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            proc = await asyncio.create_subprocess_exec(
                PEER,
                "overlay-stream",
                str(port),
                RUST_SEED.hex(),
                python.node_id,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            out, err = await asyncio.wait_for(proc.communicate(), 180)
            return proc.returncode, out.decode(), err.decode()
        finally:
            for session in sessions:
                await session.shutdown()
            server.close()

    code, out, err = asyncio.run(run())
    assert code == 0, f"the reference failed: {err}"
    summary = json.loads(out.strip().splitlines()[-1])
    assert summary == {
        "role": "overlay_stream",
        "peer": python.node_id,
        "bytes": STREAM_BYTES,
        "verified": True,
    }
    assert echoed == {"bytes": STREAM_BYTES, "service": "echo"}


def test_python_closes_a_flushed_stream_at_once_against_the_reference():
    rust = HybridIdentity(RUST_SEED, "rust")
    python = HybridIdentity(PY_SEED, "python")
    proc = subprocess.Popen(
        [PEER, "overlay-echo", "0", RUST_SEED.hex()],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        listening = json.loads(proc.stdout.readline())["listening"]
        host, port = listening.rsplit(":", 1)

        async def main():
            reader, writer = await asyncio.open_connection(host, int(port))
            result = await handshake_initiator(reader, writer, python, rust.node_id)
            link = TcpLink(reader, writer, result.keys, kind=RouteKind.DIRECT)
            link.start()
            session = spawn(
                SessionSetup(peer_node_id=rust.node_id, peer_name="rust", identity=python),
                [link],
                asyncio.Queue(),
            )
            try:
                assert await session.ready(10), "the reference answers our hello"
                stream = await asyncio.wait_for(session.open("echo"), 10)
                payload = os.urandom(300 * 1024)
                await session.send(stream, payload, fin=True)
                assert await read_all(session, stream) == payload, "every echoed byte matches"
                loop = asyncio.get_running_loop()
                started = loop.time()
                await asyncio.wait_for(session.close(stream), 10)
                # Everything went out and was acknowledged, so the close does not wait out the flush limit.
                assert loop.time() - started < 2, "a flushed stream closes at once"
            finally:
                await session.shutdown()
                writer.close()

        asyncio.run(asyncio.wait_for(main(), 120))
    finally:
        proc.kill()
        proc.wait()


def test_a_stream_the_reference_ends_with_a_refusal_is_an_error_in_python():
    rust = HybridIdentity(RUST_SEED, "rust")
    python = HybridIdentity(PY_SEED, "python")
    proc = subprocess.Popen(
        [PEER, "overlay-echo", "0", RUST_SEED.hex()],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        listening = json.loads(proc.stdout.readline())["listening"]
        host, port = listening.rsplit(":", 1)

        async def main():
            reader, writer = await asyncio.open_connection(host, int(port))
            result = await handshake_initiator(reader, writer, python, rust.node_id)
            link = TcpLink(reader, writer, result.keys, kind=RouteKind.DIRECT)
            link.start()
            session = spawn(
                SessionSetup(peer_node_id=rust.node_id, peer_name="rust", identity=python),
                [link],
                asyncio.Queue(),
            )
            try:
                assert await session.ready(10), "the reference answers our hello"
                # The reference accepts "refuse" and then ends the stream with a refusal: not the end.
                stream = await asyncio.wait_for(session.open("refuse"), 10)
                with pytest.raises(StreamReset) as caught:
                    await asyncio.wait_for(session.recv(stream), 10)
                assert "refused" in str(caught.value), f"the reason is kept: {caught.value}"
            finally:
                await session.shutdown()
                writer.close()

        asyncio.run(asyncio.wait_for(main(), 120))
    finally:
        proc.kill()
        proc.wait()
