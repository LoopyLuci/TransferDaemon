"""Streams the other way round: the Rust reference opens a stream, and Python echoes it back.

`test_stream_interop.py` has Python open the stream to the reference's echo. Here the reference's
`interop_peer stream` dials this test's listener, opens a stream for the service `echo`, sends 600 KiB
and checks every byte that comes back. Python plays the echo side with `StreamSession` and accepts the
stream the way any responder would. The run ends at the reference's close, so this covers the accept
path against the reference's own opener, which the loopback tests cannot.

Build the example and point `TRANSFERD_INTEROP_PEER` at it, as in `test_interop.py`. Without the
variable the test is skipped.
"""

import asyncio
import json
import os
from pathlib import Path

import pytest

from transferd.identity import HybridIdentity
from transferd.session import accept
from transferd.stream_session import StreamSession

PEER = os.environ.get("TRANSFERD_INTEROP_PEER", "")

pytestmark = pytest.mark.skipif(
    not PEER or not Path(PEER).exists(),
    reason="set TRANSFERD_INTEROP_PEER to the built interop_peer example",
)

RUST_SEED = bytes(range(64))
PY_SEED = bytes((i * 7 + 3) & 0xFF for i in range(64))


async def echo_one_stream(streams: StreamSession, echoed: dict) -> None:
    """Accept the first stream the peer opens for `echo`, echo it to its end, and close it."""
    sid, service = await streams.next_request()
    echoed["service"] = service
    if service != "echo":
        await streams.refuse(sid, "no_such_service", f"no service named {service}")
        return
    await streams.accept(sid)
    total = 0
    while True:
        chunk = await streams.read(sid)
        if not chunk:
            break
        total += len(chunk)
        await streams.write(sid, chunk)
    await streams.write(sid, b"", fin=True)
    echoed["bytes"] = total
    await streams.close(sid)


def test_a_stream_opened_by_the_rust_reference_is_echoed_by_python():
    rust = HybridIdentity(RUST_SEED, "rust")
    python = HybridIdentity(PY_SEED, "python")
    echoed: dict = {}

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            session = await accept(reader, writer, python, name="python")
            streams = StreamSession(session, node_id=python.node_id, odd=False)
            streams.start()
            try:
                await asyncio.wait_for(echo_one_stream(streams, echoed), 120)
            finally:
                await streams.aclose()
        finally:
            writer.close()

    async def run():
        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            proc = await asyncio.create_subprocess_exec(
                PEER,
                "stream",
                str(port),
                RUST_SEED.hex(),
                python.node_id,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            out, err = await asyncio.wait_for(proc.communicate(), 180)
            return proc.returncode, out.decode(), err.decode()
        finally:
            server.close()
            await server.wait_closed()

    code, out, err = asyncio.run(run())
    assert code == 0, f"the reference failed: {err}"
    summary = json.loads(out.strip().splitlines()[-1])
    assert summary == {
        "role": "stream",
        "peer": python.node_id,
        "stream_bytes_out": 600 * 1024,
        "stream_bytes_in": 600 * 1024,
        "streams": 1,
    }
    assert echoed == {"service": "echo", "bytes": 600 * 1024}
