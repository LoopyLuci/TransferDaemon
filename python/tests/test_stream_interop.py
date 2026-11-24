"""Streams against the Rust reference: a stream opened by Python is echoed back by the reference's multiplexer.

The reference runs `interop_peer echo`: after the handshake and HELLO, every stream the peer opens for the service
`echo` is echoed back, using the reference's own `Mux` for flow control, ordering and SACK. Payloads larger than the
256 KiB window need WINDOW credit from the reference in both directions, so this checks the window as well as the
frames. Build the example and point `TRANSFERD_INTEROP_PEER` at it, as in `test_interop.py`. Without the variable the
tests are skipped.
"""

import asyncio
import json
import os
import subprocess
from pathlib import Path

import pytest

from transferd.identity import HybridIdentity
from transferd.session import connect
from transferd.stream_session import StreamSession

PEER = os.environ.get("TRANSFERD_INTEROP_PEER", "")

pytestmark = pytest.mark.skipif(
    not PEER or not Path(PEER).exists(),
    reason="set TRANSFERD_INTEROP_PEER to the built interop_peer example",
)

RUST_SEED = bytes(range(64))
PY_SEED = bytes((i * 7 + 3) & 0xFF for i in range(64))


async def read_all(streams: StreamSession, sid: int) -> bytes:
    out = bytearray()
    while True:
        chunk = await streams.read(sid)
        if not chunk:
            return bytes(out)
        out.extend(chunk)


def test_a_stream_opened_by_python_is_echoed_by_the_rust_reference():
    rust = HybridIdentity(RUST_SEED, "rust")
    python = HybridIdentity(PY_SEED, "python")
    proc = subprocess.Popen(
        [PEER, "echo", "0", RUST_SEED.hex()],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        host, port = json.loads(proc.stdout.readline())["listening"].rsplit(":", 1)
        payload = os.urandom(600 * 1024)  # more than one window, so credit must come back both ways

        async def run() -> bytes:
            reader, writer = await asyncio.open_connection(host, int(port))
            session = await connect(reader, writer, python, name="python", expect_node_id=rust.node_id)
            streams = StreamSession(session, node_id=python.node_id, odd=False)
            streams.start()
            try:
                sid = await streams.open("echo")
                sent = streams.write(sid, payload, fin=True)
                received, _ = await asyncio.wait_for(asyncio.gather(read_all(streams, sid), sent), 60)
                await streams.close(sid)
                return received
            finally:
                await streams.aclose()
                writer.close()

        echoed = asyncio.run(run())
        assert echoed == payload

        line = proc.stdout.readline()
        assert line, f"the reference printed no summary: {proc.stderr.read()}"
        summary = json.loads(line)
        assert summary == {
            "role": "echo",
            "peer": python.node_id,
            "stream_bytes_in": len(payload),
            "stream_bytes_out": len(payload),
            "streams": 1,
        }
        assert proc.wait(timeout=60) == 0, proc.stderr.read()
    finally:
        if proc.poll() is None:
            proc.kill()
