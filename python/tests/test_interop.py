"""Interop with the Rust reference: its handshake and HELLO exchange, in both directions.

These tests run the reference's `interop_peer` example. Build it, then point `TRANSFERD_INTEROP_PEER`
at the executable, for example:

    cargo build -p transferd-overlay --example interop_peer
    set TRANSFERD_INTEROP_PEER=H:\\Projects\\Transferd\\target\\debug\\examples\\interop_peer.exe

Without the variable the tests are skipped.
"""

import asyncio
import json
import os
import subprocess
from pathlib import Path

import pytest

from transferd.identity import HybridIdentity
from transferd.session import accept, connect

PEER = os.environ.get("TRANSFERD_INTEROP_PEER", "")

pytestmark = pytest.mark.skipif(
    not PEER or not Path(PEER).exists(),
    reason="set TRANSFERD_INTEROP_PEER to the built interop_peer example",
)

# Seeds shared with the reference peer. Their node ids are derived here, from the same seeds.
RUST_SEED = bytes(range(64))
RUST_DIAL_SEED = bytes((i * 11 + 5) & 0xFF for i in range(64))
PY_SEED = bytes((i * 7 + 3) & 0xFF for i in range(64))


def test_python_initiator_to_rust_responder():
    rust = HybridIdentity(RUST_SEED, "rust")
    python = HybridIdentity(PY_SEED, "python")
    proc = subprocess.Popen(
        [PEER, "serve", "0", RUST_SEED.hex()],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        listening = json.loads(proc.stdout.readline())["listening"]
        host, port = listening.rsplit(":", 1)

        async def run():
            reader, writer = await asyncio.open_connection(host, int(port))
            try:
                return await connect(reader, writer, python, name="python", expect_node_id=rust.node_id)
            finally:
                writer.close()

        session = asyncio.run(run())
        assert session.peer_node_id == rust.node_id
        assert session.version == 3

        summary = json.loads(proc.stdout.readline())
        assert summary == {"role": "responder", "peer": python.node_id, "peer_name": "python", "version": 3}
        assert proc.wait(timeout=60) == 0, proc.stderr.read()
    finally:
        if proc.poll() is None:
            proc.kill()


def test_rust_initiator_to_python_responder():
    rust = HybridIdentity(RUST_DIAL_SEED, "rust-dial")
    python = HybridIdentity(PY_SEED, "python")

    async def scenario():
        accepted: asyncio.Future = asyncio.get_running_loop().create_future()

        async def handle(reader, writer):
            try:
                accepted.set_result(await accept(reader, writer, python, name="python"))
            except Exception as exc:  # surfaced to the test below
                if not accepted.done():
                    accepted.set_exception(exc)
            finally:
                writer.close()

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            proc = await asyncio.create_subprocess_exec(
                PEER,
                "dial",
                str(port),
                RUST_DIAL_SEED.hex(),
                python.node_id,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            session = await asyncio.wait_for(accepted, 60)
            out, err = await asyncio.wait_for(proc.communicate(), 60)
            return session, proc.returncode, out.decode(), err.decode()
        finally:
            server.close()

    session, returncode, out, err = asyncio.run(scenario())
    assert session.peer_node_id == rust.node_id
    assert session.version == 3
    assert returncode == 0, err
    summary = json.loads(out.strip().splitlines()[-1])
    assert summary == {"role": "initiator", "peer": python.node_id, "peer_name": "python", "version": 3}
