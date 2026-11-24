"""Interop with the reference relay: relayd, run as a UDP server, driven by the Python client.

Build the relay, then point `TRANSFERD_RELAYD` at the executable, for example:

    cargo build -p relayd --bin relayd
    set TRANSFERD_RELAYD=H:\\Projects\\Transferd\\target\\debug\\relayd.exe

Without the variable the tests are skipped. Each test starts its own relayd on a free UDP port,
at a low proof-of-work difficulty so the client solves quickly.
"""

import asyncio
import os
import socket
import subprocess
from pathlib import Path

import pytest

from transferd.errors import RelayRefused
from transferd.identity import HybridIdentity, relay_token_for
from transferd.relay import PREFIX_DATA, encapsulate, unpad
from transferd.relay_client import RelayClient

RELAYD = os.environ.get("TRANSFERD_RELAYD", "")

pytestmark = pytest.mark.skipif(
    not RELAYD or not Path(RELAYD).exists(),
    reason="set TRANSFERD_RELAYD to the built relayd binary",
)

ALICE = bytes((i * 5 + 9) & 0xFF for i in range(64))
BOB = bytes((i * 3 + 17) & 0xFF for i in range(64))
DIFFICULTY = 12


def _free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


@pytest.fixture
def relay_addr():
    port = _free_udp_port()
    env = {**os.environ, "RELAYD_BIND": f"127.0.0.1:{port}", "RELAYD_DIFFICULTY": str(DIFFICULTY)}
    proc = subprocess.Popen(
        [RELAYD],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        line = proc.stdout.readline()
        assert "listening" in line, proc.stderr.read()
        yield ("127.0.0.1", port)
    finally:
        proc.kill()
        proc.wait()


def _token(name: str, seed: bytes) -> bytes:
    return relay_token_for(HybridIdentity(seed, name).node_id)


def test_register_keepalive_forward_deliver_and_locate(relay_addr):
    alice_token = _token("alice", ALICE)
    bob_token = _token("bob", BOB)

    async def scenario():
        alice = RelayClient(relay_addr)
        bob = RelayClient(relay_addr)
        await alice.open()
        await bob.open()
        try:
            await bob.register(bob_token)
            await alice.register(alice_token)
            await alice.keepalive(alice_token)
            await alice.forward(bob_token, encapsulate(PREFIX_DATA, alice_token, b"hello over the relay"))
            delivered = await bob.delivered()
            located = await alice.locate(alice_token, bob_token)
            return delivered, located, alice.local_addr, bob.local_addr
        finally:
            alice.close()
            bob.close()

    delivered, located, alice_addr, bob_addr = asyncio.run(scenario())
    assert unpad(delivered.ciphertext) == (PREFIX_DATA, alice_token, b"hello over the relay")
    assert located.self_addr == alice_addr
    assert located.peer_addr == bob_addr


def test_forward_to_an_unregistered_token_is_refused(relay_addr):
    nobody = bytes([7]) * 32

    async def scenario():
        async with RelayClient(relay_addr) as client:
            await client.forward(nobody, encapsulate(PREFIX_DATA, nobody, b"nobody is here"))

    with pytest.raises(RelayRefused) as refused:
        asyncio.run(scenario())
    assert refused.value.code == "TokenNotFound"
