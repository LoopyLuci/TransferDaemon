"""Ghost key registration against the reference relay.

A relay started with `RELAYD_REQUIRE_GHOST=1` and the issuer from the Rust reference refuses a plain registration, admits
a registration whose certificate that issuer signed, and refuses a certificate from any other issuer. Build the relay,
then point `TRANSFERD_RELAYD` at the executable; without the variable the tests are skipped.
"""

import asyncio
import os
import socket
import subprocess
from pathlib import Path

import pytest

from transferd.errors import RelayRefused
from transferd.ghostkey import GhostKey, Issuer
from transferd.relay_client import RelayClient

RELAYD = os.environ.get("TRANSFERD_RELAYD", "")
pytestmark = pytest.mark.skipif(
    not RELAYD or not Path(RELAYD).exists(),
    reason="set TRANSFERD_RELAYD to the built relayd binary",
)

DIFFICULTY = 12


def _free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


@pytest.fixture
def ghost_relay(tmp_path, ghost_vectors):
    """A relayd that trusts only the reference issuer and requires a ghost key to register."""
    issuer_file = tmp_path / "issuer.txt"
    issuer_file.write_text(ghost_vectors["issuer"]["public_text"], encoding="utf-8")
    port = _free_udp_port()
    env = {
        **os.environ,
        "RELAYD_BIND": f"127.0.0.1:{port}",
        "RELAYD_DIFFICULTY": str(DIFFICULTY),
        "RELAYD_GHOST_ISSUERS": str(issuer_file),
        "RELAYD_REQUIRE_GHOST": "1",
    }
    proc = subprocess.Popen([RELAYD], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        line = proc.stdout.readline()
        assert "listening" in line, proc.stderr.read()
        yield ("127.0.0.1", port)
    finally:
        proc.kill()
        proc.wait()


def test_a_relay_that_requires_a_ghost_key_admits_one_its_issuer_vouched_for(ghost_relay, ghost_vectors):
    async def main():
        token = bytes.fromhex(ghost_vectors["registration"]["session_token"])
        client = RelayClient(ghost_relay, timeout=10)
        await client.open()
        try:
            with pytest.raises(RelayRefused) as refused:
                await client.register(token)
            assert refused.value.code == "GhostRequired", "a plain registration is refused"

            ghost = GhostKey(bytes.fromhex(ghost_vectors["ghost_secret"]))
            certificate = bytes.fromhex(ghost_vectors["certificate"]["bincode"])
            await client.register_ghost(token, certificate, ghost)
        finally:
            client.close()

    asyncio.run(asyncio.wait_for(main(), 60))


def test_a_relay_refuses_a_certificate_from_an_issuer_it_does_not_trust(ghost_relay, ghost_vectors):
    async def main():
        token = bytes.fromhex(ghost_vectors["registration"]["session_token"])
        other = Issuer.generate("someone else", "supporter", 2048)
        me = GhostKey.generate()
        blinded, state = me.blind_request(other.public)
        certificate = me.finish(other.public, state, other.sign_blinded(blinded))

        client = RelayClient(ghost_relay, timeout=10)
        await client.open()
        try:
            with pytest.raises(RelayRefused) as refused:
                await client.register_ghost(token, certificate.encode_bincode(), me)
            assert refused.value.code == "GhostRejected"
        finally:
            client.close()

    asyncio.run(asyncio.wait_for(main(), 60))
