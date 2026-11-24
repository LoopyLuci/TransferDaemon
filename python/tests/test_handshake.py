"""The live handshake over real TCP sockets: Python against Python, and Python against the reference's flights."""

import asyncio
from typing import Awaitable, Callable

import pytest

from transferd.errors import HandshakeError
from transferd.handshake import RESPONDER_FLIGHT_LEN, handshake_initiator, handshake_responder
from transferd.identity import HybridIdentity
from transferd.tunnel import Opener, Sealer
from transferd.wire import read_blob, write_blob

Serve = Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[object]]


async def _loopback(serve: Serve, client: Callable[[int], Awaitable[object]]):
    """Run `serve` behind a loopback listener, drive it with `client(port)`, and collect both sides.

    The responder's handler is awaited before this returns, so its outcome is always settled.
    Returns `(client result, outcome)`, where `outcome` holds `"server"` or `"server_error"`.
    A failure in `client` propagates to the caller.
    """
    outcome: dict = {}
    finished = asyncio.Event()

    async def handle(reader, writer):
        try:
            outcome["server"] = await serve(reader, writer)
        except Exception as exc:  # the test inspects what the responder refused
            outcome["server_error"] = exc
        finally:
            writer.close()
            finished.set()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        result = await client(port)
    finally:
        await asyncio.wait_for(finished.wait(), 10)
        server.close()
        await server.wait_closed()
    return result, outcome


async def _initiate(initiator: HybridIdentity, port: int, expect: str | None = None):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        return await handshake_initiator(reader, writer, initiator, expect_node_id=expect)
    finally:
        writer.close()


async def _send_raw(port: int, payload: bytes) -> bytes:
    """Send one blob, then return whatever the responder sends back before it closes."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        await write_blob(writer, payload)
        return await reader.read()
    finally:
        writer.close()


def _responder(identity: HybridIdentity) -> Serve:
    async def serve(reader, writer):
        return await handshake_responder(reader, writer, identity)

    return serve


def test_two_python_nodes_agree_on_the_session_and_its_keys():
    alpha = HybridIdentity.generate("alpha")
    beta = HybridIdentity.generate("beta")

    init, outcome = asyncio.run(_loopback(_responder(beta), lambda port: _initiate(alpha, port, beta.node_id)))

    assert "server_error" not in outcome, outcome.get("server_error")
    resp = outcome["server"]
    assert init.session_key == resp.session_key
    assert init.peer_node_id == beta.node_id
    assert resp.peer_node_id == alpha.node_id
    assert init.keys.send == resp.keys.recv and init.keys.recv == resp.keys.send


def test_a_tunnel_frame_sealed_by_one_side_opens_on_the_other():
    alpha = HybridIdentity.generate("alpha")
    beta = HybridIdentity.generate("beta")

    init, outcome = asyncio.run(_loopback(_responder(beta), lambda port: _initiate(alpha, port, beta.node_id)))

    resp = outcome["server"]
    assert Opener(resp.keys.recv).open(Sealer(init.keys.send).seal(b"from alpha to beta")) == b"from alpha to beta"
    assert Opener(init.keys.recv).open(Sealer(resp.keys.send).seal(b"and back")) == b"and back"


def test_the_initiator_refuses_a_peer_it_did_not_expect():
    alpha = HybridIdentity.generate("alpha")
    beta = HybridIdentity.generate("beta")
    stranger = HybridIdentity.generate("stranger")

    with pytest.raises(HandshakeError, match="we dialled"):
        asyncio.run(_loopback(_responder(beta), lambda port: _initiate(alpha, port, stranger.node_id)))


def test_the_initiator_refuses_a_responder_flight_that_does_not_verify(crypto_vectors):
    alpha = HybridIdentity.generate("alpha")
    tampered = bytes.fromhex(crypto_vectors["handshake"]["tampered_responder_flight"])

    async def serve(reader, writer):
        await read_blob(reader)  # the initiator's flight; we answer with a flight that cannot verify
        await write_blob(writer, tampered)

    with pytest.raises(HandshakeError, match="does not verify"):
        asyncio.run(_loopback(serve, lambda port: _initiate(alpha, port)))


def test_our_responder_accepts_the_reference_initiator_flight(crypto_vectors):
    h = crypto_vectors["handshake"]["initiator"]
    flight = bytes.fromhex(h["flight"])
    beta = HybridIdentity.generate("beta")

    answer, outcome = asyncio.run(_loopback(_responder(beta), lambda port: _send_raw(port, flight)))

    assert "server_error" not in outcome, outcome.get("server_error")
    assert outcome["server"].peer_node_id == h["node_id"]
    # The answer is one length-prefixed responder flight.
    assert len(answer) == 4 + RESPONDER_FLIGHT_LEN


def test_our_responder_refuses_a_reference_flight_with_a_flipped_signature_bit(crypto_vectors):
    flight = bytearray(bytes.fromhex(crypto_vectors["handshake"]["initiator"]["flight"]))
    flight[-1] ^= 0x01
    beta = HybridIdentity.generate("beta")

    answer, outcome = asyncio.run(_loopback(_responder(beta), lambda port: _send_raw(port, bytes(flight))))

    assert isinstance(outcome.get("server_error"), HandshakeError)
    assert "server" not in outcome
    assert answer == b"", "a refused initiator gets no flight back"
