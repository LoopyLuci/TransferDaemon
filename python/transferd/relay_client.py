"""A client of relayd: register, keepalive, locate and forward, over relayd's own UDP messages.

relayd issues a proof-of-work challenge and refuses a register, keepalive, locate or forward whose
proof does not match its current challenge. So each of those first fetches the challenge, solves it,
and sends the request. A forward's proof is over the destination token, as relayd checks it.

The client holds one UDP socket. Replies to requests (challenge, located, error, the ack of a forward)
queue for the caller, and payloads delivered to this client queue for `delivered()`. Requests run one
at a time, so a reply is matched to the request waiting for it. A reply that arrives after its request
timed out is dropped before the next request is sent.
"""

from __future__ import annotations

import asyncio
from types import TracebackType
from typing import Callable, Optional, Tuple, Type, Union

from . import relay as R
from .errors import DecodeError, RelayProtocolError, RelayRefused, RelayTimeout, TransferdError

Addr = Tuple[str, int]
Reply = Union[R.Challenge, R.Located, R.Acked, R.RelayError]


class _Datagrams(asyncio.DatagramProtocol):
    def __init__(self, client: "RelayClient") -> None:
        self._client = client

    def datagram_received(self, data: bytes, addr) -> None:  # noqa: ANN001 - asyncio's signature
        self._client._received(data)


def _is_invalid_pow(reply: object) -> bool:
    return isinstance(reply, R.RelayError) and reply.code == "InvalidPoW"


def _expect(reply: object, kind: type):
    if isinstance(reply, R.RelayError):
        raise RelayRefused(reply.code, reply.detail)
    if not isinstance(reply, kind):
        raise RelayProtocolError(f"expected {kind.__name__}, got {type(reply).__name__}")
    return reply


class RelayClient:
    """Talks to one relayd. Use `open()` before, and `close()` after."""

    def __init__(self, relay_addr: Addr, *, timeout: float = 5.0) -> None:
        self._relay_addr = relay_addr
        self._timeout = timeout
        self._transport: Optional[asyncio.DatagramTransport] = None
        self._replies: asyncio.Queue = asyncio.Queue()
        self._delivered: asyncio.Queue = asyncio.Queue()
        self._lock = asyncio.Lock()
        self._seq = 0
        #: This client's socket address, as the relay sees it.
        self.local_addr: Optional[Addr] = None

    async def open(self) -> None:
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(lambda: _Datagrams(self), remote_addr=self._relay_addr)
        self._transport = transport
        sockname = transport.get_extra_info("sockname")
        self.local_addr = (sockname[0], sockname[1])

    def close(self) -> None:
        if self._transport is not None:
            self._transport.close()
            self._transport = None

    async def __aenter__(self) -> "RelayClient":
        await self.open()
        return self

    async def __aexit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc: Optional[BaseException],
        tb: Optional[TracebackType],
    ) -> None:
        self.close()

    # --- public requests --------------------------------------------------------------------------

    async def challenge(self) -> R.Challenge:
        """The relay's current proof-of-work challenge."""
        return _expect(await self._exchange(bytes([int(R.Tag.CHALLENGE)])), R.Challenge)

    async def register(self, token: bytes) -> None:
        """Registers `token` at this client's address. Returns once relayd accepts it."""
        seq = self._next_seq()
        await self._with_proof(token, lambda nonce: R.encode_register(token, nonce, seq), R.Challenge)

    async def keepalive(self, token: bytes) -> None:
        """Refreshes a registration. relayd sends nothing back, so this returns once the datagram is out."""
        seq = self._next_seq()
        challenge = await self.challenge()
        nonce = R.solve_pow(challenge.difficulty, challenge.challenge, token)
        self._send(R.encode_keepalive(token, nonce, seq))

    async def locate(self, self_token: bytes, peer_token: bytes) -> R.Located:
        """The addresses of `self_token` and `peer_token`, as the relay sees them. `self_token` must be ours."""
        seq = self._next_seq()
        located = await self._with_proof(
            self_token,
            lambda nonce: R.encode_locate(self_token, peer_token, nonce, seq),
            R.Located,
        )
        if located.request != seq:
            raise RelayProtocolError("the location answers a different request")
        return located

    async def forward(self, peer_token: bytes, payload: bytes) -> None:
        """Sends `payload` (a relay payload, see `relay.encapsulate`) to the peer registered under `peer_token`."""
        sender_seq = self._next_seq() & 0xFFFF
        acked = await self._with_proof(
            peer_token,
            lambda nonce: R.encode_forward(peer_token, nonce, sender_seq, payload),
            R.Acked,
        )
        if acked.sender_seq != sender_seq:
            raise RelayProtocolError("the ack answers a different forward")

    async def delivered(self, timeout: Optional[float] = None) -> R.Delivered:
        """The next payload delivered to this client."""
        try:
            return await asyncio.wait_for(self._delivered.get(), timeout if timeout is not None else self._timeout)
        except asyncio.TimeoutError as exc:
            raise RelayTimeout("no payload was delivered in time") from exc

    # --- internals ----------------------------------------------------------------------------------

    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def _send(self, datagram: bytes) -> None:
        if self._transport is None:
            raise TransferdError("the relay client is not open")
        self._transport.sendto(datagram)

    def _received(self, data: bytes) -> None:
        parts = R.split(data)
        if parts is None:
            return
        tag, body = parts
        try:
            if tag == R.Tag.ACK:
                message = R.decode_ack_or_delivered(body)
                (self._delivered if isinstance(message, R.Delivered) else self._replies).put_nowait(message)
            elif tag == R.Tag.CHALLENGE:
                self._replies.put_nowait(R.decode_challenge(body))
            elif tag == R.Tag.ERROR:
                self._replies.put_nowait(R.decode_error(body))
            elif tag == R.Tag.LOCATE:
                self._replies.put_nowait(R.decode_located(body))
        except DecodeError:
            return  # not a message we can read; the relay's own frames are never this

    async def _exchange(self, datagram: bytes) -> Reply:
        async with self._lock:
            while not self._replies.empty():
                self._replies.get_nowait()  # replies to requests that already timed out
            self._send(datagram)
            try:
                return await asyncio.wait_for(self._replies.get(), self._timeout)
            except asyncio.TimeoutError as exc:
                raise RelayTimeout(f"the relay did not answer within {self._timeout} s") from exc

    async def _with_proof(self, token: bytes, build: Callable[[int], bytes], expect: type):
        """Sends `build(nonce)`, where the nonce proves work on `token` against the current challenge.

        The challenge can rotate between fetching it and sending, so an InvalidPoW is retried once.
        """
        reply: Reply
        for attempt in range(2):
            challenge = await self.challenge()
            nonce = R.solve_pow(challenge.difficulty, challenge.challenge, token)
            reply = await self._exchange(build(nonce))
            if attempt == 0 and _is_invalid_pow(reply):
                continue
            break
        return _expect(reply, expect)
