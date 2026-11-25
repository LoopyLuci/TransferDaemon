"""A client of relayd: register, keepalive, locate and forward, over relayd's own UDP messages.

relayd issues a proof-of-work challenge and refuses a register, keepalive, locate or forward whose
proof does not match its current challenge. So each of those first fetches the challenge, solves it,
and sends the request. A forward's proof is over the destination token, as relayd checks it.

The client holds one UDP socket. Replies to requests (challenge, located, error) queue for the caller, and
payloads delivered to this client queue for `delivered()`. Requests run one at a time, so a reply is matched
to the request waiting for it. A reply that arrives after its request timed out is dropped before the next
request is sent.

A forward is pipelined instead: many may be in flight at once. Each carries a sequence number that its ack or
its refusal names, so each waits for its own answer, and a forward the relay never answers only times out
itself. The relay's proof-of-work challenge is reused until it nears expiry, and a proof for a peer is solved
once per challenge, so a forward costs one datagram to the relay.
"""

from __future__ import annotations

import asyncio
import socket
import time
from types import TracebackType
from typing import Callable, Dict, Optional, Tuple, Type, Union

from . import relay as R
from .errors import DecodeError, RelayProtocolError, RelayRefused, RelayTimeout, TransferdError
from .ghostkey import GhostKey, binding

Addr = Tuple[str, int]
Reply = Union[R.Challenge, R.Located, R.RelayError]

#: Request sequence numbers start above the 16-bit range a forward's sequence number uses. A relay error names the
#: sequence number of the message it refuses, so a small number is a refused forward and a large one a refused request.
REQUEST_SEQ_BASE = 0x10000
MAX_FORWARD_SEQ = 0xFFFF
#: A cached challenge is fetched again once less than this many seconds of it remain.
CHALLENGE_MARGIN_S = 10
#: Proofs of work kept at once: one per peer, for the challenge they were solved against.
NONCES_KEPT = 256
#: Socket buffer size asked for, so a burst of pipelined datagrams does not overflow a small default buffer.
SOCKET_BUFFER = 4 << 20


class _Datagrams(asyncio.DatagramProtocol):
    def __init__(self, client: "RelayClient") -> None:
        self._client = client

    def datagram_received(self, data: bytes, addr) -> None:  # noqa: ANN001 - asyncio's signature
        self._client._received(data, (addr[0], addr[1]))


def route_source(relay_addr: Addr) -> str:
    """The address this host sends from towards the relay. A UDP `connect` sends nothing: it only makes the OS choose
    the source address it would use, which is the address the relay sees for a socket bound to the wildcard."""
    family = socket.AF_INET6 if ":" in relay_addr[0] else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as probe:
        probe.connect(relay_addr)
        return probe.getsockname()[0]


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
        self._seq = REQUEST_SEQ_BASE
        self._forward_seq = 0
        #: Forwards waiting for their ack or refusal, by sequence number.
        self._forwards: Dict[int, asyncio.Future] = {}
        #: The relay's challenge last fetched, and the lock that makes concurrent forwards share one fetch.
        self._cached_challenge: Optional[R.Challenge] = None
        self._challenge_lock = asyncio.Lock()
        #: The proof of work last solved for each peer, with the challenge it was solved against.
        self._nonces: Dict[bytes, Tuple[Tuple[bytes, int], int]] = {}
        #: Offered every datagram before the relay's replies are read. Returns True when it took the datagram. The
        #: hole-punch table uses this: its probes arrive on this same socket, from the peers rather than the relay.
        self.on_datagram: Optional[Callable[[bytes, Addr], bool]] = None
        #: This client's socket address, as the relay sees it.
        self.local_addr: Optional[Addr] = None

    async def open(self) -> None:
        loop = asyncio.get_running_loop()
        # Unconnected, so the same socket can also send to peers (hole punches) as well as to the relay.
        any_addr = "::" if ":" in self._relay_addr[0] else "0.0.0.0"
        transport, _ = await loop.create_datagram_endpoint(lambda: _Datagrams(self), local_addr=(any_addr, 0))
        self._transport = transport
        # Best effort, as on the Rust side: a system that refuses keeps its default buffers.
        sock = transport.get_extra_info("socket")
        for option in (socket.SO_RCVBUF, socket.SO_SNDBUF):
            try:
                sock.setsockopt(socket.SOL_SOCKET, option, SOCKET_BUFFER)
            except OSError:
                pass
        port = transport.get_extra_info("sockname")[1]
        self.local_addr = (route_source(self._relay_addr), port)

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

    async def register_ghost(self, token: bytes, certificate: bytes, ghost: GhostKey) -> None:
        """Registers `token` with a ghost key certificate (`certificate` is its bincode). The ghost key signs the
        binding of this token and sequence number, so a certificate someone else saw cannot be reused."""
        seq = self._next_seq()
        signature = ghost.sign(binding(token, seq))
        await self._with_proof(
            token,
            lambda nonce: R.encode_register_ghost(token, nonce, seq, certificate, signature),
            R.Challenge,
        )

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
        """Sends `payload` (a relay payload, see `relay.encapsulate`) to the peer registered under `peer_token`.

        Resolves when the relay acknowledges it, and raises when the relay refuses it or does not answer in time.
        Other forwards may be in flight meanwhile, so callers that send many should not await each one in turn.
        """
        loop = asyncio.get_running_loop()
        for attempt in range(2):
            challenge = await self._current_challenge()
            nonce = self._forward_nonce(challenge, peer_token)
            sender_seq = self._next_forward_seq()
            acked: asyncio.Future = loop.create_future()
            self._forwards[sender_seq] = acked
            try:
                self._send(R.encode_forward(peer_token, nonce, sender_seq, payload))
                await asyncio.wait_for(acked, self._timeout)
                return
            except asyncio.TimeoutError as exc:
                raise RelayTimeout(f"the relay did not acknowledge a forward within {self._timeout} s") from exc
            except RelayRefused as exc:
                # The challenge rotated under the proof: the next one is solved against a fresh challenge.
                if attempt == 0 and exc.code == "InvalidPoW":
                    self._cached_challenge = None
                    continue
                raise
            finally:
                self._forwards.pop(sender_seq, None)

    def _next_forward_seq(self) -> int:
        """The next sequence number a forward may use: the 16-bit space, skipping any still in flight."""
        while True:
            self._forward_seq = (self._forward_seq + 1) & MAX_FORWARD_SEQ
            if self._forward_seq not in self._forwards:
                return self._forward_seq

    async def _current_challenge(self) -> R.Challenge:
        """The relay's challenge, reused while it has time left: a forward needs only its own proof of work, not a
        round trip for a fresh challenge. Concurrent callers share one fetch. If a fetch fails, the challenge in hand
        is still good enough to try."""
        if self._fresh(self._cached_challenge):
            return self._cached_challenge
        async with self._challenge_lock:
            if self._fresh(self._cached_challenge):
                return self._cached_challenge
            stale = self._cached_challenge
            try:
                fresh = await self.challenge()
            except TransferdError:
                if stale is None:
                    raise
                return stale
            self._cached_challenge = fresh
            return fresh

    @staticmethod
    def _fresh(challenge: Optional[R.Challenge]) -> bool:
        return challenge is not None and challenge.expires_at > int(time.time()) + CHALLENGE_MARGIN_S

    def _forward_nonce(self, challenge: R.Challenge, peer_token: bytes) -> int:
        """The proof of work for `peer_token` against `challenge`, solved once and kept while the challenge stands."""
        version = (challenge.challenge, challenge.difficulty)
        known = self._nonces.get(peer_token)
        if known is not None and known[0] == version:
            return known[1]
        nonce = R.solve_pow(challenge.difficulty, challenge.challenge, peer_token)
        if len(self._nonces) >= NONCES_KEPT:
            self._nonces.clear()
        self._nonces[peer_token] = (version, nonce)
        return nonce

    async def delivered(self, timeout: Optional[float] = None) -> R.Delivered:
        """The next payload delivered to this client."""
        try:
            return await asyncio.wait_for(self._delivered.get(), timeout if timeout is not None else self._timeout)
        except asyncio.TimeoutError as exc:
            raise RelayTimeout("no payload was delivered in time") from exc

    async def next_delivered(self) -> R.Delivered:
        """The next payload delivered to this client, waiting as long as it takes (for a receive loop)."""
        return await self._delivered.get()

    def send_to(self, datagram: bytes, addr: Addr) -> None:
        """Sends a datagram from this client's socket to any address (a peer, for a hole punch)."""
        if self._transport is None:
            raise TransferdError("the relay client is not open")
        self._transport.sendto(datagram, addr)

    # --- internals ----------------------------------------------------------------------------------

    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def _send(self, datagram: bytes) -> None:
        self.send_to(datagram, self._relay_addr)

    def _received(self, data: bytes, addr: Addr) -> None:
        if self.on_datagram is not None and self.on_datagram(data, addr):
            return
        parts = R.split(data)
        if parts is None:
            return
        tag, body = parts
        try:
            if tag == R.Tag.ACK:
                message = R.decode_ack_or_delivered(body)
                if isinstance(message, R.Delivered):
                    self._delivered.put_nowait(message)
                else:
                    self._resolve_forward(message.sender_seq)
            elif tag == R.Tag.CHALLENGE:
                self._replies.put_nowait(R.decode_challenge(body))
            elif tag == R.Tag.ERROR:
                error = R.decode_error(body)
                if error.seq <= MAX_FORWARD_SEQ:
                    self._refuse_forward(error)
                else:
                    self._replies.put_nowait(error)
            elif tag == R.Tag.LOCATE:
                self._replies.put_nowait(R.decode_located(body))
        except DecodeError:
            return  # not a message we can read; the relay's own frames are never this

    def _resolve_forward(self, sender_seq: int) -> None:
        acked = self._forwards.get(sender_seq)
        if acked is not None and not acked.done():
            acked.set_result(None)

    def _refuse_forward(self, error: R.RelayError) -> None:
        refused = self._forwards.get(error.seq)
        if refused is not None and not refused.done():
            refused.set_exception(RelayRefused(error.code, error.detail))

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
