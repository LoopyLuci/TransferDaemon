"""The relay path for one node: one registered point, many peers, one inbound demultiplexer.

Mirrors `crates/transferd-overlay/src/relay.rs` and the relay route of `lanes.rs`. A relay is the only path that always
works: it is reached by an *outbound* datagram, and it delivers to the mapping that datagram created, so nothing here
listens and nothing needs a firewall port.

Over one relay the overlay runs three kinds of payload, each padded to a power of two (`relay.pad`):

    [0x01][sender_token: 32][initiator flight]    the authenticated hybrid handshake, opening
    [0x03][sender_token: 32][responder flight]    ... and its answer
    [0x02][sender_token: 32][sealed tunnel frame] a session's traffic

The node decides what to do with a peer that dials in: `admit` says whether its presented key may come in, and
`on_adopt` receives the new link so the node can make it a session. Everything else is the transport itself.
"""

from __future__ import annotations

import asyncio
import collections
from typing import Awaitable, Callable, Deque, Dict, List, Optional, Set, Tuple

import blake3

from .errors import HandshakeError, OverlayError, TransferdError, TunnelError
from .frames import Candidate, Frame, FrameReader
from .handshake import (
    INITIATOR_FLIGHT_LEN,
    INITIATOR_HELLO_LEN,
    RESPONDER_FLIGHT_LEN,
    RESPONDER_HELLO_LEN,
    TAG_INITIATOR,
    TAG_RESPONDER,
    Flight,
    InitiatorState,
    build_flight,
    respond,
)
from .identity import HybridIdentity, relay_token_for
from .link import CONTROL_QUEUE, RECV_QUEUE, SEND_QUEUE, Link, RouteKind
from .punch import PunchParams, PunchTable, Running, acceptable_candidate, addr_text, is_loopback_host
from .relay import PREFIX_DATA, PREFIX_HANDSHAKE, PREFIX_HANDSHAKE_REPLY, encapsulate, unpad
from .relay_client import Addr, RelayClient, route_source
from .tunnel import LinkKeys, Opener, Sealer, derive_link_keys

#: How long a relay handshake may take. Four datagrams must all get through, so on a lossy path it takes several tries.
HANDSHAKE_TIMEOUT = 10.0
#: How often an unanswered handshake flight is sent again (a datagram may be lost).
FLIGHT_RESEND = 0.9
#: Answers kept, so a resent flight gets the same answer instead of a second session key.
ANSWERS_KEPT = 64
#: How long to wait for a relay's answer to a request.
RELAY_TIMEOUT = 5.0
#: How often the registration is renewed: well inside relayd's TTL.
REREGISTER_EVERY = 30.0
#: Session payloads held for a peer whose link is not registered yet, for this many per peer and this many peers. The
#: two sides of a handshake finish at slightly different moments, so the first frames can overtake the link they belong to.
EARLY_PER_PEER = 64
EARLY_PEERS = 64
#: Links kept per peer on one relay. The oldest beyond this is closed.
LINKS_PER_PEER = 4
#: Datagrams a link may have in flight to the relay before its send loop waits for one to be acknowledged.
MAX_FORWARDS_IN_FLIGHT = 128

Admit = Callable[[str, bytes], bool]
Adopt = Callable[["RelayLink", str, bytes, bytes], Awaitable[None]]


class RelayLink(Link):
    """A route to one peer through a relay. Frames are sealed like any route's, and wrapped for the relay when sent."""

    def __init__(self, hub: "RelayHub", peer_token: bytes, keys: LinkKeys, *, link_id: Optional[int] = None) -> None:
        host, port = hub.addr
        super().__init__(
            RouteKind.RELAY,
            describe=f"relay://{host}:{port}#{peer_token.hex()}",
            link_id=link_id,
        )
        self._hub = hub
        self._peer_token = peer_token
        self._sealer = Sealer(keys.send)
        self._opener = Opener(keys.recv)
        self._frames = FrameReader()
        self._inbox: Deque[Frame] = collections.deque()
        # Bulk frames are forwarded after the control queue, so a relay backlog never holds a window update up.
        self._outbox: Deque[bytes] = collections.deque()
        self._control: Deque[bytes] = collections.deque()
        self._outwake = asyncio.Event()
        self._task: Optional[asyncio.Task] = None
        # Datagrams sent and not yet acknowledged by the relay (pipelined: the loop does not wait for each one).
        self._in_flight: Set[asyncio.Task] = set()
        # A failure that is a bug rather than a lost datagram: the route ends with it, as a raised error would.
        self._fault: Optional[BaseException] = None

    def start(self) -> None:
        """Start the task that sends what is queued. Call from a running event loop."""
        self._task = asyncio.get_running_loop().create_task(self._write_loop())

    def send(self, frame: Frame) -> bool:
        queue, limit = (self._outbox, SEND_QUEUE) if frame.is_bulk else (self._control, CONTROL_QUEUE)
        if self._closed or len(queue) >= limit:
            return False
        queue.append(self._sealer.seal(frame.encode()))
        self.stats.record_sent(len(frame.body))
        self._outwake.set()
        return True

    def try_recv(self) -> Optional[Frame]:
        return self._inbox.popleft() if self._inbox else None

    def deliver(self, sealed: bytes) -> bool:
        """Open one sealed payload and keep its frames. False when it is not this link's: another link to the same
        peer may own it, or it is a replay."""
        try:
            plain = self._opener.open(sealed)
        except TunnelError:
            return False
        self.stats.mark_up()
        self._inbox.extend(self._frames.push(plain))
        self._wake()
        return True

    def close(self) -> None:
        super().close()
        if self._task is not None:
            self._task.cancel()
        for task in list(self._in_flight):
            task.cancel()

    async def _write_loop(self) -> None:
        while True:
            if self._fault is not None:
                raise self._fault
            while not self._control and not self._outbox:
                self._outwake.clear()
                await self._outwake.wait()
            sealed = self._control.popleft() if self._control else self._outbox.popleft()
            # Pipelined: the next datagram goes out without waiting for this one's ack. The number in flight is bounded,
            # so a backlog cannot run ahead of the relay without limit.
            task = asyncio.get_running_loop().create_task(self._send_datagram(sealed))
            self._in_flight.add(task)
            task.add_done_callback(self._in_flight.discard)
            if len(self._in_flight) >= MAX_FORWARDS_IN_FLIGHT:
                await asyncio.wait(self._in_flight, return_when=asyncio.FIRST_COMPLETED)

    async def _send_datagram(self, sealed: bytes) -> None:
        try:
            await self._hub.forward_sealed(self._peer_token, sealed)
        except TransferdError:
            # A datagram that could not be sent is a lost datagram, which the session repairs. It is no reason to close
            # the route: that would end a session over one hiccup.
            pass
        except Exception as exc:
            self._fault = exc


class RelayHub:
    """A registered relay and the sessions multiplexed over it."""

    def __init__(
        self,
        addr: Addr,
        self_token: bytes,
        identity: HybridIdentity,
        *,
        admit: Optional[Admit] = None,
        on_adopt: Optional[Adopt] = None,
        timeout: float = RELAY_TIMEOUT,
        gateway: Optional[Addr] = None,
    ) -> None:
        if len(self_token) != 32:
            raise TransferdError("a relay token is 32 bytes")
        self.addr = addr
        self.self_token = self_token
        self._identity = identity
        self._admit: Admit = admit or (lambda _node_id, _key: True)
        self._on_adopt = on_adopt
        self._client = RelayClient(addr, timeout=timeout)
        # The hole punches share the registration socket, so the punch table takes the datagrams it is offered first.
        self._punch = PunchTable(self._client, gateway=gateway, relay_is_loopback=is_loopback_host(addr[0]))
        self._peers: Dict[bytes, List[RelayLink]] = {}
        self._early: Dict[bytes, List[bytes]] = {}
        self._answered: Dict[bytes, bytes] = {}
        self._handshakes: Dict[bytes, asyncio.Future] = {}
        self._tasks: List[asyncio.Task] = []
        self._background: Set[asyncio.Task] = set()

    @property
    def client(self) -> RelayClient:
        """The relay client this hub's registration socket belongs to (the hole punches share it)."""
        return self._client

    @property
    def punch(self) -> PunchTable:
        """The hole-punch table on this hub's registration socket."""
        return self._punch

    async def start(self) -> None:
        """Open the socket, register our token, and start the receive and renewal loops."""
        await self._client.open()
        try:
            await self._client.register(self.self_token)
        except Exception:
            self._client.close()
            raise
        loop = asyncio.get_running_loop()
        self._tasks = [loop.create_task(self._receive_loop()), loop.create_task(self._renew_loop())]

    async def close(self) -> None:
        for task in self._tasks:
            task.cancel()
        for links in self._peers.values():
            for link in links:
                link.close()
        self._client.close()

    # --- inbound ------------------------------------------------------------------------------------

    async def _receive_loop(self) -> None:
        while True:
            delivered = await self._client.next_delivered()
            self._dispatch(delivered.ciphertext)

    async def _renew_loop(self) -> None:
        while True:
            await asyncio.sleep(REREGISTER_EVERY)
            try:
                await self._client.register(self.self_token)
            except TransferdError:
                continue  # the next renewal tries again; a restarted relay is reached once one gets through

    def _dispatch(self, payload: bytes) -> None:
        parts = unpad(payload)
        if parts is None:
            return
        prefix, sender, rest = parts
        if prefix == PREFIX_HANDSHAKE:
            self._spawn(self._answer_inbound(sender, rest))
        elif prefix == PREFIX_HANDSHAKE_REPLY:
            # An answer nobody waits for any more (a copy, for a resent flight) is dropped.
            waiting = self._handshakes.pop(sender, None)
            if waiting is not None and not waiting.done():
                waiting.set_result(rest)
        elif prefix == PREFIX_DATA:
            links = self._peers.get(sender)
            if links is not None:
                # The payload carries no link id, so the keys decide which of the peer's links it is for.
                any(link.deliver(rest) for link in links)
                return
            held = self._early.get(sender)
            if held is None:
                if len(self._early) >= EARLY_PEERS:
                    return
                held = self._early[sender] = []
            if len(held) < EARLY_PER_PEER:
                held.append(rest)

    def _spawn(self, coro: Awaitable[None]) -> None:
        task = asyncio.get_running_loop().create_task(coro)
        self._background.add(task)
        task.add_done_callback(self._background.discard)

    async def _answer_inbound(self, sender: bytes, flight: bytes) -> None:
        """Answer a handshake a peer dialled through this relay, so a node with no open port can still be reached."""
        digest = blake3.blake3(flight).digest()
        known = self._answered.get(digest)
        if known is not None:
            # Our answer was lost and the flight came again: send the same answer, not a second key the dialler never sees.
            await self._send_quietly(PREFIX_HANDSHAKE_REPLY, sender, known)
            return
        answered = answer_handshake(flight, self._identity)
        if answered is None:
            return
        keys, peer_id, peer_key, reply = answered
        # As on the direct listener, a first contact must present the key its invite named. A refused flight gets no
        # answer, so the dialler's handshake times out.
        if not self._admit(peer_id, peer_key):
            return
        if len(self._answered) >= ANSWERS_KEPT:
            self._answered.clear()
        self._answered[digest] = reply
        # The token is derived from the node id, so the two are the same key material.
        peer_token = relay_token_for(peer_id)
        # The link is registered before the answer goes out, so the dialler's first frames find it.
        link = self.link(peer_token, keys)
        await self._send_quietly(PREFIX_HANDSHAKE_REPLY, sender, reply)
        if self._on_adopt is not None:
            await self._on_adopt(link, peer_id, peer_key, sender)

    async def _send_quietly(self, prefix: int, peer_token: bytes, body: bytes) -> None:
        try:
            await self._send_payload(prefix, peer_token, body)
        except TransferdError:
            pass  # a lost answer is repaired by the dialler's resend

    # --- outbound -----------------------------------------------------------------------------------

    async def _send_payload(self, prefix: int, peer_token: bytes, body: bytes) -> None:
        await self._client.forward(peer_token, encapsulate(prefix, self.self_token, body))

    async def forward_sealed(self, peer_token: bytes, sealed: bytes) -> None:
        """Send one sealed blob to a peer through this relay."""
        await self._client.forward(peer_token, encapsulate(PREFIX_DATA, self.self_token, sealed))

    async def handshake(self, peer_node_id: str, peer_token: bytes) -> Tuple[LinkKeys, bytes]:
        """Run the authenticated hybrid handshake with a peer over this relay.

        Returns the link keys (the same derivation as a direct connection, so a relay route and a direct route are
        interchangeable) and the peer's 2624-byte hybrid public key, from its verified flight. The caller checks that
        key against the peer's fingerprint.
        """
        loop = asyncio.get_running_loop()
        waiting: asyncio.Future = loop.create_future()
        self._handshakes[peer_token] = waiting
        state = InitiatorState()
        flight = build_flight(TAG_INITIATOR, state.hello(), self._identity).to_wire()
        deadline = loop.time() + HANDSHAKE_TIMEOUT
        # The same flight again until it is answered: the peer answers a repeat with the answer it already gave.
        while True:
            await self._send_payload(PREFIX_HANDSHAKE, peer_token, flight)
            wait = min(FLIGHT_RESEND, max(deadline - loop.time(), 0.0))
            try:
                reply = await asyncio.wait_for(asyncio.shield(waiting), wait)
                break
            except asyncio.TimeoutError:
                if loop.time() >= deadline:
                    self._handshakes.pop(peer_token, None)
                    raise OverlayError(f"{peer_node_id} did not answer through {self.addr[0]}:{self.addr[1]}")
        answer = Flight.parse(reply, TAG_RESPONDER, RESPONDER_HELLO_LEN, RESPONDER_FLIGHT_LEN)
        if not answer.verify():
            raise HandshakeError("the responder flight signature does not verify")
        if answer.node_id != peer_node_id:
            raise HandshakeError(f"we dialled {peer_node_id}, but the peer is {answer.node_id}")
        session_key = state.finish(answer.hello)
        return derive_link_keys(session_key), answer.identity_pk

    def link(self, peer_token: bytes, keys: LinkKeys) -> RelayLink:
        """Open a session link to a peer over this relay. Call from a running event loop."""
        link = RelayLink(self, peer_token, keys)
        link.start()
        links = self._peers.setdefault(peer_token, [])
        # Anything that overtook the link is delivered first, then the link takes over.
        for sealed in self._early.pop(peer_token, []):
            link.deliver(sealed)
        links[:] = [existing for existing in links if not existing.is_closed()]
        links.insert(0, link)
        while len(links) > LINKS_PER_PEER:
            links.pop().close()
        return link

    async def locate(self, peer_token: bytes):
        """The addresses the relay sees for us and for a peer (STUN-style). This is what makes a hole punch possible."""
        return await self._client.locate(self.self_token, peer_token)

    async def punch_candidates(self, peer_token: bytes) -> List[Candidate]:
        """The addresses a peer may try for a hole punch to this node.

        The one the relay sees for the registration socket comes first: it is asked on that same socket, so it is the NAT
        mapping the punch will use. This machine's own address towards the relay follows when it is not loopback, for a
        peer on the same network, which a NAT would not loop traffic back to.
        """
        located = await self.locate(peer_token)
        out = [Candidate(addr=addr_text(located.self_addr), private=False)]
        port = self._punch.local_port
        try:
            ip = route_source(self.addr)
        except OSError:
            return out
        if port is not None:
            own = (ip, port)
            if own != tuple(located.self_addr) and acceptable_candidate(own, False):
                out.append(Candidate(addr=addr_text(own), private=True))
        return out

    def punch_begin(self, params: PunchParams) -> Running:
        """Register a hole-punch attempt on the registration socket (see `PunchTable.begin`)."""
        return self._punch.begin(params)

    def forget(self, peer_token: bytes) -> None:
        """Forget a peer, because its session ended."""
        self._peers.pop(peer_token, None)
        self._early.pop(peer_token, None)


def answer_handshake(flight: bytes, identity: HybridIdentity) -> Optional[Tuple[LinkKeys, str, bytes, bytes]]:
    """Answer an inbound handshake flight. Returns the link keys, the peer's node id and hybrid public key (both from
    its signed flight), and the answer to send back. None when the flight does not verify."""
    try:
        hello = Flight.parse(flight, TAG_INITIATOR, INITIATOR_HELLO_LEN, INITIATOR_FLIGHT_LEN)
        if not hello.verify():
            return None
        responder_hello, session_key = respond(hello.hello)
    except TransferdError:
        return None
    reply = build_flight(TAG_RESPONDER, responder_hello, identity).to_wire()
    return derive_link_keys(session_key).swapped(), hello.node_id, hello.identity_pk, reply
