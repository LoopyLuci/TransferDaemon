"""Hole punching (§8): the probe keys, the 33-byte probe datagram, and the TDGW gateway envelope.

Probes are plain datagrams sent from a relay registration socket. Their keys come from the two
nodes' nonces, which only ever travel inside the encrypted session.

    probe := "TDPB" | kind u8 | id u64 BE | seq u32 BE | mac[16]       (33 bytes)
    kind  := 1 probe from the initiator, 2 probe from the responder,
             3 reply from the initiator, 4 reply from the responder
    mac   := BLAKE3-keyed(probe_key, every byte before it)[..16]
"""

from __future__ import annotations

import asyncio
import collections
import hmac
import ipaddress
import struct
import time
from dataclasses import dataclass, field
from typing import Callable, Deque, Dict, List, Optional, Sequence, Set, Tuple

from .crypto import blake3_derive_key, blake3_keyed
from .errors import OverlayError, TransferdError, TunnelError
from .frames import Frame, FrameReader
from .link import RECV_QUEUE, Link, RouteKind
from .relay_client import Addr, RelayClient
from .tunnel import LinkKeys, Opener, Sealer, derive_link_keys

PROBE_MAGIC = b"TDPB"
PROBE_LEN = 33
GATEWAY_MAGIC = b"TDGW"
MAX_CANDIDATES = 8
ROUNDS = 10
PROBE_EVERY_S = 0.2
LINGER_S = 2.0
REPLY_GAP_S = 0.04
MAX_REPLIES = 64
MAX_ESTABLISHED = 8

PROBE_CONTEXT = "transferd-overlay-punch-probe-v1"
LINK_CONTEXT = "transferd-overlay-punch-link-v1"


@dataclass(frozen=True)
class PunchKeys:
    probe: bytes
    link: bytes

    @classmethod
    def derive(cls, attempt_id: int, initiator_nonce: bytes, responder_nonce: bytes) -> "PunchKeys":
        material = struct.pack(">Q", attempt_id) + initiator_nonce + responder_nonce
        return cls(probe=blake3_derive_key(PROBE_CONTEXT, material), link=blake3_derive_key(LINK_CONTEXT, material))


@dataclass(frozen=True)
class Probe:
    kind: str  # "probe" or "reply"
    from_initiator: bool
    id: int
    seq: int


def _kind_byte(p: Probe) -> int:
    return 1 + 2 * (p.kind == "reply") + (0 if p.from_initiator else 1)


def encode_probe(keys: PunchKeys, probe: Probe) -> bytes:
    head = PROBE_MAGIC + bytes([_kind_byte(probe)]) + struct.pack(">QI", probe.id, probe.seq)
    return head + blake3_keyed(keys.probe, head)[:16]


def probe_shaped(datagram: bytes) -> bool:
    return len(datagram) == PROBE_LEN and datagram[:4] == PROBE_MAGIC


def probe_id(datagram: bytes) -> Optional[int]:
    if not probe_shaped(datagram):
        return None
    return struct.unpack(">Q", datagram[5:13])[0]


def decode_probe(keys: PunchKeys, datagram: bytes) -> Optional[Probe]:
    """The probe, if its MAC is valid under `keys`. Anything else is `None`."""
    if not probe_shaped(datagram):
        return None
    expected = blake3_keyed(keys.probe, datagram[:17])[:16]
    if not hmac.compare_digest(expected, datagram[17:]):
        return None
    kind_byte = datagram[4]
    table = {1: ("probe", True), 2: ("probe", False), 3: ("reply", True), 4: ("reply", False)}
    if kind_byte not in table:
        return None
    kind, from_initiator = table[kind_byte]
    id_, seq = struct.unpack(">QI", datagram[5:17])
    return Probe(kind=kind, from_initiator=from_initiator, id=id_, seq=seq)


def gateway_wrap(addr: Tuple[str, int], datagram: bytes) -> bytes:
    """`"TDGW" | family u8 | ip | port u16 BE | datagram`, for a local UDP gateway only."""
    ip = ipaddress.ip_address(addr[0])
    family = 4 if ip.version == 4 else 6
    return GATEWAY_MAGIC + bytes([family]) + ip.packed + struct.pack(">H", addr[1]) + datagram


def gateway_unwrap(data: bytes) -> Optional[Tuple[Tuple[str, int], bytes]]:
    if len(data) < 5 or data[:4] != GATEWAY_MAGIC:
        return None
    family = data[4]
    width = {4: 4, 6: 16}.get(family)
    if width is None or len(data) < 5 + width + 2:
        return None
    ip = ipaddress.ip_address(data[5 : 5 + width])
    (port,) = struct.unpack(">H", data[5 + width : 7 + width])
    return (str(ip), port), data[7 + width :]


# ---------------------------------------------------------------------------
# The table of attempts and punched routes on one relay socket (punch.rs)
# ---------------------------------------------------------------------------

#: How long the last probe round waits for an answer that is late but still taken.
LATE_REPLY_S = 0.4


def acceptable_candidate(addr: Addr, relay_is_loopback: bool) -> bool:
    """Whether a peer's address may be probed: an address that can be a peer, with a port.

    Never port 0, unspecified, multicast, broadcast or link-local. Loopback only when the relay is on loopback too, which is
    a node and its relay on one machine (a test, or a lab): otherwise a peer could aim our probes at our own services.
    """
    host, port = addr
    if port == 0:
        return False
    ip = ipaddress.ip_address(host)
    if ip.is_unspecified or ip.is_multicast or ip.is_link_local:
        return False
    if ip == ipaddress.IPv4Address("255.255.255.255"):
        return False
    return not (ip.is_loopback and not relay_is_loopback)


def is_loopback_host(host: str) -> bool:
    return ipaddress.ip_address(host).is_loopback


def addr_text(addr: Addr) -> str:
    """An address as a candidate names it: `ip:port`, with an IPv6 address in brackets, as Rust's `SocketAddr` writes it."""
    host, port = addr
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


@dataclass
class _Attempt:
    keys: PunchKeys
    initiator: bool
    allowed: Set[Addr]
    won: Optional[asyncio.Future]
    rounds_sent: int = 0
    replies: int = 0
    last_reply: Dict[Addr, float] = field(default_factory=dict)


@dataclass
class _Established:
    link: "PunchLink"
    opener: Opener
    reader: FrameReader


@dataclass(frozen=True)
class PunchParams:
    """What one attempt needs. `candidates` are the peer's, as it named them (filtered by `begin`); `link_id` is the id
    the new route gets in its session."""

    id: int
    initiator: bool
    keys: PunchKeys
    candidates: Sequence[Addr]
    link_id: int


class PunchLink(Link):
    """A route over a hole-punched UDP path: frames are sealed like any route's, and sent as datagrams to one address."""

    def __init__(self, link_id: int, addr: Addr, keys: LinkKeys, sink: Callable[[bytes], None]) -> None:
        super().__init__(RouteKind.HOLEPUNCH, describe=f"udp://{addr_text(addr)}", link_id=link_id)
        self._sealer = Sealer(keys.send)
        self._sink = sink
        self._inbox: Deque[Frame] = collections.deque()

    def send(self, frame: Frame) -> bool:
        if self._closed:
            return False
        self._sink(self._sealer.seal(frame.encode()))
        self.stats.record_sent(len(frame.body))
        return True

    def try_recv(self) -> Optional[Frame]:
        return self._inbox.popleft() if self._inbox else None

    def push_frame(self, frame: Frame) -> None:
        """Keep a frame that a punched datagram carried. Dropped when the inbox is full, as the reference's punch path is."""
        if len(self._inbox) < RECV_QUEUE:
            self._inbox.append(frame)
        self._wake()


class PunchTable:
    """The hole-punching state of one relay socket: the attempts in progress, and the punched routes.

    The relay client offers every datagram it receives here first (`RelayClient.on_datagram`). A probe is taken, and a
    datagram of a punched route; the rest is for the relay path.
    """

    def __init__(self, client: RelayClient, *, gateway: Optional[Addr] = None, relay_is_loopback: bool = False) -> None:
        self._client = client
        self._gateway = gateway
        self._relay_is_loopback = relay_is_loopback
        self._attempts: Dict[int, _Attempt] = {}
        self._routes: Dict[Addr, _Established] = {}
        client.on_datagram = self._offered

    @property
    def local_port(self) -> Optional[int]:
        """The port of the socket every candidate of this node is on."""
        return None if self._client.local_addr is None else self._client.local_addr[1]

    def _offered(self, data: bytes, addr: Addr) -> bool:
        # A datagram a peer sent through the gateway arrives wrapped with its address. One that came straight is looked
        # at as it is.
        if self._gateway is not None and addr == self._gateway:
            unwrapped = gateway_unwrap(data)
            if unwrapped is not None:
                src, inner = unwrapped
                self.on_datagram(src, inner)
                return True  # a wrapped datagram is never the relay's
        return self.on_datagram(addr, data)

    def on_datagram(self, src: Addr, data: bytes) -> bool:
        """Take a datagram that arrived from `src`. True when it was ours: a probe, or traffic of a punched route."""
        if probe_shaped(data):
            self._on_probe(src, data)
            return True
        est = self._routes.get(src)
        if est is None:
            return False
        if est.link.is_closed():
            del self._routes[src]
            return True
        try:
            plain = est.opener.open(data)
        except TunnelError:
            return True  # not under this route's keys: dropped without a word
        est.link.stats.mark_up()
        for frame in est.reader.push(plain):
            est.link.push_frame(frame)
        return True

    def _on_probe(self, src: Addr, data: bytes) -> None:
        attempt_id = probe_id(data)
        if attempt_id is None:
            return
        attempt = self._attempts.get(attempt_id)
        if attempt is None:
            return
        # Only from an address the peer named, and only with a valid MAC from the other role.
        if src not in attempt.allowed:
            return
        probe = decode_probe(attempt.keys, data)
        if probe is None or probe.id != attempt_id or probe.from_initiator == attempt.initiator:
            return
        if probe.kind == "probe":
            now = time.monotonic()
            last = attempt.last_reply.get(src)
            recent = last is not None and now - last < REPLY_GAP_S
            if recent or attempt.replies >= MAX_REPLIES:
                return
            attempt.replies += 1
            attempt.last_reply[src] = now
            reply = encode_probe(
                attempt.keys,
                Probe(kind="reply", from_initiator=attempt.initiator, id=attempt_id, seq=probe.seq),
            )
            self._send_to(src, reply)
        elif probe.seq < attempt.rounds_sent and attempt.won is not None:
            # A reply must answer a round we sent, and the first one to do so wins.
            won, attempt.won = attempt.won, None
            if not won.done():
                won.set_result(src)

    def begin(self, params: PunchParams) -> "Running":
        """Register an attempt, so the peer's probes are answered from now on. Call from a running event loop, and before
        the answer that tells the peer to start goes out; then `Running.finish` does the probing."""
        usable = list(
            dict.fromkeys(a for a in params.candidates if acceptable_candidate(a, self._relay_is_loopback))
        )[:MAX_CANDIDATES]
        if not usable:
            raise OverlayError("the peer named no usable address")
        won = asyncio.get_running_loop().create_future()
        self._attempts[params.id] = _Attempt(
            keys=params.keys,
            initiator=params.initiator,
            allowed=set(usable),
            won=won,
        )
        return Running(self, params, usable, won)

    def _send_to(self, dest: Addr, data: bytes) -> None:
        """Send one datagram to a peer address from the relay socket, through the gateway when there is one."""
        try:
            if self._gateway is not None:
                self._client.send_to(gateway_wrap(dest, data), self._gateway)
            else:
                self._client.send_to(data, dest)
        except (OSError, TransferdError):
            pass  # a datagram that did not go is a lost one; the next round sends again

    def _establish(self, addr: Addr, params: PunchParams) -> PunchLink:
        """The route over a punched address, registered so its datagrams reach it."""
        keys = derive_link_keys(params.keys.link)
        if not params.initiator:
            keys = keys.swapped()
        link = PunchLink(params.link_id, addr, keys, sink=lambda sealed: self._send_to(addr, sealed))
        link.mark_down()
        for stale in [a for a, est in self._routes.items() if est.link.is_closed()]:
            del self._routes[stale]
        if len(self._routes) >= MAX_ESTABLISHED:
            oldest = min(self._routes, key=lambda a: self._routes[a].link.id)
            self._routes.pop(oldest).link.close()
        replaced = self._routes.get(addr)
        self._routes[addr] = _Established(link=link, opener=Opener(keys.recv), reader=FrameReader())
        if replaced is not None:
            replaced.link.close()
        return link


class Running:
    """An attempt that is registered and about to probe (see `PunchTable.begin`)."""

    def __init__(self, table: PunchTable, params: PunchParams, allowed: List[Addr], won: asyncio.Future) -> None:
        self._table = table
        self._params = params
        self._allowed = allowed
        self._won = won

    async def finish(self) -> PunchLink:
        """Probe every named address for about two seconds, and on the first authenticated reply return a link over it.

        The link starts marked down, so the session sends nothing on it before its own first ping has been answered.
        """
        table, params = self._table, self._params
        winner: Optional[Addr] = None
        for seq in range(ROUNDS):
            attempt = table._attempts.get(params.id)
            if attempt is not None:
                attempt.rounds_sent = seq + 1
            probe = encode_probe(
                params.keys,
                Probe(kind="probe", from_initiator=params.initiator, id=params.id, seq=seq),
            )
            for addr in self._allowed:
                table._send_to(addr, probe)
            winner = await _answer_within(self._won, PROBE_EVERY_S)
            if winner is not None:
                break
        if winner is None:
            winner = await _answer_within(self._won, LATE_REPLY_S)
        # The attempt keeps answering the peer's probes a little longer: it may not have heard our reply to the last one.
        asyncio.get_running_loop().call_later(LINGER_S, table._attempts.pop, params.id, None)
        if winner is None:
            raise OverlayError("no authenticated reply came back from any address the peer named")
        return table._establish(winner, params)


async def _answer_within(won: asyncio.Future, timeout: float) -> Optional[Addr]:
    """The first answer, or None when `timeout` passes first. The future is shielded, so a later wait can still take it."""
    try:
        return await asyncio.wait_for(asyncio.shield(won), timeout)
    except asyncio.TimeoutError:
        return None
