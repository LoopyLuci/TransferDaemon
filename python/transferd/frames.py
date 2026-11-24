"""Overlay frames (§4) and their bodies (§5).

A frame is `"TDOV" | version u8 | kind u8 | flags u16 LE | seq u64 LE | len u32 LE | body[len]`.
The body is bincode for the struct named by `kind` (see `bincode.py`).

Reading follows the reference's rules: a frame of a kind this build does not know is skipped by
its length; a frame that is not ours, or declares a body over `MAX_BODY`, empties the buffer.
A body's trailing bytes are ignored. `ACK` has an older form, `ACK_BASE`, which has no SACK ranges.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from .bincode import Reader, Writer
from .errors import DecodeError, FrameError

MAGIC = b"TDOV"
HEADER_LEN = 20
MAX_BODY = 60 * 1024
VERSION_MIN = 1
VERSION_CURRENT = 3
VERSION_PUNCH = 3

FLAG_MIRROR = 0x1
FLAG_BULK = 0x2

HELLO = 0x01
HELLO_ACK = 0x02
OPEN = 0x03
OPEN_OK = 0x04
OPEN_ERR = 0x05
DATA = 0x10
ACK = 0x11
WINDOW = 0x12
CLOSE = 0x13
CTRL_ACK = 0x14
PING = 0x20
PONG = 0x21
ROUTES = 0x30
CANDIDATE = 0x40
BYE = 0x7F

KNOWN_KINDS = frozenset(
    {HELLO, HELLO_ACK, OPEN, OPEN_OK, OPEN_ERR, DATA, ACK, WINDOW, CLOSE, CTRL_ACK, PING, PONG, ROUTES, CANDIDATE, BYE}
)
RELIABLE_KINDS = frozenset({HELLO, HELLO_ACK, OPEN, OPEN_OK, OPEN_ERR, WINDOW, CLOSE, CANDIDATE})


# --- Bodies ---------------------------------------------------------------------------------------


@dataclass
class ServiceInfo:
    name: str
    description: str = ""


@dataclass
class HelloExt:
    """The bincode extension a HELLO or HELLO_ACK carries. Optional fields only."""

    pairing: Optional[bytes] = None  # 16-byte invite nonce
    direct: List[str] = field(default_factory=list)


@dataclass
class Hello:
    min_version: int
    max_version: int
    node_id: str
    name: str
    services: List[ServiceInfo]
    ext: bytes
    nonce: bytes  # 16 bytes


@dataclass
class HelloAck:
    version: int
    node_id: str
    name: str
    services: List[ServiceInfo]
    nonce: bytes
    reason: str
    ext: bytes


@dataclass
class Open:
    stream: int
    service: str
    node_id: str


@dataclass
class OpenOk:
    stream: int
    route: str


@dataclass
class OpenErr:
    stream: int
    code: str
    reason: str


@dataclass
class Data:
    stream: int
    seq: int
    fin: bool
    payload: bytes


@dataclass
class Ack:
    stream: int
    seq: int
    sack: List[Tuple[int, int]] = field(default_factory=list)


@dataclass
class AckBase:
    stream: int
    seq: int


@dataclass
class Window:
    stream: int
    credit: int


@dataclass
class Close:
    stream: int
    code: str
    reason: str


@dataclass
class CtrlAck:
    seq: int


@dataclass
class Ping:
    nonce: int
    sent_us: int


@dataclass
class Pong:
    nonce: int
    sent_us: int


@dataclass
class RouteReport:
    kind: str
    rtt_ms: float
    loss: float
    mbps: float
    active: bool
    cwnd: int
    in_flight: int
    srtt_ms: float
    rto_ms: float
    sent_bytes: int
    retx_bytes: int


@dataclass
class Routes:
    routes: List[RouteReport]


@dataclass
class Candidate:
    addr: str
    private: bool


@dataclass
class PunchMsg:
    id: int
    reply: bool
    nonce: bytes  # 32 bytes
    candidates: List[Candidate]


# --- Codecs for the bodies ------------------------------------------------------------------------


def _write_service(w: Writer, s: ServiceInfo) -> None:
    w.string(s.name)
    w.string(s.description)


def _read_service(r: Reader) -> ServiceInfo:
    return ServiceInfo(name=r.string(), description=r.string())


def encode_hello_ext(ext: HelloExt) -> bytes:
    w = Writer()
    w.option(ext.pairing, lambda w_, v: w_.raw(v))
    w.seq(ext.direct, lambda w_, v: w_.string(v))
    return w.getvalue()


def decode_hello_ext(data: bytes) -> HelloExt:
    """An unreadable extension is an empty one: an extension is never fatal."""
    if not data:
        return HelloExt()
    try:
        r = Reader(data)
        return HelloExt(pairing=r.option(lambda rr: rr.raw(16)), direct=r.seq(lambda rr: rr.string()))
    except DecodeError:
        pass
    try:  # the extension as it was before `direct` existed
        return HelloExt(pairing=Reader(data).option(lambda rr: rr.raw(16)), direct=[])
    except DecodeError:
        return HelloExt()


def _encode_hello(h: Hello) -> bytes:
    w = Writer()
    w.u16(h.min_version)
    w.u16(h.max_version)
    w.string(h.node_id)
    w.string(h.name)
    w.seq(h.services, _write_service)
    w.bytes_(h.ext)
    w.raw(h.nonce)
    return w.getvalue()


def _decode_hello(r: Reader) -> Hello:
    return Hello(
        min_version=r.u16(),
        max_version=r.u16(),
        node_id=r.string(),
        name=r.string(),
        services=r.seq(_read_service),
        ext=r.bytes_(),
        nonce=r.raw(16),
    )


def _encode_hello_ack(h: HelloAck) -> bytes:
    w = Writer()
    w.u16(h.version)
    w.string(h.node_id)
    w.string(h.name)
    w.seq(h.services, _write_service)
    w.raw(h.nonce)
    w.string(h.reason)
    w.bytes_(h.ext)
    return w.getvalue()


def _decode_hello_ack(r: Reader) -> HelloAck:
    return HelloAck(
        version=r.u16(),
        node_id=r.string(),
        name=r.string(),
        services=r.seq(_read_service),
        nonce=r.raw(16),
        reason=r.string(),
        ext=r.bytes_(),
    )


def _encode_routes(routes: Routes) -> bytes:
    def write_route(w: Writer, x: RouteReport) -> None:
        w.string(x.kind)
        w.f64(x.rtt_ms)
        w.f64(x.loss)
        w.f64(x.mbps)
        w.boolean(x.active)
        w.u64(x.cwnd)
        w.u64(x.in_flight)
        w.f64(x.srtt_ms)
        w.f64(x.rto_ms)
        w.u64(x.sent_bytes)
        w.u64(x.retx_bytes)

    w = Writer()
    w.seq(routes.routes, write_route)
    return w.getvalue()


def _decode_routes(r: Reader) -> Routes:
    def read_route(rr: Reader) -> RouteReport:
        return RouteReport(
            kind=rr.string(),
            rtt_ms=rr.f64(),
            loss=rr.f64(),
            mbps=rr.f64(),
            active=rr.boolean(),
            cwnd=rr.u64(),
            in_flight=rr.u64(),
            srtt_ms=rr.f64(),
            rto_ms=rr.f64(),
            sent_bytes=rr.u64(),
            retx_bytes=rr.u64(),
        )

    return Routes(routes=r.seq(read_route))


def _encode_punch(p: PunchMsg) -> bytes:
    def write_candidate(w: Writer, c: Candidate) -> None:
        w.string(c.addr)
        w.boolean(c.private)

    w = Writer()
    w.u64(p.id)
    w.boolean(p.reply)
    w.raw(p.nonce)
    w.seq(p.candidates, write_candidate)
    return w.getvalue()


def _decode_punch(r: Reader) -> PunchMsg:
    def read_candidate(rr: Reader) -> Candidate:
        return Candidate(addr=rr.string(), private=rr.boolean())

    return PunchMsg(id=r.u64(), reply=r.boolean(), nonce=r.raw(32), candidates=r.seq(read_candidate))


def _ack_from(body: bytes) -> Ack:
    """An ACK with its trailing SACK list; a body that does not read that way is an `AckBase`."""
    try:
        r = Reader(body)
        stream, seq = r.u64(), r.u64()
        return Ack(stream=stream, seq=seq, sack=r.seq(lambda rr: (rr.u64(), rr.u64())))
    except DecodeError:
        base = _decode_ack_base(Reader(body))
        return Ack(stream=base.stream, seq=base.seq, sack=[])


def _encode_ack(a: Ack) -> bytes:
    w = Writer()
    w.u64(a.stream)
    w.u64(a.seq)
    w.seq(a.sack, lambda w_, pair: (w_.u64(pair[0]), w_.u64(pair[1])))
    return w.getvalue()


def _decode_ack_base(r: Reader) -> AckBase:
    return AckBase(stream=r.u64(), seq=r.u64())


# kind -> (encode body object -> bytes, decode bytes -> body object)
_BODY_CODECS: Dict[int, Tuple[Callable[[object], bytes], Callable[[bytes], object]]] = {
    HELLO: (
        _encode_hello,
        lambda b: _decode_hello(Reader(b)),
    ),
    HELLO_ACK: (
        _encode_hello_ack,
        lambda b: _decode_hello_ack(Reader(b)),
    ),
    OPEN: (
        lambda o: _pack(lambda w: (w.u64(o.stream), w.string(o.service), w.string(o.node_id))),
        lambda b: _decode_open(Reader(b)),
    ),
    OPEN_OK: (
        lambda o: _pack(lambda w: (w.u64(o.stream), w.string(o.route))),
        lambda b: (lambda r: OpenOk(stream=r.u64(), route=r.string()))(Reader(b)),
    ),
    OPEN_ERR: (
        lambda o: _pack(lambda w: (w.u64(o.stream), w.string(o.code), w.string(o.reason))),
        lambda b: (lambda r: OpenErr(stream=r.u64(), code=r.string(), reason=r.string()))(Reader(b)),
    ),
    DATA: (
        lambda o: _pack(lambda w: (w.u64(o.stream), w.u64(o.seq), w.boolean(o.fin), w.bytes_(o.payload))),
        lambda b: (lambda r: Data(stream=r.u64(), seq=r.u64(), fin=r.boolean(), payload=r.bytes_()))(Reader(b)),
    ),
    ACK: (
        _encode_ack,
        _ack_from,
    ),
    WINDOW: (
        lambda o: _pack(lambda w: (w.u64(o.stream), w.u64(o.credit))),
        lambda b: (lambda r: Window(stream=r.u64(), credit=r.u64()))(Reader(b)),
    ),
    CLOSE: (
        lambda o: _pack(lambda w: (w.u64(o.stream), w.string(o.code), w.string(o.reason))),
        lambda b: (lambda r: Close(stream=r.u64(), code=r.string(), reason=r.string()))(Reader(b)),
    ),
    CTRL_ACK: (
        lambda o: _pack(lambda w: w.u64(o.seq)),
        lambda b: CtrlAck(seq=Reader(b).u64()),
    ),
    PING: (
        lambda o: _pack(lambda w: (w.u64(o.nonce), w.u64(o.sent_us))),
        lambda b: (lambda r: Ping(nonce=r.u64(), sent_us=r.u64()))(Reader(b)),
    ),
    PONG: (
        lambda o: _pack(lambda w: (w.u64(o.nonce), w.u64(o.sent_us))),
        lambda b: (lambda r: Pong(nonce=r.u64(), sent_us=r.u64()))(Reader(b)),
    ),
    ROUTES: (
        _encode_routes,
        lambda b: _decode_routes(Reader(b)),
    ),
    CANDIDATE: (
        _encode_punch,
        lambda b: _decode_punch(Reader(b)),
    ),
    BYE: (
        lambda _o: b"",
        lambda _b: None,
    ),
}


def _pack(fn: Callable[[Writer], object]) -> bytes:
    w = Writer()
    fn(w)
    return w.getvalue()


def _decode_open(r: Reader) -> Open:
    return Open(stream=r.u64(), service=r.string(), node_id=r.string())


def encode_body(kind: int, body: object) -> bytes:
    if kind not in _BODY_CODECS:
        raise FrameError(f"no body codec for kind {kind:#04x}")
    return _BODY_CODECS[kind][0](body)


def decode_body(kind: int, body: bytes) -> object:
    if kind not in _BODY_CODECS:
        raise FrameError(f"no body codec for kind {kind:#04x}")
    try:
        return _BODY_CODECS[kind][1](body)
    except DecodeError as exc:
        raise FrameError(f"body of kind {kind:#04x} does not decode: {exc}") from exc


# --- Frames ---------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Frame:
    version: int
    kind: int
    flags: int
    seq: int
    body: bytes

    @classmethod
    def with_body(cls, version: int, kind: int, seq: int, body: object, flags: int = 0) -> "Frame":
        return cls(version=version, kind=kind, flags=flags, seq=seq, body=encode_body(kind, body))

    def decode(self) -> object:
        return decode_body(self.kind, self.body)

    @property
    def is_mirrored(self) -> bool:
        return bool(self.flags & FLAG_MIRROR)

    @property
    def is_bulk(self) -> bool:
        return bool(self.flags & FLAG_BULK)

    def encode(self) -> bytes:
        return MAGIC + struct.pack("<BBHQI", self.version, self.kind, self.flags, self.seq, len(self.body)) + self.body


def decode_frame(buf: bytes) -> Optional[Tuple[Frame, int]]:
    """Read one frame from the front of `buf`. Returns `None` while the frame is incomplete."""
    if len(buf) < HEADER_LEN:
        return None
    if buf[:4] != MAGIC:
        raise FrameError("not a TransferDaemon overlay frame")
    version, kind, flags, seq, length = struct.unpack("<BBHQI", buf[4:HEADER_LEN])
    if length > MAX_BODY:
        raise FrameError(f"frame body of {length} bytes is over the limit")
    if len(buf) < HEADER_LEN + length:
        return None
    frame = Frame(version=version, kind=kind, flags=flags, seq=seq, body=bytes(buf[HEADER_LEN : HEADER_LEN + length]))
    return frame, HEADER_LEN + length


def negotiate(peer_min: int, peer_max: int, our_min: int = VERSION_MIN, our_max: int = VERSION_CURRENT) -> Optional[int]:
    """The highest version both ranges contain, or `None` when they do not overlap."""
    hi = min(peer_max, our_max)
    lo = max(peer_min, our_min)
    return hi if lo <= hi else None


class FrameReader:
    """Reassembles frames from a byte stream, keeping those of kinds this build knows."""

    __slots__ = ("_buf",)

    def __init__(self) -> None:
        self._buf = bytearray()

    def push(self, data: bytes) -> List[Frame]:
        self._buf += data
        out: List[Frame] = []
        while True:
            try:
                got = decode_frame(bytes(self._buf))
            except FrameError:
                self._buf.clear()
                break
            if got is None:
                break
            frame, used = got
            del self._buf[:used]
            if frame.kind in KNOWN_KINDS:
                out.append(frame)
        return out

    def buffered(self) -> int:
        return len(self._buf)
