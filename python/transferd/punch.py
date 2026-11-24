"""Hole punching (§8): the probe keys, the 33-byte probe datagram, and the TDGW gateway envelope.

Probes are plain datagrams sent from a relay registration socket. Their keys come from the two
nodes' nonces, which only ever travel inside the encrypted session.

    probe := "TDPB" | kind u8 | id u64 BE | seq u32 BE | mac[16]       (33 bytes)
    kind  := 1 probe from the initiator, 2 probe from the responder,
             3 reply from the initiator, 4 reply from the responder
    mac   := BLAKE3-keyed(probe_key, every byte before it)[..16]
"""

from __future__ import annotations

import hmac
import ipaddress
import struct
from dataclasses import dataclass
from typing import Optional, Tuple

from .crypto import blake3_derive_key, blake3_keyed

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
