"""Tunnel, frames, invites, punch probes, relay messages and padding, checked against the reference."""

import struct

import pytest

from transferd import frames as F
from transferd.errors import InviteError, TunnelError
from transferd.identity import HybridIdentity
from transferd.invite import accept_invite
from transferd.punch import Probe, PunchKeys, decode_probe, encode_probe, gateway_unwrap, gateway_wrap
from transferd.relay import (
    PREFIX_DATA,
    decode_ack_or_delivered,
    decode_challenge,
    decode_error,
    decode_located,
    encapsulate,
    encode_ack,
    encode_challenge,
    encode_delivered,
    encode_error,
    encode_forward,
    encode_keepalive,
    encode_located,
    encode_locate,
    encode_register,
    pad,
    pow_ok,
    solve_pow,
    split,
    unpad,
)
from transferd.tunnel import Opener, ReplayWindow, Sealer, derive_link_keys

from .conftest import pattern, pattern32


# --- Tunnel ---------------------------------------------------------------------------------------


def test_link_keys_match_the_reference(wire_vectors):
    t = wire_vectors["tunnel"]
    keys = derive_link_keys(bytes.fromhex(t["session_key"]))
    assert keys.send.hex() == t["c2s"]
    assert keys.recv.hex() == t["s2c"]


def test_sealed_frames_match_the_reference_byte_for_byte(wire_vectors):
    t = wire_vectors["tunnel"]
    sealer = Sealer(bytes.fromhex(t["c2s"]))
    for f in t["frames"]:
        assert sealer.seal(bytes.fromhex(f["plaintext"]), counter=f["counter"]).hex() == f["sealed"]


def test_reference_frames_open_and_replays_are_refused(wire_vectors):
    t = wire_vectors["tunnel"]
    opener = Opener(bytes.fromhex(t["c2s"]))
    for f in t["frames"]:
        assert opener.open(bytes.fromhex(f["sealed"])) == bytes.fromhex(f["plaintext"])
    with pytest.raises(TunnelError):
        opener.open(bytes.fromhex(t["frames"][0]["sealed"]))


def test_a_flipped_bit_or_a_changed_length_does_not_authenticate(wire_vectors):
    t = wire_vectors["tunnel"]
    sealed = bytearray(bytes.fromhex(t["frames"][2]["sealed"]))
    flipped = bytearray(sealed)
    flipped[-1] ^= 1
    with pytest.raises(TunnelError):
        Opener(bytes.fromhex(t["c2s"])).open(bytes(flipped))
    lengthened = bytearray(sealed)
    lengthened[3] ^= 0x7F
    with pytest.raises(TunnelError):
        Opener(bytes.fromhex(t["c2s"])).open(bytes(lengthened))


def test_the_replay_window_is_4096_wide():
    w = ReplayWindow()
    assert w.accept(0)
    assert w.accept(5)
    assert w.accept(3), "late but inside the window"
    assert not w.accept(3), "the same counter twice"
    assert w.accept(5 + 4096)
    assert not w.accept(5), "fell out of the window"
    assert w.accept(100_000)
    assert w.accept(100_000 - 4000)
    assert not w.accept(100_000 - 4000)


# --- Overlay frames -------------------------------------------------------------------------------


def _expected_bodies():
    node_a = "ab" * 32
    node_b = "cd" * 32
    services = [F.ServiceInfo(name="chat", description="text")]
    ext = F.HelloExt(pairing=bytes([7]) * 16, direct=["192.0.2.1:4000"])
    ext_bytes = F.encode_hello_ext(ext)
    return {
        "HELLO": (F.HELLO, 2, 0, 1, F.Hello(1, 3, node_a, "node-a", services, ext_bytes, bytes([9]) * 16)),
        "HELLO_ACK": (F.HELLO_ACK, 2, 0, 2, F.HelloAck(2, node_b, "", [], bytes([9]) * 16, "", b"")),
        "OPEN": (F.OPEN, 2, 0, 3, F.Open(3, "chat", node_a)),
        "OPEN_OK": (F.OPEN_OK, 2, 0, 4, F.OpenOk(3, "relay")),
        "OPEN_ERR": (F.OPEN_ERR, 2, 0, 5, F.OpenErr(3, "denied", "nope")),
        "DATA": (F.DATA, 2, 0, 6, F.Data(3, 5, False, b"hello")),
        "DATA_FIN": (F.DATA, 2, 0, 7, F.Data(3, 6, True, b"")),
        "ACK": (F.ACK, 2, 0, 8, F.Ack(3, 6, [(8, 10), (12, 13)])),
        "ACK_BASE": (F.ACK, 2, 0, 9, None),  # the old form: 16 bytes, no SACK list
        "WINDOW": (F.WINDOW, 2, 0, 10, F.Window(3, 262_144)),
        "CLOSE": (F.CLOSE, 2, 0, 11, F.Close(3, "ok", "bye")),
        "CTRL_ACK": (F.CTRL_ACK, 2, 0, 12, F.CtrlAck(42)),
        "PING": (F.PING, 2, 0, 13, F.Ping(7, 1_234_567)),
        "PONG": (F.PONG, 2, 0, 14, F.Pong(7, 1_234_567)),
        "ROUTES": (
            F.ROUTES,
            2,
            0,
            15,
            F.Routes([F.RouteReport("relay", 12.5, 0.01, 2.0, True, 65_536, 1024, 13.0, 300.0, 1000, 10)]),
        ),
        "CANDIDATE": (
            F.CANDIDATE,
            3,
            0,
            16,
            F.PunchMsg(99, False, bytes([5]) * 32, [F.Candidate("203.0.113.7:50000", False), F.Candidate("10.0.0.2:50000", True)]),
        ),
        "BYE": (F.BYE, 2, 0, 17, None),
    }


@pytest.mark.parametrize("entry_name", list(_expected_bodies().keys()))
def test_each_frame_kind_matches_the_reference(wire_vectors, entry_name):
    entry = next(f for f in wire_vectors["frames"] if f["name"] == entry_name)
    kind, version, flags, seq, obj = _expected_bodies()[entry_name]
    assert entry["kind"] == kind and entry["version"] == version and entry["seq"] == seq
    if obj is None and entry_name == "ACK_BASE":
        body = struct.pack("<QQ", 3, 6)
    elif obj is None:
        body = b""
    else:
        body = F.encode_body(kind, obj)
    assert body.hex() == entry["body"], entry_name
    frame = F.Frame(version=version, kind=kind, flags=flags, seq=seq, body=body)
    assert frame.encode().hex() == entry["frame"], entry_name
    decoded, used = F.decode_frame(frame.encode()) or (None, 0)
    assert decoded == frame and used == len(frame.encode())
    if obj is not None:
        assert F.decode_body(kind, body) == obj, entry_name


def test_the_ack_base_form_reads_as_an_ack_without_ranges(wire_vectors):
    entry = next(f for f in wire_vectors["frames"] if f["name"] == "ACK_BASE")
    frame = F.decode_frame(bytes.fromhex(entry["frame"]))[0]
    assert F.decode_body(F.ACK, frame.body) == F.Ack(3, 6, [])


def test_the_flags_survive_the_header(wire_vectors):
    entry = next(f for f in wire_vectors["frames"] if f["name"] == "flags_mirror_bulk")
    frame = F.decode_frame(bytes.fromhex(entry["frame"]))[0]
    assert frame.flags == 3 and frame.is_mirrored and frame.is_bulk and frame.seq == 18


def test_hello_ext_matches_the_reference(wire_vectors):
    h = wire_vectors["hello_ext"]
    ext = F.HelloExt(pairing=bytes.fromhex(h["pairing"]), direct=h["direct"])
    assert F.encode_hello_ext(ext).hex() == h["bytes"]
    assert F.decode_hello_ext(bytes.fromhex(h["bytes"])) == ext


def test_an_older_extension_with_only_the_pairing_still_reads():
    old = F.encode_hello_ext(F.HelloExt(pairing=bytes([3]) * 16))[:17]  # option tag + 16 bytes
    assert F.decode_hello_ext(old) == F.HelloExt(pairing=bytes([3]) * 16, direct=[])


def test_an_unreadable_extension_is_an_empty_one():
    assert F.decode_hello_ext(b"\x09garbage") == F.HelloExt()


def test_an_unknown_kind_is_skipped_and_known_ones_pass():
    reader = F.FrameReader()
    unknown = F.Frame(2, 0x55, 0, 1, b"xyz").encode()
    known = F.Frame.with_body(2, F.PING, 2, F.Ping(1, 2)).encode()
    got = reader.push(unknown + known)
    assert [f.kind for f in got] == [F.PING]


def test_a_frame_that_is_not_ours_empties_the_buffer():
    reader = F.FrameReader()
    assert reader.push(b"NOPE" + bytes(20)) == []
    assert reader.buffered() == 0


def test_negotiation_picks_the_highest_common_version():
    assert F.negotiate(1, 3, 1, 3) == 3
    assert F.negotiate(1, 2, 1, 3) == 2
    assert F.negotiate(4, 5, 1, 3) is None


# --- Invites --------------------------------------------------------------------------------------


def test_the_reference_invite_is_accepted(wire_vectors):
    inv = wire_vectors["invite"]
    verified = accept_invite(inv["invite"], now=inv["expires_at"] - 1)
    assert verified.node_id == inv["node_id"]
    assert verified.name == inv["verified_name"]
    assert verified.key_fingerprint.hex() == inv["key_fingerprint"]
    assert verified.nonce.hex() == inv["nonce"]
    assert verified.relays == tuple(inv["relays"])
    assert verified.direct == tuple(inv["direct"])


@pytest.mark.parametrize("case", ["tampered_relays", "tampered_expiry", "tdov1_prefix", "oversized"])
def test_the_reference_refuses_these_invites_and_so_do_we(wire_vectors, case):
    inv = wire_vectors["invite"]
    text = next(r["invite"] for r in inv["refused"] if r["case"] == case)
    with pytest.raises(InviteError):
        accept_invite(text, now=inv["expires_at"] - 1)


def test_an_expired_invite_is_refused(wire_vectors):
    inv = wire_vectors["invite"]
    with pytest.raises(InviteError):
        accept_invite(inv["invite"], now=inv["expires_at"] + 1)


def _signed_invite_expiring_at(identity, expires_at):
    """An invite signed correctly for `expires_at`, which `make_invite` would never issue."""
    import json
    import os

    from transferd.identity import key_fingerprint
    from transferd.invite import PREFIX, base64url_encode, invite_binding

    nonce = os.urandom(16)
    fields = dict(
        version=2,
        node_id=identity.node_id,
        name=identity.name,
        key_fingerprint=key_fingerprint(identity.public_key).hex(),
        relays=[],
        direct=[],
        expires_at=expires_at,
        nonce=nonce.hex(),
    )
    signature = identity.sign_ed25519(invite_binding(**fields)).hex()
    body = {**fields, "signature": signature}
    return PREFIX + base64url_encode(json.dumps(body, separators=(",", ":")).encode("utf-8"))


def test_an_invite_that_lives_longer_than_a_day_is_refused():
    from transferd.invite import MAX_TTL_S

    identity = HybridIdentity.generate("alpha")
    now = 1_000_000
    too_long = _signed_invite_expiring_at(identity, now + MAX_TTL_S + 3600)
    with pytest.raises(InviteError):
        accept_invite(too_long, now=now)
    at_the_limit = _signed_invite_expiring_at(identity, now + MAX_TTL_S - 60)
    assert accept_invite(at_the_limit, now=now).node_id == identity.node_id


def test_an_invite_we_make_is_accepted_by_our_own_reader():
    from transferd.invite import make_invite

    identity = HybridIdentity.generate("alpha")
    made = make_invite(identity, ["relay.example:4433"], ["192.0.2.10:4000"], 600, now=1_000_000)
    verified = accept_invite(made.text, now=1_000_000 + 1)
    assert verified.node_id == identity.node_id
    assert verified.nonce == made.nonce


# --- Punch probes ---------------------------------------------------------------------------------


def test_punch_keys_match_the_reference(wire_vectors):
    p = wire_vectors["punch"]
    keys = PunchKeys.derive(p["id"], bytes.fromhex(p["initiator_nonce"]), bytes.fromhex(p["responder_nonce"]))
    assert keys.probe.hex() == p["probe_key"]
    assert keys.link.hex() == p["link_key"]


def test_probes_match_the_reference_and_decode(wire_vectors):
    p = wire_vectors["punch"]
    keys = PunchKeys.derive(p["id"], bytes.fromhex(p["initiator_nonce"]), bytes.fromhex(p["responder_nonce"]))
    for entry in p["probes"]:
        probe = Probe(entry["kind"], entry["from_initiator"], p["id"], entry["seq"])
        datagram = encode_probe(keys, probe)
        assert datagram.hex() == entry["datagram"]
        assert decode_probe(keys, datagram) == probe


def test_a_probe_under_another_key_does_not_decode(wire_vectors):
    p = wire_vectors["punch"]
    keys = PunchKeys.derive(p["id"], bytes.fromhex(p["initiator_nonce"]), bytes.fromhex(p["responder_nonce"]))
    other = PunchKeys.derive(p["id"] + 1, bytes.fromhex(p["initiator_nonce"]), bytes.fromhex(p["responder_nonce"]))
    datagram = bytes.fromhex(p["probes"][0]["datagram"])
    assert decode_probe(other, datagram) is None


def test_the_gateway_envelope_round_trips():
    wrapped = gateway_wrap(("2001:db8::5", 4500), b"datagram")
    assert gateway_unwrap(wrapped) == (("2001:db8::5", 4500), b"datagram")
    assert gateway_unwrap(gateway_wrap(("198.51.100.1", 9), b"x")) == (("198.51.100.1", 9), b"x")


# --- Relay padding and payloads -------------------------------------------------------------------


def test_padding_matches_the_reference(wire_vectors):
    for entry in wire_vectors["padding"]:
        data = bytes.fromhex(entry["input"])
        assert pad(data).hex() == entry["padded"]
        assert len(pad(data)) >= 64 and (len(pad(data)) & (len(pad(data)) - 1)) == 0


def test_the_relay_payload_matches_the_reference(wire_vectors):
    p = wire_vectors["payload"]
    token = bytes.fromhex(p["sender_token"])
    body = bytes.fromhex(p["body"])
    assert encapsulate(PREFIX_DATA, token, body).hex() == p["padded"]
    assert unpad(bytes.fromhex(p["padded"])) == (PREFIX_DATA, token, body)


def test_relay_messages_match_the_reference(wire_vectors):
    relay = wire_vectors["relay"]
    token = bytes.fromhex(relay["token"])
    challenge = bytes.fromhex(relay["challenge"])
    nonce = relay["valid_nonce"]
    expected = {
        "register": encode_register(token, nonce, 7),
        "forward": encode_forward(token, nonce, 9, pattern(40, 92)),
        "keepalive": encode_keepalive(token, nonce, 8),
        "challenge": encode_challenge(challenge, 1_900_000_000, 12),
        "locate": encode_locate(token, pattern32(93), nonce, 11),
        "located_v4": encode_located(("203.0.113.5", 4433), ("198.51.100.9", 50000), 5),
        "located_v6": encode_located(("2001:db8::1", 4433), None, 6),
        "error": encode_error(1, 3, "no such token"),
        "ack": encode_ack(9),
        "delivered": encode_delivered(9, pattern(40, 94)),
    }
    for m in relay["messages"]:
        assert expected[m["name"]].hex() == m["bytes"], m["name"]


def test_relay_bodies_decode_back(wire_vectors):
    relay = wire_vectors["relay"]
    messages = {m["name"]: bytes.fromhex(m["bytes"]) for m in relay["messages"]}
    tag, body = split(messages["challenge"])
    assert tag == 0x04
    challenge = decode_challenge(body)
    assert challenge.challenge.hex() == relay["challenge"] and challenge.difficulty == 12
    _, body = split(messages["located_v6"])
    assert decode_located(body).self_addr == ("2001:db8::1", 4433)
    _, body = split(messages["error"])
    assert decode_error(body).code == "TokenNotFound"
    _, body = split(messages["ack"])
    assert decode_ack_or_delivered(body).sender_seq == 9
    _, body = split(messages["delivered"])
    assert decode_ack_or_delivered(body).ciphertext == pattern(40, 94)


def test_proof_of_work_matches_the_reference(wire_vectors):
    relay = wire_vectors["relay"]
    challenge = bytes.fromhex(relay["challenge"])
    token = bytes.fromhex(relay["token"])
    assert pow_ok(relay["difficulty"], challenge, token, relay["valid_nonce"])
    assert pow_ok(relay["difficulty"], challenge, token, relay["check_nonce"]) == relay["check_result"]
    assert solve_pow(relay["difficulty"], challenge, token) == relay["valid_nonce"]
