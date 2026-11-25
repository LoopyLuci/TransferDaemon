"""Ghost keys: blind issuance, certificates, the files, and a relay's admission of a registration.

The Rust reference (`crates/transferd-crypto/src/ghostkey.rs`, `crates/relayd/src/ghost.rs`) writes `vectors/ghost.json`;
the reference tests check that a certificate and a registration it produced verify here, byte for byte.
"""

from dataclasses import replace

import pytest

from transferd.ghostkey import (
    BlindState,
    GhostCertificate,
    GhostKey,
    GhostKeyError,
    GhostPolicy,
    Issuer,
    IssuerPublic,
    admit_ghost,
    binding,
)
from transferd.relay import Tag, decode_register_ghost, encode_register_ghost


@pytest.fixture(scope="module")
def issuer() -> Issuer:
    return Issuer.generate("test relay", "supporter", 2048)


def test_a_ghost_key_issued_by_blind_signature_verifies(issuer):
    me = GhostKey.generate()
    blinded, state = me.blind_request(issuer.public)
    cert = me.finish(issuer.public, state, issuer.sign_blinded(blinded))
    cert.verify(issuer.public)
    sig = me.sign(b"hello relay")
    cert.verify_signed(issuer.public, b"hello relay", sig)
    with pytest.raises(GhostKeyError):
        cert.verify_signed(issuer.public, b"other message", sig)
    assert GhostCertificate.from_text(cert.to_text()) == cert


def test_the_issuer_never_sees_the_key(issuer):
    me = GhostKey.generate()
    first, _ = me.blind_request(issuer.public)
    second, _ = me.blind_request(issuer.public)
    assert first != second, "every request is blinded afresh"
    assert me.public() not in first, "the key is not visible in the request"


def test_forged_or_mismatched_certificates_fail(issuer):
    other = Issuer.generate("someone else", "supporter", 2048)
    me = GhostKey.generate()
    blinded, state = me.blind_request(issuer.public)
    cert = me.finish(issuer.public, state, issuer.sign_blinded(blinded))

    with pytest.raises(GhostKeyError):
        cert.verify(other.public)
    swapped = replace(cert, ghost_public=GhostKey.generate().public())
    with pytest.raises(GhostKeyError):
        swapped.verify(issuer.public)
    retiered = replace(cert, tier="gold")
    with pytest.raises(GhostKeyError):
        retiered.verify(issuer.public)

    blinded, state = me.blind_request(issuer.public)
    try:
        wrong = other.sign_blinded(blinded)
    except GhostKeyError:
        wrong = None  # the value is larger than the other key's modulus: nothing to unblind
    if wrong is not None:
        with pytest.raises(GhostKeyError):
            me.finish(issuer.public, state, wrong)
    with pytest.raises(GhostKeyError):
        issuer.sign_blinded(b"\x01\x02\x03")


def test_the_files_round_trip(issuer):
    again = Issuer.from_secret_text(issuer.to_secret_text())
    assert again.public == issuer.public
    assert IssuerPublic.from_text(issuer.public.to_text()) == issuer.public
    me = GhostKey.generate()
    blinded, state = me.blind_request(issuer.public)
    state_again, me_again = BlindState.from_text(state.to_text(me))
    assert me_again.public() == me.public()
    cert = me_again.finish(issuer.public, state_again, again.sign_blinded(blinded))
    cert.verify(issuer.public)


def test_the_issuer_key_size_is_bounded():
    with pytest.raises(GhostKeyError, match="2048 to 4096"):
        Issuer.generate("x", "t", 1024)


def test_a_certificate_from_the_reference_verifies(ghost_vectors):
    v = ghost_vectors
    issuer = IssuerPublic.from_text(v["issuer"]["public_text"])
    assert issuer.id() == v["issuer"]["id"]
    assert issuer.spki.hex() == v["issuer"]["spki"]

    cert = GhostCertificate.from_text(v["certificate"]["text"])
    cert.verify(issuer)
    assert cert.encode_bincode().hex() == v["certificate"]["bincode"], "the bincode is the reference's, byte for byte"
    assert GhostCertificate.decode_bincode(bytes.fromhex(v["certificate"]["bincode"])) == cert
    assert cert.ghost_public.hex() == v["certificate"]["ghost_public"]


def test_the_relay_admits_a_registration_the_reference_signed(ghost_vectors):
    v = ghost_vectors
    reg = v["registration"]
    issuer = IssuerPublic.from_text(v["issuer"]["public_text"])
    token = bytes.fromhex(reg["session_token"])

    ghost = GhostKey(bytes.fromhex(v["ghost_secret"]))
    assert ghost.sign(binding(token, reg["seq"])).hex() == reg["signature"], "Ed25519 signs the same bytes"
    assert binding(token, reg["seq"]).hex() == reg["binding"]

    admitted = admit_ghost(
        GhostPolicy(issuers=(issuer,)),
        token,
        reg["seq"],
        bytes.fromhex(v["certificate"]["bincode"]),
        bytes.fromhex(reg["signature"]),
    )
    assert admitted == bytes.fromhex(v["certificate"]["ghost_public"])


def test_the_relay_refuses_a_registration_for_another_session(ghost_vectors):
    v = ghost_vectors
    reg = v["registration"]
    policy = GhostPolicy(issuers=(IssuerPublic.from_text(v["issuer"]["public_text"]),))
    with pytest.raises(GhostKeyError, match="signature"):
        admit_ghost(
            policy,
            bytes.fromhex(reg["session_token"]),
            reg["seq"] + 1,
            bytes.fromhex(v["certificate"]["bincode"]),
            bytes.fromhex(reg["signature"]),
        )


def test_the_relay_refuses_a_certificate_from_an_issuer_it_does_not_trust(ghost_vectors, issuer):
    v = ghost_vectors
    reg = v["registration"]
    args = (bytes.fromhex(reg["session_token"]), reg["seq"], bytes.fromhex(v["certificate"]["bincode"]))
    signature = bytes.fromhex(reg["signature"])
    with pytest.raises(GhostKeyError, match="trusts no ghost key issuer"):
        admit_ghost(GhostPolicy(), *args, signature)
    with pytest.raises(GhostKeyError, match="not trusted here"):
        admit_ghost(GhostPolicy(issuers=(issuer.public,)), *args, signature)


def test_the_registration_message_is_the_reference_bytes(ghost_vectors):
    reg = ghost_vectors["registration"]
    body = bytes.fromhex(reg["body"])
    token = bytes.fromhex(reg["session_token"])
    cert = bytes.fromhex(ghost_vectors["certificate"]["bincode"])
    signature = bytes.fromhex(reg["signature"])

    wire = encode_register_ghost(token, reg["pow_nonce"], reg["seq"], cert, signature)
    assert wire[0] == Tag.REGISTER_GHOST
    assert wire[1:] == body, "the registration body is the reference's, byte for byte"

    decoded = decode_register_ghost(body)
    assert (decoded.session_token, decoded.pow_nonce, decoded.seq) == (token, reg["pow_nonce"], reg["seq"])
    assert (decoded.certificate, decoded.signature) == (cert, signature)
