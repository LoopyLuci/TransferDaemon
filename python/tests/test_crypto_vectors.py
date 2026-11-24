"""The primitives and identity, checked against the Rust reference's output."""

from transferd.crypto import (
    blake3_derive_key,
    blake3_hash,
    blake3_keyed,
    ed25519_verify_strict,
    mlkem_decapsulate,
    mlkem_keypair,
)
from transferd.handshake import (
    INITIATOR_FLIGHT_LEN,
    INITIATOR_HELLO_LEN,
    RESPONDER_FLIGHT_LEN,
    RESPONDER_HELLO_LEN,
    TAG_INITIATOR,
    TAG_RESPONDER,
    Flight,
)
from transferd.identity import HybridIdentity, key_fingerprint, relay_token_for, verify_hybrid


def test_blake3_hash_matches_the_reference(crypto_vectors):
    v = crypto_vectors["blake3"]["hash"]
    assert blake3_hash(bytes.fromhex(v["input"])).hex() == v["output"]


def test_blake3_keyed_matches_the_reference(crypto_vectors):
    v = crypto_vectors["blake3"]["keyed"]
    assert blake3_keyed(bytes.fromhex(v["key"]), bytes.fromhex(v["input"])).hex() == v["output"]


def test_blake3_derive_key_matches_the_reference(crypto_vectors):
    v = crypto_vectors["blake3"]["derive_key"]
    assert blake3_derive_key(v["context"], bytes.fromhex(v["input"])).hex() == v["output"]


def test_ml_kem_768_keys_and_decapsulation_match_fips_203(crypto_vectors):
    v = crypto_vectors["mlkem768"]
    private, ek = mlkem_keypair(bytes.fromhex(v["seed"]))
    assert ek.hex() == v["encapsulation_key"]
    assert mlkem_decapsulate(private, bytes.fromhex(v["ciphertext"])).hex() == v["shared_secret"]


def test_hybrid_identity_matches_the_reference(crypto_vectors):
    v = crypto_vectors["identity"]
    identity = HybridIdentity(bytes.fromhex(v["seed"]))
    assert identity.node_id == v["node_id"]
    assert identity.public_key.hex() == v["hybrid_public_key"]
    assert identity.relay_token().hex() == v["relay_token"]
    assert key_fingerprint(identity.public_key).hex() == v["key_fingerprint"]
    assert relay_token_for(v["node_id"]).hex() == v["relay_token"]


def test_reference_hybrid_signature_verifies(crypto_vectors):
    v = crypto_vectors["identity"]["sign"]
    pk = bytes.fromhex(crypto_vectors["identity"]["hybrid_public_key"])
    sig = bytes.fromhex(v["signature"])
    msg = bytes.fromhex(v["message"])
    assert verify_hybrid(pk, msg, sig)
    assert not verify_hybrid(pk, msg + b"!", sig)


def test_our_signature_verifies_under_the_reference_public_key(crypto_vectors):
    v = crypto_vectors["identity"]
    identity = HybridIdentity(bytes.fromhex(v["seed"]))
    msg = b"made by Python"
    assert verify_hybrid(identity.public_key, msg, identity.sign(msg))


def test_ed25519_signature_is_deterministic_and_matches_the_reference(crypto_vectors):
    v = crypto_vectors["identity"]
    identity = HybridIdentity(bytes.fromhex(v["seed"]))
    e = v["ed25519_sign"]
    assert identity.sign_ed25519(bytes.fromhex(e["message"])).hex() == e["signature"]
    assert ed25519_verify_strict(
        identity.ed25519_public_key, bytes.fromhex(e["message"]), bytes.fromhex(e["signature"])
    )


def test_strict_verification_refuses_a_non_canonical_s(crypto_vectors):
    v = crypto_vectors["identity"]
    identity = HybridIdentity(bytes.fromhex(v["seed"]))
    e = v["ed25519_sign"]
    sig = bytes.fromhex(e["signature"])
    L = 2**252 + 27742317777372353535851937790883648493
    s = int.from_bytes(sig[32:], "little")
    forged = sig[:32] + (s + L).to_bytes(32, "little")
    assert not ed25519_verify_strict(identity.ed25519_public_key, bytes.fromhex(e["message"]), forged)


def test_strict_verification_refuses_a_small_order_public_key():
    identity_key = bytes(32)  # the all-zero encoding is a point of small order
    sig = bytes(64)
    assert not ed25519_verify_strict(identity_key, b"msg", sig)


def test_reference_handshake_flights_have_the_specified_lengths_and_verify(crypto_vectors):
    h = crypto_vectors["handshake"]
    init = Flight.parse(bytes.fromhex(h["initiator"]["flight"]), TAG_INITIATOR, INITIATOR_HELLO_LEN, INITIATOR_FLIGHT_LEN)
    assert len(bytes.fromhex(h["initiator"]["flight"])) == 8568
    assert init.verify()
    assert init.node_id == h["initiator"]["node_id"]

    resp = Flight.parse(bytes.fromhex(h["responder"]["flight"]), TAG_RESPONDER, RESPONDER_HELLO_LEN, RESPONDER_FLIGHT_LEN)
    assert len(bytes.fromhex(h["responder"]["flight"])) == 8472
    assert resp.verify()
    assert resp.node_id == h["responder"]["node_id"]


def test_a_tampered_responder_flight_fails_verification(crypto_vectors):
    h = crypto_vectors["handshake"]
    flight = Flight.parse(
        bytes.fromhex(h["tampered_responder_flight"]), TAG_RESPONDER, RESPONDER_HELLO_LEN, RESPONDER_FLIGHT_LEN
    )
    assert not flight.verify()
