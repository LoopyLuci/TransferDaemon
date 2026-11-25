"""The double ratchet: envelopes from the Rust reference, and the behaviour of the reference's unit tests.

Mirrors `crates/transferd-crypto/src/ratchet.rs`. The reference writes `vectors/ratchet.json`: messages a sender made for
a fixed root with no reply, so every key comes off the send chain; those must open here under the same root.
"""

import pytest

from transferd.crypto import blake3_derive_key
from transferd.ratchet import RATCHET_INTERVAL, DoubleRatchet, RatchetChain, RatchetError, RatchetMessage, mix_root

ROOT = bytes([0x42]) * 32


def _exchange_initial_keys():
    alice = DoubleRatchet(ROOT, True)
    bob = DoubleRatchet(ROOT, False)
    bob.decrypt(alice.encrypt(b"init"))
    alice.decrypt(bob.encrypt(b"init-reply"))
    return alice, bob


def test_a_message_from_the_reference_opens_under_the_same_root(ratchet_vectors):
    responder = DoubleRatchet(bytes.fromhex(ratchet_vectors["root"]), False)
    for i, entry in enumerate(ratchet_vectors["messages"]):
        msg = RatchetMessage(
            chain_index=entry["chain_index"],
            nonce=bytes.fromhex(entry["nonce"]),
            tag=bytes.fromhex(entry["tag"]),
            ciphertext=bytes.fromhex(entry["ciphertext"]),
            ratchet_pk=bytes.fromhex(entry["ratchet_pk"]) if entry["ratchet_pk"] else None,
            kem_ek=bytes.fromhex(entry["kem_ek"]) if entry["kem_ek"] else None,
        )
        assert msg.chain_index == i, "the reference numbers its chain from zero"
        assert responder.decrypt(msg) == bytes.fromhex(entry["plaintext"]), f"message {i}"


def test_the_first_message_publishes_the_keys_and_later_ones_do_not(ratchet_vectors):
    entries = ratchet_vectors["messages"]
    assert entries[0]["ratchet_pk"] is not None and entries[0]["kem_ek"] is not None
    assert all(e["ratchet_pk"] is None and e["kem_ek"] is None for e in entries[1:])


def test_chains_advance_independently():
    chain = RatchetChain(ROOT, "TransferDaemon-v3-ratchet-init-send")
    k1, i1 = chain.step()
    k2, i2 = chain.step()
    assert (i1, i2) == (0, 1)
    assert k1 != k2


def test_a_single_message_carries_the_initial_key():
    alice = DoubleRatchet(ROOT, True)
    bob = DoubleRatchet(ROOT, False)
    msg = alice.encrypt(b"hello ratchet")
    assert msg.ratchet_pk is not None, "the first message publishes the ratchet key"
    assert bob.decrypt(msg) == b"hello ratchet"
    reply = bob.encrypt(b"hello back")
    assert reply.ratchet_pk is not None
    assert alice.decrypt(reply) == b"hello back"


def test_a_multi_message_round_trip_without_dh_steps():
    alice, bob = _exchange_initial_keys()
    for i in range(RATCHET_INTERVAL - 1):
        payload = f"message-{i}".encode()
        msg = alice.encrypt(payload)
        assert msg.ratchet_pk is None
        assert bob.decrypt(msg) == payload


def test_a_dh_ratchet_resets_and_reciprocates_both_ways():
    alice = DoubleRatchet(ROOT, True)
    bob = DoubleRatchet(ROOT, False)
    saw_dh_step = False
    for n in range(4):
        for i in range(RATCHET_INTERVAL):
            payload = f"a-{n}-{i}".encode()
            msg = alice.encrypt(payload)
            if msg.ratchet_pk is not None and alice._peer_dh_pk is not None:
                saw_dh_step = True
            assert bob.decrypt(msg) == payload, f"a-{n}-{i} must survive"
        reply = f"b-{n}".encode()
        assert alice.decrypt(bob.encrypt(reply)) == reply
    assert saw_dh_step, "a real DH ratchet step must have occurred"


def test_a_tampered_message_is_rejected():
    alice, bob = _exchange_initial_keys()
    msg = alice.encrypt(b"secret")
    msg.ciphertext = bytes([msg.ciphertext[0] ^ 0xFF]) + msg.ciphertext[1:]
    with pytest.raises(RatchetError):
        bob.decrypt(msg)


def test_a_compromised_root_cannot_decrypt_after_a_dh_ratchet():
    alice, bob = _exchange_initial_keys()
    post = None
    for _ in range(RATCHET_INTERVAL):
        msg = alice.encrypt(b"pre-ratchet")
        if msg.ratchet_pk is not None:
            post = msg
        assert bob.decrypt(msg) == b"pre-ratchet"
    assert post is not None, "a DH step must have occurred"
    attacker = DoubleRatchet(ROOT, False)
    with pytest.raises(RatchetError):
        attacker.decrypt(post)


def test_the_roles_chains_line_up():
    initiator = DoubleRatchet(ROOT, True)
    responder = DoubleRatchet(ROOT, False)
    assert responder.decrypt(initiator.encrypt(b"from initiator")) == b"from initiator"
    assert initiator.decrypt(responder.encrypt(b"from responder")) == b"from responder"


def test_the_first_messages_publish_the_mlkem_keys():
    alice = DoubleRatchet(ROOT, True)
    bob = DoubleRatchet(ROOT, False)
    m1 = alice.encrypt(b"a")
    assert m1.kem_ek is not None and len(m1.kem_ek) == 1184
    bob.decrypt(m1)
    m2 = bob.encrypt(b"b")
    assert m2.kem_ek is not None
    alice.decrypt(m2)


def test_a_dh_step_carries_a_kem_ciphertext_and_decrypts():
    alice, bob = _exchange_initial_keys()
    saw_kem_ct = False
    for i in range(RATCHET_INTERVAL + 2):
        m = alice.encrypt(f"a{i}".encode())
        if m.kem_ct is not None:
            assert m.kem_ek is not None, "a DH step publishes a fresh ML-KEM encapsulation key"
            assert len(m.kem_ct) == 1088
            saw_kem_ct = True
        assert bob.decrypt(m) == f"a{i}".encode()
    assert saw_kem_ct, "a DH ratchet step must carry an ML-KEM ciphertext"


def test_the_kem_mix_blocks_a_classical_only_attacker():
    """An attacker holding every classical secret cannot reproduce a root that also mixes an ML-KEM secret."""
    dh_shared = bytes([6]) * 32
    real = DoubleRatchet(ROOT, True)
    classical = DoubleRatchet(ROOT, True)
    real._derive_new_root(dh_shared, bytes([9]) * 32)
    classical._derive_new_root(dh_shared, None)
    assert real._root != classical._root
    send_context = "TransferDaemon-v3-ratchet-init-send"
    real_key, _ = RatchetChain(real._root, send_context).step()
    classical_key, _ = RatchetChain(classical._root, send_context).step()
    assert real_key != classical_key


def test_the_root_mix_is_the_reference_kdf():
    """The root mix is `blake3_derive_key(ROOT_MIX, root || blake3_derive_key(DH, dh) || blake3_derive_key(KEM, kem))`."""
    dh_shared, kem_shared = bytes([1]) * 32, bytes([2]) * 32
    expected = blake3_derive_key(
        "TransferDaemon-v3-ratchet-root-mix",
        ROOT + blake3_derive_key("TransferDaemon-v3-ratchet-dh", dh_shared) + blake3_derive_key("TransferDaemon-v3-ratchet-kem", kem_shared),
    )
    assert mix_root(ROOT, dh_shared, kem_shared) == expected
    assert mix_root(ROOT, dh_shared) != expected, "without the KEM output the root differs"
