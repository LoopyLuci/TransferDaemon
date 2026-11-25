/**
 * The double ratchet: envelopes from the Rust reference, and the behaviour of the reference's unit tests.
 *
 * Mirrors `python/tests/test_ratchet.py` and `crates/transferd-crypto/src/ratchet.rs`. The reference writes
 * `vectors/ratchet.json`: messages a sender made for a fixed root with no reply, so every key comes off the send chain.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { bytesToHex, concatBytes, hexToBytes } from "../src/bytes.js";
import { blake3DeriveKey } from "../src/crypto.js";
import { RatchetError, RATCHET_INTERVAL, DoubleRatchet, RatchetChain, type RatchetMessage, mixRoot } from "../src/ratchet.js";
import { loadVectors } from "./helpers.js";

const ROOT = new Uint8Array(32).fill(0x42);
const CTX_INIT_SEND = "TransferDaemon-v3-ratchet-init-send";

function bytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

function exchangeInitialKeys(): { alice: DoubleRatchet; bob: DoubleRatchet } {
  const alice = new DoubleRatchet(ROOT, true);
  const bob = new DoubleRatchet(ROOT, false);
  bob.decrypt(alice.encrypt(bytes("init")));
  alice.decrypt(bob.encrypt(bytes("init-reply")));
  return { alice, bob };
}

function throwsRatchet(fn: () => unknown): void {
  assert.throws(fn, RatchetError);
}

test("a message from the reference opens under the same root", () => {
  const v = loadVectors("ratchet.json");
  const responder = new DoubleRatchet(hexToBytes(v.root), false);
  v.messages.forEach((entry: Record<string, string | number | null>, i: number) => {
    const msg: RatchetMessage = {
      chainIndex: entry.chain_index as number,
      nonce: hexToBytes(entry.nonce as string),
      tag: hexToBytes(entry.tag as string),
      ciphertext: hexToBytes(entry.ciphertext as string),
      ratchetPk: entry.ratchet_pk === null ? undefined : hexToBytes(entry.ratchet_pk as string),
      kemEk: entry.kem_ek === null ? undefined : hexToBytes(entry.kem_ek as string),
    };
    assert.equal(msg.chainIndex, i, "the reference numbers its chain from zero");
    assert.equal(bytesToHex(responder.decrypt(msg)), entry.plaintext, `message ${i}`);
  });
});

test("the first message publishes the keys and later ones do not", () => {
  const entries = loadVectors("ratchet.json").messages;
  assert.ok(entries[0].ratchet_pk !== null && entries[0].kem_ek !== null);
  assert.ok(entries.slice(1).every((e: Record<string, unknown>) => e.ratchet_pk === null && e.kem_ek === null));
});

test("chains advance independently", () => {
  const chain = new RatchetChain(ROOT, CTX_INIT_SEND);
  const [k1, i1] = chain.step();
  const [k2, i2] = chain.step();
  assert.deepEqual([i1, i2], [0, 1]);
  assert.notEqual(bytesToHex(k1), bytesToHex(k2));
});

test("a single message carries the initial key", () => {
  const alice = new DoubleRatchet(ROOT, true);
  const bob = new DoubleRatchet(ROOT, false);
  const msg = alice.encrypt(bytes("hello ratchet"));
  assert.ok(msg.ratchetPk !== undefined, "the first message publishes the ratchet key");
  assert.equal(new TextDecoder().decode(bob.decrypt(msg)), "hello ratchet");
  const reply = bob.encrypt(bytes("hello back"));
  assert.ok(reply.ratchetPk !== undefined);
  assert.equal(new TextDecoder().decode(alice.decrypt(reply)), "hello back");
});

test("a multi-message round trip without DH steps", () => {
  const { alice, bob } = exchangeInitialKeys();
  for (let i = 0; i < RATCHET_INTERVAL - 1; i++) {
    const payload = bytes(`message-${i}`);
    const msg = alice.encrypt(payload);
    assert.equal(msg.ratchetPk, undefined);
    assert.deepEqual(bob.decrypt(msg), payload);
  }
});

test("a DH ratchet resets and reciprocates both ways", () => {
  const alice = new DoubleRatchet(ROOT, true);
  const bob = new DoubleRatchet(ROOT, false);
  // A DH step resets the send chain, so its message has chain index 0. The only other messages that carry a ratchet key
  // are the first, so any later one with a key is a DH step.
  let sawDhStep = false;
  let sent = 0;
  for (let n = 0; n < 4; n++) {
    for (let i = 0; i < RATCHET_INTERVAL; i++) {
      const payload = bytes(`a-${n}-${i}`);
      const msg = alice.encrypt(payload);
      if (msg.ratchetPk !== undefined && sent > 0) {
        sawDhStep = true;
      }
      sent += 1;
      assert.deepEqual(bob.decrypt(msg), payload, `a-${n}-${i} must survive`);
    }
    const reply = bytes(`b-${n}`);
    assert.deepEqual(alice.decrypt(bob.encrypt(reply)), reply);
  }
  assert.ok(sawDhStep, "a real DH ratchet step must have occurred");
});

test("a tampered message is rejected", () => {
  const { alice, bob } = exchangeInitialKeys();
  const msg = alice.encrypt(bytes("secret"));
  msg.ciphertext = Uint8Array.from(msg.ciphertext, (b, i) => (i === 0 ? b ^ 0xff : b));
  throwsRatchet(() => bob.decrypt(msg));
});

test("a compromised root cannot decrypt after a DH ratchet", () => {
  const { alice, bob } = exchangeInitialKeys();
  let post: RatchetMessage | undefined;
  for (let i = 0; i < RATCHET_INTERVAL; i++) {
    const msg = alice.encrypt(bytes("pre-ratchet"));
    if (msg.ratchetPk !== undefined) {
      post = msg;
    }
    assert.equal(new TextDecoder().decode(bob.decrypt(msg)), "pre-ratchet");
  }
  assert.ok(post !== undefined, "a DH step must have occurred");
  throwsRatchet(() => new DoubleRatchet(ROOT, false).decrypt(post as RatchetMessage));
});

test("the roles' chains line up", () => {
  const initiator = new DoubleRatchet(ROOT, true);
  const responder = new DoubleRatchet(ROOT, false);
  assert.equal(new TextDecoder().decode(responder.decrypt(initiator.encrypt(bytes("from initiator")))), "from initiator");
  assert.equal(new TextDecoder().decode(initiator.decrypt(responder.encrypt(bytes("from responder")))), "from responder");
});

test("the first messages publish the ML-KEM keys", () => {
  const alice = new DoubleRatchet(ROOT, true);
  const bob = new DoubleRatchet(ROOT, false);
  const m1 = alice.encrypt(bytes("a"));
  assert.ok(m1.kemEk !== undefined && m1.kemEk.length === 1184);
  bob.decrypt(m1);
  const m2 = bob.encrypt(bytes("b"));
  assert.ok(m2.kemEk !== undefined);
  alice.decrypt(m2);
});

test("a DH step carries an ML-KEM ciphertext and decrypts", () => {
  const { alice, bob } = exchangeInitialKeys();
  let sawKemCt = false;
  for (let i = 0; i < RATCHET_INTERVAL + 2; i++) {
    const m = alice.encrypt(bytes(`a${i}`));
    if (m.kemCt !== undefined) {
      assert.ok(m.kemEk !== undefined, "a DH step publishes a fresh ML-KEM encapsulation key");
      assert.equal(m.kemCt.length, 1088);
      sawKemCt = true;
    }
    assert.equal(new TextDecoder().decode(bob.decrypt(m)), `a${i}`);
  }
  assert.ok(sawKemCt, "a DH ratchet step must carry an ML-KEM ciphertext");
});

test("the KEM mix blocks a classical-only attacker", () => {
  const dhShared = new Uint8Array(32).fill(6);
  const real = mixRoot(ROOT, dhShared, new Uint8Array(32).fill(9));
  const classical = mixRoot(ROOT, dhShared);
  assert.notEqual(bytesToHex(real), bytesToHex(classical));
  const realKey = new RatchetChain(real, CTX_INIT_SEND).step()[0];
  const classicalKey = new RatchetChain(classical, CTX_INIT_SEND).step()[0];
  assert.notEqual(bytesToHex(realKey), bytesToHex(classicalKey), "classical-only keys differ from the KEM-mixed keys");
});

test("the root mix is the reference KDF", () => {
  const dhShared = new Uint8Array(32).fill(1);
  const kemShared = new Uint8Array(32).fill(2);
  const expected = blake3DeriveKey(
    "TransferDaemon-v3-ratchet-root-mix",
    concatBytes(ROOT, blake3DeriveKey("TransferDaemon-v3-ratchet-dh", dhShared), blake3DeriveKey("TransferDaemon-v3-ratchet-kem", kemShared)),
  );
  assert.equal(bytesToHex(mixRoot(ROOT, dhShared, kemShared)), bytesToHex(expected));
  assert.notEqual(bytesToHex(mixRoot(ROOT, dhShared)), bytesToHex(expected), "without the KEM output the root differs");
});
