import assert from "node:assert/strict";
import { test } from "node:test";
import { bytesToHex, hexToBytes, utf8 } from "../src/bytes.js";
import {
  blake3DeriveKey,
  blake3Hash,
  blake3Keyed,
  ed25519Sign,
  ed25519VerifyStrict,
  mlkemDecapsulate,
  mlkemEncapsulate,
  mlkemKeypair,
  ML_DSA_SIGN_CONTEXT,
  ED25519_ORDER,
} from "../src/crypto.js";
import { HYBRID_PK_LEN, HybridIdentity, keyFingerprint, relayTokenFor, verifyHybrid } from "../src/identity.js";
import {
  INITIATOR_FLIGHT_LEN,
  INITIATOR_HELLO_LEN,
  RESPONDER_FLIGHT_LEN,
  RESPONDER_HELLO_LEN,
  TAG_INITIATOR,
  TAG_RESPONDER,
  Flight,
} from "../src/handshake.js";
import { loadVectors } from "./helpers.js";

const crypto = loadVectors("crypto.json");

test("BLAKE3 hash, keyed and derive_key match the reference", () => {
  const h = crypto.blake3.hash;
  assert.equal(bytesToHex(blake3Hash(hexToBytes(h.input))), h.output);
  const k = crypto.blake3.keyed;
  assert.equal(bytesToHex(blake3Keyed(hexToBytes(k.key), hexToBytes(k.input))), k.output);
  const d = crypto.blake3.derive_key;
  assert.equal(bytesToHex(blake3DeriveKey(d.context, hexToBytes(d.input))), d.output);
});

test("ML-KEM-768 keys, encapsulation and decapsulation match FIPS 203 vectors", () => {
  const v = crypto.mlkem768;
  const kp = mlkemKeypair(hexToBytes(v.seed));
  assert.equal(bytesToHex(kp.publicKey), v.encapsulation_key);
  const enc = mlkemEncapsulate(kp.publicKey, hexToBytes(v.m));
  assert.equal(bytesToHex(enc.ciphertext), v.ciphertext);
  assert.equal(bytesToHex(enc.sharedSecret), v.shared_secret);
  assert.equal(bytesToHex(mlkemDecapsulate(kp.secretKey, hexToBytes(v.ciphertext))), v.shared_secret);
});

test("the hybrid identity derives the node id, public key, relay token and fingerprint", () => {
  const v = crypto.identity;
  const identity = new HybridIdentity(hexToBytes(v.seed));
  assert.equal(identity.nodeId, v.node_id);
  assert.equal(bytesToHex(identity.publicKey), v.hybrid_public_key);
  assert.equal(bytesToHex(identity.relayToken()), v.relay_token);
  assert.equal(bytesToHex(keyFingerprint(identity.publicKey)), v.key_fingerprint);
  assert.equal(bytesToHex(relayTokenFor(v.node_id)), v.relay_token);
  assert.equal(identity.publicKey.length, HYBRID_PK_LEN);
});

test("a reference hybrid signature verifies, and a changed message does not", () => {
  const pk = hexToBytes(crypto.identity.hybrid_public_key);
  const { message, signature } = crypto.identity.sign;
  assert.equal(verifyHybrid(pk, hexToBytes(message), hexToBytes(signature)), true);
  assert.equal(verifyHybrid(pk, utf8("tampered"), hexToBytes(signature)), false);
});

test("our hybrid signature verifies under the reference public key", () => {
  const identity = new HybridIdentity(hexToBytes(crypto.identity.seed));
  const message = utf8("made by TypeScript");
  assert.equal(verifyHybrid(identity.publicKey, message, identity.sign(message)), true);
  assert.equal(new TextDecoder().decode(ML_DSA_SIGN_CONTEXT), "TransferDaemon-v1-hybrid-sign");
});

test("Ed25519 signing is deterministic and matches the reference", () => {
  const identity = new HybridIdentity(hexToBytes(crypto.identity.seed));
  const e = crypto.identity.ed25519_sign;
  const message = hexToBytes(e.message);
  assert.equal(bytesToHex(identity.signEd25519(message)), e.signature);
  assert.equal(bytesToHex(ed25519Sign(hexToBytes(crypto.identity.seed).subarray(0, 32), message)), e.signature);
});

test("strict Ed25519 refuses a non-canonical S", () => {
  const identity = new HybridIdentity(hexToBytes(crypto.identity.seed));
  const e = crypto.identity.ed25519_sign;
  const message = hexToBytes(e.message);
  const sig = hexToBytes(e.signature);
  const s = sig.slice(32).reduce((acc, b, i) => acc | (BigInt(b) << BigInt(8 * i)), 0n);
  const forged = new Uint8Array(sig);
  const canonicalPlusL = s + ED25519_ORDER;
  for (let i = 0; i < 32; i++) {
    forged[32 + i] = Number((canonicalPlusL >> BigInt(8 * i)) & 0xffn);
  }
  assert.equal(ed25519VerifyStrict(identity.ed25519PublicKey, message, sig), true);
  assert.equal(ed25519VerifyStrict(identity.ed25519PublicKey, message, forged), false);
});

test("strict Ed25519 refuses a small-order public key", () => {
  assert.equal(ed25519VerifyStrict(new Uint8Array(32), utf8("msg"), new Uint8Array(64)), false);
});

test("reference handshake flights have the specified lengths and verify", () => {
  const h = crypto.handshake;
  const init = Flight.parse(hexToBytes(h.initiator.flight), TAG_INITIATOR, INITIATOR_HELLO_LEN, INITIATOR_FLIGHT_LEN);
  assert.equal(hexToBytes(h.initiator.flight).length, 8568);
  assert.equal(init.verify(), true);
  assert.equal(init.nodeId, h.initiator.node_id);

  const resp = Flight.parse(hexToBytes(h.responder.flight), TAG_RESPONDER, RESPONDER_HELLO_LEN, RESPONDER_FLIGHT_LEN);
  assert.equal(hexToBytes(h.responder.flight).length, 8472);
  assert.equal(resp.verify(), true);
  assert.equal(resp.nodeId, h.responder.node_id);
});

test("a tampered responder flight fails verification", () => {
  const flight = Flight.parse(
    hexToBytes(crypto.handshake.tampered_responder_flight),
    TAG_RESPONDER,
    RESPONDER_HELLO_LEN,
    RESPONDER_FLIGHT_LEN,
  );
  assert.equal(flight.verify(), false);
});
