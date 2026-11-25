/**
 * Ghost keys: blind issuance, certificates, the files, and a relay's admission of a registration.
 *
 * Mirrors `python/tests/test_ghostkey.py`. The Rust reference writes `vectors/ghost.json`; these tests check that a
 * certificate and a registration it produced verify here, byte for byte.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { bytesToHex, hexToBytes } from "../src/bytes.js";
import { BlindState, GhostCertificate, GhostKey, GhostKeyError, Issuer, IssuerPublic, admitGhost, binding } from "../src/ghostkey.js";
import { Tag, decodeRegisterGhost, encodeRegisterGhost } from "../src/relay.js";
import { loadVectors } from "./helpers.js";

let shared: Issuer | undefined;
/** One 2048-bit issuer for the tests that need a trusted key (generating one is the slow part). */
function issuer(): Issuer {
  shared ??= Issuer.generate("test relay", "supporter", 2048);
  return shared;
}

function throwsGhost(fn: () => unknown, pattern?: RegExp): void {
  assert.throws(fn, (error: unknown) => error instanceof GhostKeyError && (pattern === undefined || pattern.test(error.message)));
}

test("a ghost key issued by blind signature verifies", { timeout: 60_000 }, () => {
  const iss = issuer();
  const me = GhostKey.generate();
  const { blinded, state } = me.blindRequest(iss.info);
  const cert = me.finish(iss.info, state, iss.signBlinded(blinded));
  cert.verify(iss.info);
  const sig = me.sign(new TextEncoder().encode("hello relay"));
  cert.verifySigned(iss.info, new TextEncoder().encode("hello relay"), sig);
  throwsGhost(() => cert.verifySigned(iss.info, new TextEncoder().encode("other message"), sig));
  assert.deepEqual(GhostCertificate.fromText(cert.toText()), cert);
});

test("the issuer never sees the key", { timeout: 60_000 }, () => {
  const iss = issuer();
  const me = GhostKey.generate();
  const first = me.blindRequest(iss.info).blinded;
  const second = me.blindRequest(iss.info).blinded;
  assert.notEqual(bytesToHex(first), bytesToHex(second), "every request is blinded afresh");
  assert.equal(bytesToHex(first).includes(bytesToHex(me.public())), false, "the key is not visible in the request");
});

test("forged or mismatched certificates fail", { timeout: 120_000 }, () => {
  const iss = issuer();
  const other = Issuer.generate("someone else", "supporter", 2048);
  const me = GhostKey.generate();
  const { blinded, state } = me.blindRequest(iss.info);
  const cert = me.finish(iss.info, state, iss.signBlinded(blinded));

  throwsGhost(() => cert.verify(other.info));
  const swapped = new GhostCertificate(cert.issuerId, cert.tier, GhostKey.generate().public(), cert.prefix, cert.signature);
  throwsGhost(() => swapped.verify(iss.info));
  const retiered = new GhostCertificate(cert.issuerId, "gold", cert.ghostPublic, cert.prefix, cert.signature);
  throwsGhost(() => retiered.verify(iss.info));

  const next = me.blindRequest(iss.info);
  let wrong: Uint8Array | undefined;
  try {
    wrong = other.signBlinded(next.blinded);
  } catch (error) {
    if (!(error instanceof GhostKeyError)) {
      throw error;
    }
    wrong = undefined; // the value is larger than the other key's modulus: nothing to unblind
  }
  if (wrong !== undefined) {
    throwsGhost(() => me.finish(iss.info, next.state, wrong as Uint8Array));
  }
  throwsGhost(() => iss.signBlinded(Uint8Array.of(1, 2, 3)));
});

test("the files round trip", { timeout: 60_000 }, () => {
  const iss = issuer();
  const again = Issuer.fromSecretText(iss.toSecretText());
  assert.deepEqual(again.info, iss.info);
  assert.deepEqual(IssuerPublic.fromText(iss.info.toText()), iss.info);
  const me = GhostKey.generate();
  const { blinded, state } = me.blindRequest(iss.info);
  const restored = BlindState.fromText(state.toText(me));
  assert.equal(bytesToHex(restored.key.public()), bytesToHex(me.public()));
  const cert = restored.key.finish(iss.info, restored.state, again.signBlinded(blinded));
  cert.verify(iss.info);
});

test("the issuer key size is bounded", () => {
  throwsGhost(() => Issuer.generate("x", "t", 1024), /2048 to 4096/);
});

test("a certificate from the reference verifies", () => {
  const v = loadVectors("ghost.json");
  const iss = IssuerPublic.fromText(v.issuer.public_text);
  assert.equal(iss.id(), v.issuer.id);
  assert.equal(bytesToHex(iss.spki), v.issuer.spki);

  const cert = GhostCertificate.fromText(v.certificate.text);
  cert.verify(iss);
  assert.equal(bytesToHex(cert.encodeBincode()), v.certificate.bincode, "the bincode is the reference's, byte for byte");
  assert.deepEqual(GhostCertificate.decodeBincode(hexToBytes(v.certificate.bincode)), cert);
  assert.equal(bytesToHex(cert.ghostPublic), v.certificate.ghost_public);
});

test("the relay admits a registration the reference signed", () => {
  const v = loadVectors("ghost.json");
  const reg = v.registration;
  const iss = IssuerPublic.fromText(v.issuer.public_text);
  const token = hexToBytes(reg.session_token);

  const ghost = GhostKey.fromSecret(hexToBytes(v.ghost_secret));
  assert.equal(bytesToHex(ghost.sign(binding(token, reg.seq))), reg.signature, "Ed25519 signs the same bytes");
  assert.equal(bytesToHex(binding(token, reg.seq)), reg.binding);

  const admitted = admitGhost(
    { issuers: [iss] },
    token,
    reg.seq,
    hexToBytes(v.certificate.bincode),
    hexToBytes(reg.signature),
  );
  assert.equal(bytesToHex(admitted), v.certificate.ghost_public);
});

test("the relay refuses a registration for another session", () => {
  const v = loadVectors("ghost.json");
  const reg = v.registration;
  const policy = { issuers: [IssuerPublic.fromText(v.issuer.public_text)] };
  throwsGhost(
    () =>
      admitGhost(
        policy,
        hexToBytes(reg.session_token),
        reg.seq + 1,
        hexToBytes(v.certificate.bincode),
        hexToBytes(reg.signature),
      ),
    /signature/,
  );
});

test("the relay refuses a certificate from an issuer it does not trust", { timeout: 60_000 }, () => {
  const v = loadVectors("ghost.json");
  const reg = v.registration;
  const token = hexToBytes(reg.session_token);
  const cert = hexToBytes(v.certificate.bincode);
  const signature = hexToBytes(reg.signature);
  throwsGhost(() => admitGhost({ issuers: [] }, token, reg.seq, cert, signature), /trusts no ghost key issuer/);
  throwsGhost(() => admitGhost({ issuers: [issuer().info] }, token, reg.seq, cert, signature), /not trusted here/);
});

test("the registration message is the reference bytes", () => {
  const v = loadVectors("ghost.json");
  const reg = v.registration;
  const cert = hexToBytes(v.certificate.bincode);
  const signature = hexToBytes(reg.signature);
  const token = hexToBytes(reg.session_token);

  const wire = encodeRegisterGhost(token, BigInt(reg.pow_nonce), reg.seq, cert, signature);
  assert.equal(wire[0], Tag.REGISTER_GHOST);
  assert.equal(bytesToHex(wire.subarray(1)), reg.body, "the registration body is the reference's, byte for byte");

  const decoded = decodeRegisterGhost(hexToBytes(reg.body));
  assert.equal(bytesToHex(decoded.sessionToken), reg.session_token);
  assert.equal(decoded.powNonce, BigInt(reg.pow_nonce));
  assert.equal(decoded.seq, reg.seq);
  assert.equal(bytesToHex(decoded.certificate), v.certificate.bincode);
  assert.equal(bytesToHex(decoded.signature), reg.signature);
});
