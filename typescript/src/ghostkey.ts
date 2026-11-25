/**
 * Ghost keys: anonymous, verifiable identities (`crates/transferd-crypto/src/ghostkey.rs`).
 *
 * An issuer vouches that a person passed some gate without learning which key it vouched for. The person makes an
 * Ed25519 key, blinds it (RFC 9474), the issuer signs the blinded value, and the person unblinds the answer into a
 * certificate that anyone can check with the issuer's public key. A relay that trusts an issuer admits a registration
 * that carries such a certificate (`admitGhost`), and learns nothing about who the person is.
 *
 * Construction: RSABSSA-SHA384-PSS-Randomized. The signed message is a 32-byte random prefix, then
 * `"transferd-ghostkey-v1" || len(tier) || tier || ghost public key`, under EMSA-PSS with SHA-384, MGF1-SHA-384 and a
 * 48-byte salt. A certificate is therefore an ordinary RSASSA-PSS signature.
 *
 * Certificates and issuer keys travel as bincode in hex, as the reference writes them. Issuing uses plain modular
 * exponentiation on `bigint`: unlike the Rust reference it is not blinded against timing, so issue certificates on a
 * machine you trust.
 */
import { type KeyObject, constants, createHash, createPrivateKey, createPublicKey, generateKeyPairSync, verify as cryptoVerify } from "node:crypto";
import { Reader, Writer } from "./bincode.js";
import { bytesToHex, concatBytes, hexToBytes, u32Bytes, utf8 } from "./bytes.js";
import { blake3Hash, ed25519Public, ed25519Sign, ed25519Verify, randomBytes } from "./crypto.js";
import { TransferdError } from "./errors.js";

const DOMAIN = utf8("transferd-ghostkey-v1");
/** The domain of what a ghost key signs to register a session (`relayd/src/ghost.rs`). */
const BINDING_DOMAIN = utf8("transferd-relay-ghost-v1");
const SALT_LEN = 48;
const PREFIX_LEN = 32;
const HASH_LEN = 48;
const SIGNATURE_LEN = 64;

const ISSUER_TEXT = "transferd-ghostissuerpub-v1:";
const ISSUER_SECRET_TEXT = "transferd-ghostissuer-v1:";
const CERTIFICATE_TEXT = "transferd-ghostcert-v1:";
const PENDING_TEXT = "transferd-ghostpending-v1:";

export class GhostKeyError extends TransferdError {}

/** What a ghost key signs to register a session: the domain, the session token and the sequence number. */
export function binding(sessionToken: Uint8Array, seq: number): Uint8Array {
  return concatBytes(BINDING_DOMAIN, sessionToken, u32Bytes(seq >>> 0));
}

function ghostMessage(tier: string, ghostPublic: Uint8Array): Uint8Array {
  const encoded = utf8(tier);
  return concatBytes(DOMAIN, Uint8Array.of(encoded.length), encoded, ghostPublic);
}

// --- big-integer helpers ----------------------------------------------------------------------------

function bigFromBytes(bytes: Uint8Array): bigint {
  let x = 0n;
  for (const b of bytes) {
    x = (x << 8n) | BigInt(b);
  }
  return x;
}

/** `x` as exactly `length` big-endian bytes. Throws when `x` does not fit, as the reference's `i2osp` does. */
function bigToBytes(x: bigint, length: number): Uint8Array {
  if (x >> BigInt(8 * length) !== 0n) {
    throw new GhostKeyError("the message is too long for this issuer key");
  }
  const out = new Uint8Array(length);
  let v = x;
  for (let i = length - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function bitLength(x: bigint): number {
  return x === 0n ? 0 : x.toString(2).length;
}

function byteLength(x: bigint): number {
  return Math.ceil(bitLength(x) / 8);
}

/** A non-negative integer as minimal big-endian bytes, as num-bigint's `to_bytes_be` writes it. */
function minimalBytes(x: bigint): Uint8Array {
  return bigToBytes(x, Math.max(1, byteLength(x)));
}

function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  let result = 1n;
  let b = base % modulus;
  let e = exponent;
  while (e > 0n) {
    if (e & 1n) {
      result = (result * b) % modulus;
    }
    b = (b * b) % modulus;
    e >>= 1n;
  }
  return result;
}

/** The inverse of `a` modulo `m`, or null when there is none. */
function modInverse(a: bigint, m: bigint): bigint | null {
  let oldR = a % m;
  let r = m;
  let oldS = 1n;
  let s = 0n;
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  if (oldR !== 1n) {
    return null;
  }
  return ((oldS % m) + m) % m;
}

/** A uniform integer in [1, n). */
function randomBelow(n: bigint): bigint {
  const bits = bitLength(n);
  const k = byteLength(n);
  const excess = 8 * k - bits;
  for (;;) {
    const bytes = randomBytes(k);
    bytes[0] &= 0xff >> excess;
    const r = bigFromBytes(bytes);
    if (r >= 1n && r < n) {
      return r;
    }
  }
}

// --- RFC 9474 pieces ---------------------------------------------------------------------------------

function sha384(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha384").update(bytes).digest());
}

function mgf1(seed: Uint8Array, length: number): Uint8Array {
  const parts: Uint8Array[] = [];
  let total = 0;
  for (let counter = 0; total < length; counter++) {
    const part = sha384(concatBytes(seed, u32Bytes(counter, false)));
    parts.push(part);
    total += part.length;
  }
  return concatBytes(...parts).subarray(0, length);
}

/** EMSA-PSS-ENCODE (RFC 8017 section 9.1.1) with SHA-384, MGF1-SHA-384 and a 48-byte salt. */
function emsaPssEncode(msg: Uint8Array, emBits: number): Uint8Array {
  const emLen = Math.ceil(emBits / 8);
  if (emLen < HASH_LEN + SALT_LEN + 2) {
    throw new GhostKeyError("the message is too long for this issuer key");
  }
  const mHash = sha384(msg);
  const salt = randomBytes(SALT_LEN);
  const h = sha384(concatBytes(new Uint8Array(8), mHash, salt));
  const psLen = emLen - SALT_LEN - HASH_LEN - 2;
  const db = concatBytes(new Uint8Array(psLen), Uint8Array.of(0x01), salt);
  const mask = mgf1(h, emLen - HASH_LEN - 1);
  for (let i = 0; i < db.length; i++) {
    db[i] ^= mask[i] ?? 0;
  }
  db[0] &= 0xff >> (8 * emLen - emBits);
  return concatBytes(db, h, Uint8Array.of(0xbc));
}

// --- RSA through node:crypto -------------------------------------------------------------------------

function rsaParts(key: KeyObject): { n: bigint; e: bigint; d: bigint | null } {
  const jwk = key.export({ format: "jwk" });
  if (jwk.n === undefined || jwk.e === undefined) {
    throw new GhostKeyError("encoding: not an RSA key");
  }
  const fromB64 = (s: string): bigint => bigFromBytes(new Uint8Array(Buffer.from(s, "base64url")));
  return { n: fromB64(jwk.n), e: fromB64(jwk.e), d: jwk.d === undefined ? null : fromB64(jwk.d) };
}

// --- bincode helpers ----------------------------------------------------------------------------------

function stripPrefix(text: string, prefix: string, message: string): string {
  const body = text.trim();
  if (!body.startsWith(prefix)) {
    throw new GhostKeyError(message);
  }
  return body.slice(prefix.length);
}

function decode<T>(data: Uint8Array, read: (r: Reader) => T): T {
  try {
    return read(new Reader(data));
  } catch (error) {
    if (error instanceof TransferdError) {
      throw new GhostKeyError(`encoding: ${error.message}`);
    }
    throw error;
  }
}

function decodeHex<T>(hex: string, read: (r: Reader) => T): T {
  let data: Uint8Array;
  try {
    data = hexToBytes(hex);
  } catch (error) {
    throw new GhostKeyError(`encoding: ${error instanceof Error ? error.message : String(error)}`);
  }
  return decode(data, read);
}

// --- the issuer ----------------------------------------------------------------------------------------

/** What everyone needs to check certificates: the RSA public key (SPKI DER), its tier and its name. */
export class IssuerPublic {
  constructor(
    readonly name: string,
    readonly tier: string,
    readonly spki: Uint8Array,
  ) {}

  rsaKey(): KeyObject {
    try {
      return createPublicKey({ key: Buffer.from(this.spki), format: "der", type: "spki" });
    } catch (error) {
      throw new GhostKeyError(`encoding: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /** blake3 of the SPKI, first 8 bytes in hex: how certificates name their issuer. */
  id(): string {
    return bytesToHex(blake3Hash(this.spki).subarray(0, 8));
  }

  toText(): string {
    const w = new Writer();
    w.string(this.name);
    w.string(this.tier);
    w.bytes(this.spki);
    return ISSUER_TEXT + bytesToHex(w.getValue());
  }

  static fromText(text: string): IssuerPublic {
    const body = stripPrefix(text, ISSUER_TEXT, "not an issuer public key");
    return decodeHex(body, (r) => new IssuerPublic(r.string(), r.string(), r.bytes()));
  }
}

/** An issuer key for one tier. Keep the private part offline or on the relay; publish `public`. */
export class Issuer {
  constructor(
    private readonly key: KeyObject,
    readonly info: IssuerPublic,
  ) {}

  static generate(name: string, tier: string, bits: number): Issuer {
    if (!Number.isInteger(bits) || bits < 2048 || bits > 4096) {
      throw new GhostKeyError(`the issuer key must be 2048 to 4096 bits (got ${bits})`);
    }
    if (utf8(tier).length > 64) {
      throw new GhostKeyError("a tier is at most 64 bytes");
    }
    const { privateKey } = generateKeyPairSync("rsa", { modulusLength: bits, publicExponent: 65537 });
    return Issuer.fromPrivate(name, tier, privateKey);
  }

  static fromPrivate(name: string, tier: string, key: KeyObject): Issuer {
    const spki = createPublicKey(key).export({ format: "der", type: "spki" });
    return new Issuer(key, new IssuerPublic(name, tier, new Uint8Array(spki)));
  }

  /** The issuer's secret file: `transferd-ghostissuer-v1:<name>`, the tier, and the key as hex PKCS#8 DER. */
  toSecretText(): string {
    const der = this.key.export({ format: "der", type: "pkcs8" });
    return `${ISSUER_SECRET_TEXT}${this.info.name}\n${this.info.tier}\n${Buffer.from(der).toString("hex")}\n`;
  }

  static fromSecretText(text: string): Issuer {
    const body = stripPrefix(text, ISSUER_SECRET_TEXT, "not an issuer secret");
    const [name = "", tier = "", der = ""] = body.trim().split(/\r?\n/);
    if (name === "" || tier === "" || der === "") {
      throw new GhostKeyError("an issuer secret has a name, a tier and a key");
    }
    let key: KeyObject;
    try {
      key = createPrivateKey({ key: Buffer.from(hexToBytes(der.trim())), format: "der", type: "pkcs8" });
    } catch (error) {
      throw new GhostKeyError(`encoding: ${error instanceof Error ? error.message : String(error)}`);
    }
    return Issuer.fromPrivate(name, tier, key);
  }

  /** BlindSign (RFC 9474 section 4.3): the RSA private operation on a value the issuer cannot read. */
  signBlinded(blinded: Uint8Array): Uint8Array {
    const { n, e, d } = rsaParts(this.key);
    if (d === null) {
      throw new GhostKeyError("this issuer key is public only");
    }
    const k = byteLength(n);
    if (blinded.length !== k) {
      throw new GhostKeyError(`a blinded value has the wrong length (expected ${k} bytes, got ${blinded.length})`);
    }
    const m = bigFromBytes(blinded);
    if (m >= n) {
      throw new GhostKeyError("the message is too long for this issuer key");
    }
    const s = modPow(m, d, n);
    // the check RFC 9474 asks for: s^e == m, so a fault never leaks the key
    if (modPow(s, e, n) !== m) {
      throw new GhostKeyError("the issuer's signature does not check out (a wrong issuer key, or tampering)");
    }
    return bigToBytes(s, k);
  }
}

// --- the person ----------------------------------------------------------------------------------------

/** Between asking and finishing: the blinding inverse and the randomised message. Never sent anywhere. */
export class BlindState {
  constructor(
    readonly inv: bigint,
    readonly msg: Uint8Array,
    readonly k: number,
  ) {}

  /** The pending request, `transferd-ghostpending-v1:<hex>`. Its secrets stay with the person. */
  toText(key: GhostKey): string {
    const w = new Writer();
    w.bytes(minimalBytes(this.inv));
    w.bytes(this.msg);
    w.u64(this.k);
    w.raw(key.secret());
    return PENDING_TEXT + bytesToHex(w.getValue());
  }

  static fromText(text: string): { state: BlindState; key: GhostKey } {
    const body = stripPrefix(text, PENDING_TEXT, "not a pending ghost key request");
    const [inv, msg, k, secret] = decodeHex(body, (r) => [r.bytes(), r.bytes(), r.u64(), r.raw(32)] as const);
    return { state: new BlindState(bigFromBytes(inv), msg, k), key: GhostKey.fromSecret(secret) };
  }
}

/** The ghost key itself: an Ed25519 key the person keeps; its certificate says an issuer vouched for it. */
export class GhostKey {
  private constructor(private readonly seed: Uint8Array) {}

  static generate(): GhostKey {
    return new GhostKey(randomBytes(32));
  }

  static fromSecret(secret: Uint8Array): GhostKey {
    if (secret.length !== 32) {
      throw new GhostKeyError("a ghost key secret is 32 bytes");
    }
    return new GhostKey(Uint8Array.from(secret));
  }

  secret(): Uint8Array {
    return Uint8Array.from(this.seed);
  }

  public(): Uint8Array {
    return ed25519Public(this.seed);
  }

  sign(message: Uint8Array): Uint8Array {
    return ed25519Sign(this.seed, message);
  }

  /** Blind (RFC 9474 section 4.2, randomised variant): what to send the issuer, and the state to keep. */
  blindRequest(issuer: IssuerPublic): { blinded: Uint8Array; state: BlindState } {
    const { n, e } = rsaParts(issuer.rsaKey());
    const k = byteLength(n);
    const msg = concatBytes(randomBytes(PREFIX_LEN), ghostMessage(issuer.tier, this.public()));
    const m = bigFromBytes(emsaPssEncode(msg, bitLength(n) - 1));
    for (;;) {
      const r = randomBelow(n);
      const inv = modInverse(r, n);
      if (inv === null) {
        continue; // not invertible modulo n: draw again
      }
      const z = (m * modPow(r, e, n)) % n;
      return { blinded: bigToBytes(z, k), state: new BlindState(inv, msg, k) };
    }
  }

  /** Finalize (RFC 9474 section 4.4): unblind the issuer's answer and check it is a valid PSS signature. */
  finish(issuer: IssuerPublic, state: BlindState, blindSig: Uint8Array): GhostCertificate {
    if (blindSig.length !== state.k) {
      throw new GhostKeyError(`a blinded value has the wrong length (expected ${state.k} bytes, got ${blindSig.length})`);
    }
    const { n } = rsaParts(issuer.rsaKey());
    const s = (bigFromBytes(blindSig) * state.inv) % n;
    const cert = new GhostCertificate(
      issuer.id(),
      issuer.tier,
      this.public(),
      state.msg.slice(0, PREFIX_LEN),
      bigToBytes(s, state.k),
    );
    try {
      cert.verify(issuer);
    } catch (error) {
      if (error instanceof GhostKeyError) {
        throw new GhostKeyError("the issuer's signature does not check out (a wrong issuer key, or tampering)");
      }
      throw error;
    }
    return cert;
  }
}

/** A finished certificate: shareable, checkable by anyone with the issuer's public key. */
export class GhostCertificate {
  constructor(
    readonly issuerId: string,
    readonly tier: string,
    readonly ghostPublic: Uint8Array,
    readonly prefix: Uint8Array,
    readonly signature: Uint8Array,
  ) {}

  /** Throws `GhostKeyError` unless this is a key the issuer vouched for, at its tier. */
  verify(issuer: IssuerPublic): void {
    if (this.issuerId !== issuer.id() || this.tier !== issuer.tier) {
      throw new GhostKeyError("the certificate is not valid for this issuer");
    }
    const ok = cryptoVerify(
      "sha384",
      concatBytes(this.prefix, ghostMessage(this.tier, this.ghostPublic)),
      { key: issuer.rsaKey(), padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: SALT_LEN },
      this.signature,
    );
    if (!ok) {
      throw new GhostKeyError("the certificate is not valid for this issuer");
    }
  }

  /** Throws `GhostKeyError` unless the certificate is valid and `signature` is by the ghost key it vouches for. */
  verifySigned(issuer: IssuerPublic, message: Uint8Array, signature: Uint8Array): void {
    this.verify(issuer);
    if (signature.length !== SIGNATURE_LEN || !ed25519Verify(this.ghostPublic, message, signature)) {
      throw new GhostKeyError("the ghost key's signature does not check out");
    }
  }

  /** The certificate as bincode (what a registration carries). */
  encodeBincode(): Uint8Array {
    const w = new Writer();
    w.string(this.issuerId);
    w.string(this.tier);
    w.raw(this.ghostPublic);
    w.raw(this.prefix);
    w.bytes(this.signature);
    return w.getValue();
  }

  static decodeBincode(data: Uint8Array): GhostCertificate {
    return decode(data, readCertificate);
  }

  toText(): string {
    return CERTIFICATE_TEXT + bytesToHex(this.encodeBincode());
  }

  static fromText(text: string): GhostCertificate {
    return decodeHex(stripPrefix(text, CERTIFICATE_TEXT, "not a ghost key certificate"), readCertificate);
  }
}

function readCertificate(r: Reader): GhostCertificate {
  return new GhostCertificate(r.string(), r.string(), r.raw(32), r.raw(PREFIX_LEN), r.bytes());
}

// --- a relay's admission -------------------------------------------------------------------------------

/** A relay's ghost key admission: the issuers it trusts. The rest is the relay's own state. */
export interface GhostPolicy {
  readonly issuers: readonly IssuerPublic[];
  readonly required?: boolean;
  readonly maxSessionsPerKey?: number;
}

/** The ghost key a registration proves (`GhostPolicy::admit`). Throws `GhostKeyError` when it proves none. */
export function admitGhost(
  policy: GhostPolicy,
  sessionToken: Uint8Array,
  seq: number,
  certificate: Uint8Array,
  signature: Uint8Array,
): Uint8Array {
  if (policy.issuers.length === 0) {
    throw new GhostKeyError("this relay trusts no ghost key issuer");
  }
  let cert: GhostCertificate;
  try {
    cert = GhostCertificate.decodeBincode(certificate);
  } catch (error) {
    if (error instanceof GhostKeyError) {
      throw new GhostKeyError("not a ghost key certificate");
    }
    throw error;
  }
  const issuer = policy.issuers.find((i) => i.id() === cert.issuerId);
  if (issuer === undefined) {
    throw new GhostKeyError("the certificate's issuer is not trusted here");
  }
  cert.verifySigned(issuer, binding(sessionToken, seq), signature);
  return cert.ghostPublic;
}
