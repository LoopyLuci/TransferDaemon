import { bytesToHex, concatBytes, hexToBytes, u16Bytes, u32Bytes, u64Bytes, utf8, utf8Decode } from "./bytes.js";
import { blake3Hash, ed25519VerifyStrict, randomBytes } from "./crypto.js";
import { InviteError, TransferdError } from "./errors.js";
import { HybridIdentity, checkNodeId, keyFingerprint } from "./identity.js";

/** Invites (§6): `tdov2:` followed by unpadded base64url of a signed JSON object. */
export const PREFIX = "tdov2:";
export const MAX_INVITE_BYTES = 4 * 1024;
export const INVITE_CONTEXT = utf8("TransferDaemon-overlay-invite-v2");
export const DEFAULT_TTL_S = 900;
export const MIN_TTL_S = 30;
export const MAX_TTL_S = 86_400;

const BASE64URL = /^[A-Za-z0-9_-]*$/;

function field(data: Uint8Array): Uint8Array {
  return concatBytes(u32Bytes(data.length), data);
}

export interface InviteFields {
  version: number;
  nodeId: string;
  name: string;
  keyFingerprint: string;
  relays: string[];
  direct: string[];
  expiresAt: number;
  nonce: string;
}

/** The 32-byte digest an invite's signature covers. */
export function inviteBinding(f: InviteFields): Uint8Array {
  return blake3Hash(
    concatBytes(
      INVITE_CONTEXT,
      u16Bytes(f.version),
      field(utf8(f.nodeId)),
      field(utf8(f.name)),
      field(utf8(f.keyFingerprint)),
      u32Bytes(f.relays.length),
      ...f.relays.map((r) => field(utf8(r))),
      u32Bytes(f.direct.length),
      ...f.direct.map((d) => field(utf8(d))),
      u64Bytes(BigInt(f.expiresAt)),
      field(utf8(f.nonce)),
    ),
  );
}

export function base64urlEncode(data: Uint8Array): string {
  return Buffer.from(data).toString("base64url");
}

export function base64urlDecode(text: string): Uint8Array {
  if (!BASE64URL.test(text) || text.length % 4 === 1) {
    throw new InviteError("invite is not valid base64url");
  }
  return new Uint8Array(Buffer.from(text, "base64url"));
}

export interface MadeInvite {
  text: string;
  nonce: Uint8Array;
  expiresAt: number;
}

export interface MakeInviteOptions {
  now?: number;
  nonce?: Uint8Array;
}

export function makeInvite(
  identity: HybridIdentity,
  relays: string[],
  direct: string[],
  ttlS: number = DEFAULT_TTL_S,
  options: MakeInviteOptions = {},
): MadeInvite {
  const ttl = Math.min(Math.max(ttlS, MIN_TTL_S), MAX_TTL_S);
  const nonce = options.nonce ?? randomBytes(16);
  const expiresAt = (options.now ?? Math.floor(Date.now() / 1000)) + ttl;
  const fields: InviteFields = {
    version: 2,
    nodeId: identity.nodeId,
    name: identity.name,
    keyFingerprint: bytesToHex(keyFingerprint(identity.publicKey)),
    relays: [...relays],
    direct: [...direct],
    expiresAt,
    nonce: bytesToHex(nonce),
  };
  const signature = bytesToHex(identity.signEd25519(inviteBinding(fields)));
  const body = {
    version: 2,
    node_id: fields.nodeId,
    name: fields.name,
    key_fingerprint: fields.keyFingerprint,
    relays: fields.relays,
    direct: fields.direct,
    expires_at: fields.expiresAt,
    nonce: fields.nonce,
    signature,
  };
  return { text: PREFIX + base64urlEncode(utf8(JSON.stringify(body))), nonce, expiresAt };
}

export interface VerifiedInvite {
  nodeId: string;
  name: string;
  keyFingerprint: Uint8Array;
  nonce: Uint8Array;
  relays: string[];
  direct: string[];
}

function stringField(doc: Record<string, unknown>, key: string): string {
  const value = doc[key];
  if (typeof value !== "string") {
    throw new InviteError("invite is missing a field");
  }
  return value;
}

function stringList(doc: Record<string, unknown>, key: string): string[] {
  const value = doc[key];
  if (value === undefined) {
    return [];
  }
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) {
    throw new InviteError("invite is missing a field");
  }
  return value as string[];
}

function hexField(hex: string, message: string): Uint8Array {
  try {
    return hexToBytes(hex);
  } catch (error) {
    if (error instanceof TransferdError) {
      throw new InviteError(message);
    }
    throw error;
  }
}

/** Verifies an invite. Throws `InviteError` for anything the reference would refuse. */
export function acceptInvite(text: string, options: { now?: number } = {}): VerifiedInvite {
  if (!text.startsWith(PREFIX)) {
    throw new InviteError("an invite starts with tdov2:");
  }
  const raw = base64urlDecode(text.slice(PREFIX.length));
  if (raw.length > MAX_INVITE_BYTES) {
    throw new InviteError("invite is too large");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(utf8Decode(raw));
  } catch {
    throw new InviteError("invite is not a JSON object");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new InviteError("invite is not a JSON object");
  }
  const doc = parsed as Record<string, unknown>;
  const version = doc.version;
  if (typeof version !== "number" || !Number.isInteger(version)) {
    throw new InviteError("invite is missing a field");
  }
  const nodeId = stringField(doc, "node_id");
  const name = typeof doc.name === "string" ? doc.name : "";
  const fingerprintHex = stringField(doc, "key_fingerprint");
  const relays = stringList(doc, "relays");
  const direct = stringList(doc, "direct");
  const expiresAt = doc.expires_at;
  if (typeof expiresAt !== "number" || !Number.isSafeInteger(expiresAt)) {
    throw new InviteError("invite is missing a field");
  }
  const nonceHex = stringField(doc, "nonce");
  const signatureHex = stringField(doc, "signature");

  const current = options.now ?? Math.floor(Date.now() / 1000);
  if (expiresAt <= current) {
    throw new InviteError("invite has expired");
  }
  try {
    checkNodeId(nodeId);
  } catch (error) {
    if (error instanceof TransferdError) {
      throw new InviteError(error.message);
    }
    throw error;
  }
  const publicKey = hexField(nodeId, "invite node id is malformed");
  const signature = hexField(signatureHex, "invite signature is malformed");
  if (signature.length !== 64) {
    throw new InviteError("invite signature is malformed");
  }
  const binding = inviteBinding({
    version,
    nodeId,
    name,
    keyFingerprint: fingerprintHex,
    relays,
    direct,
    expiresAt,
    nonce: nonceHex,
  });
  if (!ed25519VerifyStrict(publicKey, binding, signature)) {
    throw new InviteError("invite signature does not verify");
  }
  const fingerprint = hexField(fingerprintHex, "invite key fingerprint or nonce is malformed");
  const nonce = hexField(nonceHex, "invite key fingerprint or nonce is malformed");
  if (fingerprint.length !== 32) {
    throw new InviteError("invite key fingerprint is malformed");
  }
  return {
    nodeId,
    name: name || nodeId.slice(0, 12),
    keyFingerprint: fingerprint,
    nonce,
    relays,
    direct,
  };
}
