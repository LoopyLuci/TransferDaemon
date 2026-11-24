import { TransferdError } from "./errors.js";

const HEX = /^(?:[0-9a-fA-F]{2})*$/;
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

/** Parses hex text of either case. Odd length or any other character is an error. */
export function hexToBytes(hex: string): Uint8Array {
  if (!HEX.test(hex)) {
    throw new TransferdError("value is not an even-length hex string");
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
  }
  return out;
}

/** Lowercase hex text. */
export function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) {
    out += b.toString(16).padStart(2, "0");
  }
  return out;
}

/** The concatenation of the parts, in order. */
export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const part of parts) {
    total += part.length;
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function utf8(text: string): Uint8Array {
  return encoder.encode(text);
}

/** Strict UTF-8 decoding. Throws a `TypeError` on invalid input; callers map that to their own error. */
export function utf8Decode(bytes: Uint8Array): string {
  return decoder.decode(bytes);
}

/** Compares two byte strings without returning early on the first difference. */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

export function u16Bytes(value: number, littleEndian = true): Uint8Array {
  const out = new Uint8Array(2);
  new DataView(out.buffer).setUint16(0, value, littleEndian);
  return out;
}

export function u32Bytes(value: number, littleEndian = true): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, littleEndian);
  return out;
}

export function u64Bytes(value: bigint, littleEndian = true): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, value, littleEndian);
  return out;
}
