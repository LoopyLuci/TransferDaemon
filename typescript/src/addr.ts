import { isIPv4, isIPv6 } from "node:net";
import { TransferdError } from "./errors.js";

export type IpFamily = 4 | 6;

/** Parses an IPv4 or IPv6 address into its family and its raw octets (4 or 16 bytes). */
export function ipToBytes(text: string): { family: IpFamily; bytes: Uint8Array } {
  if (isIPv4(text)) {
    return { family: 4, bytes: Uint8Array.from(text.split(".").map((part) => Number(part))) };
  }
  if (isIPv6(text)) {
    return { family: 6, bytes: parseIPv6(text) };
  }
  throw new TransferdError(`not an IP address: ${text}`);
}

/** The text form of raw octets: dotted quad for IPv4, RFC 5952 compressed form for IPv6. */
export function ipFromBytes(family: IpFamily, bytes: Uint8Array): string {
  if (family === 4) {
    return Array.from(bytes).join(".");
  }
  return formatIPv6(bytes);
}

function parseIPv6(text: string): Uint8Array {
  let body = text;
  const lastColon = body.lastIndexOf(":");
  const tail = body.slice(lastColon + 1);
  if (tail.includes(".")) {
    // An embedded IPv4 tail becomes two hex groups.
    const q = tail.split(".").map((part) => Number(part));
    body = `${body.slice(0, lastColon + 1)}${((q[0] << 8) | q[1]).toString(16)}:${((q[2] << 8) | q[3]).toString(16)}`;
  }
  const halves = body.split("::");
  if (halves.length > 2) {
    throw new TransferdError(`not an IPv6 address: ${text}`);
  }
  let groups: string[];
  if (halves.length === 2) {
    const head = halves[0] ? halves[0].split(":") : [];
    const rest = halves[1] ? halves[1].split(":") : [];
    const missing = 8 - head.length - rest.length;
    if (missing < 1) {
      throw new TransferdError(`not an IPv6 address: ${text}`);
    }
    groups = [...head, ...new Array<string>(missing).fill("0"), ...rest];
  } else {
    groups = body.split(":");
    if (groups.length !== 8) {
      throw new TransferdError(`not an IPv6 address: ${text}`);
    }
  }
  const out = new Uint8Array(16);
  const view = new DataView(out.buffer);
  groups.forEach((group, i) => view.setUint16(2 * i, Number.parseInt(group, 16), false));
  return out;
}

function formatIPv6(bytes: Uint8Array): string {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const groups = Array.from({ length: 8 }, (_, i) => view.getUint16(2 * i, false));
  // Compress the longest run of zero groups, if it is at least two groups long.
  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < 8; ) {
    if (groups[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === 0) {
      j++;
    }
    if (j - i >= 2 && j - i > bestLen) {
      bestStart = i;
      bestLen = j - i;
    }
    i = j;
  }
  const hex = groups.map((g) => g.toString(16));
  if (bestStart < 0) {
    return hex.join(":");
  }
  const left = hex.slice(0, bestStart).join(":");
  const right = hex.slice(bestStart + bestLen).join(":");
  return `${left}::${right}`;
}
