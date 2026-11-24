import { readFileSync } from "node:fs";

/** The vectors live at the repository root, next to `typescript/`: `dist/test` is three levels down. */
const VECTORS = new URL("../../../vectors/", import.meta.url);

/** Loads a JSON vector file written by the Rust reference. */
export function loadVectors(name: string): any {
  return JSON.parse(readFileSync(new URL(name, VECTORS), "utf8"));
}

/** The generator's byte pattern: `i * 13 + tag` modulo 256. */
export function pattern(length: number, tag: number): Uint8Array {
  return Uint8Array.from({ length }, (_, i) => (i * 13 + tag) & 0xff);
}

export function pattern32(tag: number): Uint8Array {
  return pattern(32, tag);
}
