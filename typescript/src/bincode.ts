import { u16Bytes, u32Bytes, u64Bytes, utf8, utf8Decode, concatBytes } from "./bytes.js";
import { DecodeError } from "./errors.js";

const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);
const MAX_U64 = 0xffffffffffffffffn;

export type WriteFn<T> = (w: Writer, value: T) => void;
export type ReadFn<T> = (r: Reader) => T;

function checkRange(value: number, min: number, max: number): number {
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new RangeError(`${value} is outside ${min}..${max}`);
  }
  return value;
}

/** Writes a bincode encoding: little-endian fixed-width integers, u64 lengths, one-byte option tags. */
export class Writer {
  private readonly parts: Uint8Array[] = [];

  u8(value: number): void {
    this.parts.push(Uint8Array.of(checkRange(value, 0, 0xff)));
  }

  u16(value: number): void {
    this.parts.push(u16Bytes(checkRange(value, 0, 0xffff)));
  }

  u32(value: number): void {
    this.parts.push(u32Bytes(checkRange(value, 0, 0xffffffff)));
  }

  /** Accepts a number (which must be a safe, non-negative integer) or a bigint. */
  u64(value: number | bigint): void {
    let big: bigint;
    if (typeof value === "bigint") {
      big = value;
    } else {
      if (!Number.isSafeInteger(value) || value < 0) {
        throw new RangeError(`${value} is not a non-negative safe integer`);
      }
      big = BigInt(value);
    }
    if (big < 0n || big > MAX_U64) {
      throw new RangeError("u64 is out of range");
    }
    this.parts.push(u64Bytes(big));
  }

  f64(value: number): void {
    const out = new Uint8Array(8);
    new DataView(out.buffer).setFloat64(0, value, true);
    this.parts.push(out);
  }

  boolean(value: boolean): void {
    this.u8(value ? 1 : 0);
  }

  raw(bytes: Uint8Array): void {
    this.parts.push(bytes);
  }

  /** A u64 length, then the bytes. */
  bytes(bytes: Uint8Array): void {
    this.u64(bytes.length);
    this.parts.push(bytes);
  }

  string(text: string): void {
    this.bytes(utf8(text));
  }

  option<T>(value: T | null | undefined, write: WriteFn<T>): void {
    if (value === null || value === undefined) {
      this.u8(0);
      return;
    }
    this.u8(1);
    write(this, value);
  }

  seq<T>(items: readonly T[], write: WriteFn<T>): void {
    this.u64(items.length);
    for (const item of items) {
      write(this, item);
    }
  }

  getValue(): Uint8Array {
    return concatBytes(...this.parts);
  }
}

function view(bytes: Uint8Array): DataView {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

/** Reads a bincode encoding front to back. Trailing bytes are left unread. */
export class Reader {
  private pos = 0;

  constructor(private readonly data: Uint8Array) {}

  remaining(): number {
    return this.data.length - this.pos;
  }

  take(n: number): Uint8Array {
    if (n < 0 || this.remaining() < n) {
      throw new DecodeError("body ends before its fields do");
    }
    const out = this.data.slice(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }

  u8(): number {
    return this.take(1)[0];
  }

  u16(): number {
    return view(this.take(2)).getUint16(0, true);
  }

  u32(): number {
    return view(this.take(4)).getUint32(0, true);
  }

  /** A u64 that fits in a safe JavaScript number. Use `u64Big` for values that may be larger. */
  u64(): number {
    const value = this.u64Big();
    if (value > MAX_SAFE) {
      throw new DecodeError("u64 is too large for a number");
    }
    return Number(value);
  }

  u64Big(): bigint {
    return view(this.take(8)).getBigUint64(0, true);
  }

  f64(): number {
    return view(this.take(8)).getFloat64(0, true);
  }

  boolean(): boolean {
    const value = this.u8();
    if (value > 1) {
      throw new DecodeError("bool byte is neither 0 nor 1");
    }
    return value === 1;
  }

  raw(n: number): Uint8Array {
    return this.take(n);
  }

  bytes(): Uint8Array {
    const n = this.u64();
    if (n > this.remaining()) {
      throw new DecodeError("a length runs past the end of the body");
    }
    return this.take(n);
  }

  string(): string {
    const raw = this.bytes();
    try {
      return utf8Decode(raw);
    } catch {
      throw new DecodeError("string is not UTF-8");
    }
  }

  option<T>(read: ReadFn<T>): T | null {
    const tag = this.u8();
    if (tag === 0) {
      return null;
    }
    if (tag === 1) {
      return read(this);
    }
    throw new DecodeError("option tag is neither 0 nor 1");
  }

  seq<T>(read: ReadFn<T>): T[] {
    const n = this.u64();
    // Every element takes at least one byte, so a longer claim cannot be honest.
    if (n > this.remaining()) {
      throw new DecodeError("a sequence length runs past the end of the body");
    }
    const out: T[] = [];
    for (let i = 0; i < n; i++) {
      out.push(read(this));
    }
    return out;
  }
}
