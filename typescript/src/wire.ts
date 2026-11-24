import type { Duplex, Writable } from "node:stream";
import { concatBytes, u32Bytes } from "./bytes.js";
import { TransferdError } from "./errors.js";

/** The largest blob a reader accepts, so a hostile length cannot make it allocate freely. */
export const MAX_BLOB = 256 * 1024;

/** Reads exact byte counts from an async byte source, keeping any surplus for the next read. */
export class ByteStream {
  private readonly iterator: AsyncIterator<Uint8Array>;
  private pending: Uint8Array = new Uint8Array(0);

  constructor(source: AsyncIterable<Uint8Array>) {
    this.iterator = source[Symbol.asyncIterator]();
  }

  async readExactly(n: number): Promise<Uint8Array> {
    while (this.pending.length < n) {
      const next = await this.iterator.next();
      if (next.done) {
        throw new TransferdError("connection closed before the expected bytes arrived");
      }
      this.pending = concatBytes(this.pending, next.value);
    }
    const out = this.pending.slice(0, n);
    this.pending = this.pending.slice(n);
    return out;
  }
}

/** Reads one length-prefixed blob: `len u32 BE || bytes`. */
export async function readBlob(input: ByteStream): Promise<Uint8Array> {
  const header = await input.readExactly(4);
  const length = new DataView(header.buffer, header.byteOffset, header.byteLength).getUint32(0, false);
  if (length > MAX_BLOB) {
    throw new TransferdError("blob is larger than the tunnel allows");
  }
  return input.readExactly(length);
}

/** Writes one length-prefixed blob and resolves once the socket has accepted it. */
export function writeBlob(output: Writable, body: Uint8Array): Promise<void> {
  if (body.length > 0xffffffff) {
    throw new TransferdError("blob too large");
  }
  const framed = concatBytes(u32Bytes(body.length, false), body);
  return new Promise((resolve, reject) => {
    output.write(framed, (error) => (error ? reject(error) : resolve()));
  });
}

/** One direct link: a buffered reader and the writer, both over the same socket. */
export class Link {
  readonly input: ByteStream;
  readonly output: Duplex;

  constructor(socket: Duplex) {
    this.input = new ByteStream(socket);
    this.output = socket;
  }
}
