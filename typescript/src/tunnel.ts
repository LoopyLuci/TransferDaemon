import type { Writable } from "node:stream";
import { concatBytes, u32Bytes, u64Bytes } from "./bytes.js";
import { aesGcmOpen, aesGcmSeal, blake3DeriveKey } from "./crypto.js";
import { TransferdError, TunnelError } from "./errors.js";
import { Frame, FrameReader } from "./frames.js";
import { type ByteStream, readBlob, writeBlob } from "./wire.js";

export const C2S_CONTEXT = "TransferDaemon-overlay-c2s-v1";
export const S2C_CONTEXT = "TransferDaemon-overlay-s2c-v1";
export const REPLAY_WINDOW = 4096;
/** `len u32 BE || counter u64 BE`: also the associated data. */
export const TUNNEL_HEADER_LEN = 12;

/** The keys one link uses: `send` for this side's frames, `recv` for the peer's. */
export interface LinkKeys {
  send: Uint8Array;
  recv: Uint8Array;
}

/** The mirrored view, for the side that accepted the connection. */
export function swapLinkKeys(keys: LinkKeys): LinkKeys {
  return { send: keys.recv, recv: keys.send };
}

export function deriveLinkKeys(sessionKey: Uint8Array): LinkKeys {
  return {
    send: blake3DeriveKey(C2S_CONTEXT, sessionKey),
    recv: blake3DeriveKey(S2C_CONTEXT, sessionKey),
  };
}

/** Hands out counters 0, 1, 2, ... A session shares one per direction. */
export class FrameCounter {
  private nextValue: bigint;

  constructor(start = 0n) {
    this.nextValue = start;
  }

  next(): bigint {
    const value = this.nextValue;
    this.nextValue += 1n;
    return value;
  }
}

/** Accepts each counter once, within `width` of the newest one accepted. */
export class ReplayWindow {
  private highest: bigint | null = null;
  private seen = new Set<bigint>();

  constructor(readonly width: number = REPLAY_WINDOW) {}

  /** Call this only after the frame has authenticated, so a forged counter cannot move the window. */
  accept(counter: bigint): boolean {
    const width = BigInt(this.width);
    if (this.highest === null) {
      this.highest = counter;
      this.seen = new Set([counter]);
      return true;
    }
    if (counter > this.highest) {
      this.highest = counter;
      const floor = counter - width;
      this.seen = new Set([...this.seen].filter((c) => c > floor));
      this.seen.add(counter);
      return true;
    }
    if (this.highest - counter >= width) {
      return false;
    }
    if (this.seen.has(counter)) {
      return false;
    }
    this.seen.add(counter);
    return true;
  }
}

/** Seals blobs with one key, drawing counters from a shared counter. */
export class Sealer {
  private readonly key: Uint8Array;
  private readonly counter: FrameCounter;

  constructor(key: Uint8Array, counter: FrameCounter = new FrameCounter()) {
    if (key.length !== 32) {
      throw new TunnelError("a tunnel key is 32 bytes");
    }
    this.key = key;
    this.counter = counter;
  }

  /** `counter` is given only by tests that pin the reference's output. */
  seal(plaintext: Uint8Array, counter?: bigint): Uint8Array {
    const c = counter ?? this.counter.next();
    if (plaintext.length > 0xffffffff) {
      throw new TunnelError("frame too large");
    }
    const aad = concatBytes(u32Bytes(plaintext.length, false), u64Bytes(c, false));
    const nonce = concatBytes(this.key.subarray(0, 4), u64Bytes(c, false));
    return concatBytes(aad, aesGcmSeal(this.key, nonce, plaintext, aad));
  }
}

/** Opens sealed frames with one key and checks replays. */
export class Opener {
  private readonly key: Uint8Array;
  private readonly window: ReplayWindow;

  constructor(key: Uint8Array, window: ReplayWindow = new ReplayWindow()) {
    if (key.length !== 32) {
      throw new TunnelError("a tunnel key is 32 bytes");
    }
    this.key = key;
    this.window = window;
  }

  open(frame: Uint8Array): Uint8Array {
    if (frame.length < TUNNEL_HEADER_LEN) {
      throw new TunnelError("tunnel frame is too short");
    }
    const aad = frame.subarray(0, TUNNEL_HEADER_LEN);
    const view = new DataView(aad.buffer, aad.byteOffset, aad.byteLength);
    const length = view.getUint32(0, false);
    const counter = view.getBigUint64(4, false);
    const nonce = concatBytes(this.key.subarray(0, 4), u64Bytes(counter, false));
    let plaintext: Uint8Array;
    try {
      plaintext = aesGcmOpen(this.key, nonce, frame.subarray(TUNNEL_HEADER_LEN), aad);
    } catch (error) {
      if (error instanceof TransferdError) {
        throw new TunnelError("tunnel frame failed to authenticate");
      }
      throw error;
    }
    if (!this.window.accept(counter)) {
      throw new TunnelError("replayed tunnel frame");
    }
    if (plaintext.length !== length) {
      throw new TunnelError("tunnel frame length does not match its header");
    }
    return plaintext;
  }
}

/** Reads overlay frames off a link. Every frame in a sealed blob is kept, none dropped. */
export class TunnelReader {
  private readonly opener: Opener;
  private readonly frames = new FrameReader();
  private readonly pending: Frame[] = [];

  constructor(keys: LinkKeys) {
    this.opener = new Opener(keys.recv);
  }

  async nextFrame(input: ByteStream): Promise<Frame> {
    while (this.pending.length === 0) {
      const blob = await readBlob(input);
      this.pending.push(...this.frames.push(this.opener.open(blob)));
    }
    const next = this.pending.shift();
    if (next === undefined) {
      throw new TunnelError("no frame was pending");
    }
    return next;
  }
}

export async function writeFrame(output: Writable, sealer: Sealer, frame: Frame): Promise<void> {
  await writeBlob(output, sealer.seal(frame.encode()));
}
