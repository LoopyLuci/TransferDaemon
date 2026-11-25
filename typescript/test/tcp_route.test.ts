/**
 * A TCP route keeps every frame it receives, even when its reader falls behind.
 *
 * While the inbox is full the route stops reading its socket, so the frames wait in TCP and the sender is held back.
 * The earlier code dropped the frames that arrived while the inbox was full. Mirrors `python/tests/test_link.py`.
 */
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { once } from "node:events";
import net from "node:net";
import { test } from "node:test";
import { Frame, PING, VERSION_CURRENT } from "../src/frames.js";
import { RECV_QUEUE, TcpRoute } from "../src/link.js";
import { deriveLinkKeys, swapLinkKeys } from "../src/tunnel.js";
import { Link as WireLink } from "../src/wire.js";

/** Rejects if `promise` has not settled within `ms` milliseconds. */
async function within<T>(promise: Promise<T>, ms: number, what: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`timed out after ${ms} ms: ${what}`)), ms);
  });
  try {
    return await Promise.race([promise, timeout]);
  } finally {
    clearTimeout(timer);
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

test("a full inbox holds the sender back instead of dropping frames", async () => {
  const keys = deriveLinkKeys(randomBytes(32));
  const server = net.createServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (address === null || typeof address === "string") {
    throw new Error("the test server has no port");
  }
  const accepting = once(server, "connection");
  const client = net.connect(address.port, "127.0.0.1");
  await once(client, "connect");
  const [accepted] = await within(accepting, 5000, "the accepted connection");

  const sender = new TcpRoute(1, new WireLink(client), keys);
  const receiver = new TcpRoute(1, new WireLink(accepted), swapLinkKeys(keys));
  sender.start();
  receiver.start();

  // More frames than the inbox holds. They are small, so the sender produces them well within the reader's pause.
  const total = RECV_QUEUE + 300;
  const body = new Uint8Array(256);
  // Set when the test gives up, so both loops end instead of holding the process open.
  let stop = false;
  const produce = async (): Promise<void> => {
    for (let seq = 0; seq < total && !stop; seq++) {
      const frame = new Frame(VERSION_CURRENT, PING, 0, seq, body);
      while (!sender.send(frame) && !stop) {
        await sleep(1);
      }
    }
  };
  // The reader waits first, so the inbox fills before anything is taken from it.
  const consume = async (): Promise<number[]> => {
    await sleep(1000);
    const seqs: number[] = [];
    while (seqs.length < total && !stop) {
      const frame = receiver.tryRecv();
      if (frame === undefined) {
        await sleep(1);
      } else {
        seqs.push(frame.seq);
      }
    }
    return seqs;
  };

  try {
    const [, seqs] = await within(Promise.all([produce(), consume()]), 30_000, "every frame to arrive");
    assert.equal(seqs.length, total, "no frame is dropped");
    assert.deepEqual(
      seqs,
      Array.from({ length: total }, (_, i) => i),
      "the frames arrive in order",
    );
  } finally {
    stop = true;
    sender.close();
    receiver.close();
    server.close();
  }
});
