/**
 * The relay client's forwards against a stand-in relay: pipelined, and reusing one challenge.
 *
 * The stand-in is what makes these exact. It holds its acknowledgements until it has the forwards it wants, which a
 * client that waited for each ack before sending the next would never reach. The reference relay is covered by
 * `relay_hub.test.ts` and `relay_interop.test.ts`.
 */

import assert from "node:assert/strict";
import dgram from "node:dgram";
import { test } from "node:test";
import { Tag, encodeAck, encodeChallenge } from "../src/relay.js";
import { RelayClient } from "../src/relay_client.js";

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

interface StandIn {
  port: number;
  /** Challenge requests received. */
  challenges: number;
  /** Sequence numbers of the forwards received, in arrival order. */
  forwards: number[];
  close(): void;
}

/**
 * A relay that answers challenge requests, and acknowledges forwards once `acksAfter` of them have arrived, all at
 * once. The challenge it issues has `difficulty`.
 */
async function standIn(acksAfter: number, difficulty: number): Promise<StandIn> {
  const socket = dgram.createSocket("udp4");
  const pending: Array<{ seq: number; port: number; address: string }> = [];
  const relay: StandIn = { port: 0, challenges: 0, forwards: [], close: () => socket.close() };
  socket.on("message", (datagram, from) => {
    if (datagram[0] === Tag.CHALLENGE) {
      relay.challenges += 1;
      const expiresAt = Math.floor(Date.now() / 1000) + 60;
      socket.send(encodeChallenge(new Uint8Array(16).fill(1), expiresAt, difficulty), from.port, from.address);
    } else if (datagram[0] === Tag.FORWARD) {
      // The forward's sequence number follows its tag, the 32-byte token and the 8-byte proof of work.
      const seq = datagram.readUInt16LE(1 + 32 + 8);
      relay.forwards.push(seq);
      pending.push({ seq, port: from.port, address: from.address });
      if (pending.length === acksAfter) {
        for (const waiting of pending.splice(0)) {
          socket.send(encodeAck(waiting.seq), waiting.port, waiting.address);
        }
      }
    }
  });
  await new Promise<void>((resolve) => socket.bind(0, "127.0.0.1", resolve));
  relay.port = socket.address().port;
  return relay;
}

test("forwards are pipelined: five are in flight before the first is acknowledged", { timeout: 20_000 }, async () => {
  const relay = await standIn(5, 0);
  const client = new RelayClient({ host: "127.0.0.1", port: relay.port }, 5_000);
  try {
    await client.open();
    const token = new Uint8Array(32).fill(9);
    const sends = [0, 1, 2, 3, 4].map((i) => client.forward(token, Uint8Array.of(i)));
    // The stand-in acknowledges none until all five have arrived, so a client that waited for each ack would stall.
    await within(Promise.all(sends), 3_000, "five forwards to be acknowledged");
    assert.equal(new Set(relay.forwards).size, 5, "each forward carries its own sequence number");
    assert.equal(relay.challenges, 1, "one challenge serves all five forwards");
  } finally {
    client.close();
    relay.close();
  }
});

test("a forward reuses the relay's challenge rather than fetching one", { timeout: 20_000 }, async () => {
  const relay = await standIn(1, 8);
  const client = new RelayClient({ host: "127.0.0.1", port: relay.port }, 5_000);
  try {
    await client.open();
    const token = new Uint8Array(32).fill(4);
    for (let i = 0; i < 4; i += 1) {
      await within(client.forward(token, Uint8Array.of(i)), 3_000, "a forward to be acknowledged");
    }
    assert.equal(relay.forwards.length, 4, "every forward reached the relay");
    assert.equal(relay.challenges, 1, "the challenge is fetched once, not once per forward");
  } finally {
    client.close();
    relay.close();
  }
});
