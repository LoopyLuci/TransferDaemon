/**
 * The stream driver over a real TCP connection, with the TypeScript implementation on both ends. These need no
 * reference binary. They cover a stream the peer accepts, one it refuses, and several interleaved on one session.
 */
import assert from "node:assert/strict";
import { once } from "node:events";
import net from "node:net";
import type { AddressInfo } from "node:net";
import { test } from "node:test";
import { randomBytes } from "node:crypto"; // the library's helper is capped at 64 KiB per call; payloads here are larger
import { StreamRefused } from "../src/errors.js";
import { HybridIdentity } from "../src/identity.js";
import { Link } from "../src/wire.js";
import { accept, connect, type Session } from "../src/session.js";
import { StreamSession } from "../src/stream_session.js";

const A_SEED = Uint8Array.from({ length: 64 }, (_, i) => i);
const B_SEED = Uint8Array.from({ length: 64 }, (_, i) => (i * 5 + 9) & 0xff);

async function readAll(streams: StreamSession, sid: number): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
  for (;;) {
    const chunk = await streams.read(sid);
    if (chunk.length === 0) {
      return Buffer.concat(parts);
    }
    parts.push(chunk);
  }
}

interface Pair {
  client: StreamSession;
  peer: StreamSession;
  close(): Promise<void>;
}

/** Two stream sessions on one TCP connection: `client` opened it (even ids), `peer` accepted it (odd ids). */
async function connectedPair(): Promise<Pair> {
  const a = new HybridIdentity(A_SEED, "a");
  const b = new HybridIdentity(B_SEED, "b");
  const sockets: net.Socket[] = [];
  let resolvePeer!: (streams: StreamSession) => void;
  let rejectPeer!: (error: unknown) => void;
  const peerReady = new Promise<StreamSession>((resolve, reject) => {
    resolvePeer = resolve;
    rejectPeer = reject;
  });
  const server = net.createServer((socket) => {
    sockets.push(socket);
    accept(new Link(socket), b, { name: "b" }).then((session: Session) => {
      const streams = new StreamSession(session, { nodeId: b.nodeId, odd: true });
      streams.start();
      resolvePeer(streams);
    }, rejectPeer);
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const { port } = server.address() as AddressInfo;

  const socket = net.connect(port, "127.0.0.1");
  sockets.push(socket);
  await once(socket, "connect");
  const session = await connect(new Link(socket), a, { name: "a", expectNodeId: b.nodeId });
  const client = new StreamSession(session, { nodeId: a.nodeId, odd: false });
  client.start();
  const peer = await peerReady;
  return {
    client,
    peer,
    close: async () => {
      client.aclose();
      peer.aclose();
      for (const s of sockets) {
        s.destroy();
      }
      server.close();
    },
  };
}

test("a stream carries bytes both ways past the window", { timeout: 60_000 }, async () => {
  const pair = await connectedPair();
  try {
    // An open completes only when the peer accepts it, so the open runs alongside the accept.
    const opening = pair.client.open("echo");
    const [sid, service] = await pair.peer.nextRequest();
    assert.equal(service, "echo");
    await pair.peer.accept(sid);
    assert.equal(await opening, sid);

    const payload = new Uint8Array(randomBytes(300 * 1024)); // more than the 256 KiB window: the sender must wait for credit
    const echoBack = (async () => {
      const got = await readAll(pair.peer, sid);
      await pair.peer.write(sid, got, true);
      return got;
    })();
    const sent = pair.client.write(sid, payload, true);
    const [echoed, atPeer] = await Promise.all([readAll(pair.client, sid), echoBack]);
    await sent;
    await pair.client.close(sid);
    assert.deepEqual(new Uint8Array(atPeer), payload, "the peer received every byte, in order");
    assert.deepEqual(new Uint8Array(echoed), payload, "and the echo came back whole");
  } finally {
    await pair.close();
  }
});

test("a refused stream raises the refusal at the opener", { timeout: 30_000 }, async () => {
  const pair = await connectedPair();
  try {
    const opening = pair.client.open("nope");
    const [sid, service] = await pair.peer.nextRequest();
    assert.equal(service, "nope");
    await pair.peer.refuse(sid, "no_such_service", "nothing is exposed as nope");
    await assert.rejects(opening, (error: unknown) => {
      assert.ok(error instanceof StreamRefused);
      assert.equal(error.code, "no_such_service");
      assert.equal(error.reason, "nothing is exposed as nope");
      return true;
    });
  } finally {
    await pair.close();
  }
});

test("several streams interleave on one session", { timeout: 60_000 }, async () => {
  const pair = await connectedPair();
  try {
    const openings = [0, 1, 2].map((i) => pair.client.open(`svc${i}`));
    for (let i = 0; i < openings.length; i++) {
      const [sid] = await pair.peer.nextRequest();
      await pair.peer.accept(sid);
    }
    const ids = await Promise.all(openings);
    const payloads = ids.map((_, i) => new Uint8Array(randomBytes(20000 + 1000 * i)));

    const tasks: Promise<unknown>[] = [];
    const echoed: Promise<Uint8Array>[] = [];
    ids.forEach((sid, i) => {
      tasks.push(pair.client.write(sid, payloads[i]!, true));
      tasks.push(
        (async () => {
          const got = await readAll(pair.peer, sid);
          await pair.peer.write(sid, got, true);
        })(),
      );
      echoed.push(readAll(pair.client, sid));
    });
    await Promise.all(tasks);
    const results = await Promise.all(echoed);
    results.forEach((bytes, i) => {
      assert.deepEqual(new Uint8Array(bytes), payloads[i], "each stream carried its own bytes back, in its own order");
    });
  } finally {
    await pair.close();
  }
});
