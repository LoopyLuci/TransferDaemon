import assert from "node:assert/strict";
import { once } from "node:events";
import net from "node:net";
import type { AddressInfo } from "node:net";
import { test } from "node:test";
import { Link, readBlob, writeBlob } from "../src/wire.js";
import { concatBytes, hexToBytes } from "../src/bytes.js";
import { HandshakeError } from "../src/errors.js";
import { HybridIdentity } from "../src/identity.js";
import { RESPONDER_FLIGHT_LEN, handshakeInitiator, handshakeResponder, type HandshakeResult } from "../src/handshake.js";
import { Opener, Sealer } from "../src/tunnel.js";
import { loadVectors } from "./helpers.js";

type Outcome<T> = { ok: true; value: T } | { ok: false; error: unknown };

/**
 * Serves `serve` on a loopback listener and drives it with `client(port)`. The responder's outcome is
 * awaited before this returns, so both sides are settled when the test reads them.
 */
async function loopback<R, T>(
  serve: (link: Link) => Promise<R>,
  client: (port: number) => Promise<T>,
): Promise<{ client: T; server: Outcome<R> }> {
  let settle!: (outcome: Outcome<R>) => void;
  const outcome = new Promise<Outcome<R>>((resolve) => (settle = resolve));
  const server = net.createServer((socket) => {
    serve(new Link(socket))
      .then(
        (value) => settle({ ok: true, value }),
        (error: unknown) => settle({ ok: false, error }),
      )
      .finally(() => socket.end());
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const { port } = server.address() as AddressInfo;
  try {
    const result = await client(port);
    return { client: result, server: await outcome };
  } finally {
    server.close();
  }
}

async function initiate(identity: HybridIdentity, port: number, expectNodeId?: string): Promise<HandshakeResult> {
  const socket = net.connect(port, "127.0.0.1");
  await once(socket, "connect");
  try {
    return await handshakeInitiator(new Link(socket), identity, expectNodeId);
  } finally {
    socket.end();
  }
}

/** Sends one raw blob, then returns every byte the responder sends back before it closes. */
async function sendRaw(port: number, payload: Uint8Array): Promise<Uint8Array> {
  const socket = net.connect(port, "127.0.0.1");
  await once(socket, "connect");
  try {
    await writeBlob(socket, payload);
    const chunks: Uint8Array[] = [];
    for await (const chunk of socket) {
      chunks.push(chunk);
    }
    return concatBytes(...chunks);
  } finally {
    socket.destroy();
  }
}

function responder(identity: HybridIdentity): (link: Link) => Promise<HandshakeResult> {
  return (link) => handshakeResponder(link, identity);
}

test("two TypeScript nodes agree on the session and its keys", async () => {
  const alpha = HybridIdentity.generate("alpha");
  const beta = HybridIdentity.generate("beta");
  const { client: init, server } = await loopback(responder(beta), (port) => initiate(alpha, port, beta.nodeId));
  assert.equal(server.ok, true, server.ok ? "" : String(server.error));
  if (!server.ok) {
    return;
  }
  const resp = server.value;
  assert.deepEqual(init.sessionKey, resp.sessionKey);
  assert.equal(init.peerNodeId, beta.nodeId);
  assert.equal(resp.peerNodeId, alpha.nodeId);
  assert.deepEqual(init.keys.send, resp.keys.recv);
  assert.deepEqual(init.keys.recv, resp.keys.send);
});

test("a tunnel frame sealed by one side opens on the other", async () => {
  const alpha = HybridIdentity.generate("alpha");
  const beta = HybridIdentity.generate("beta");
  const { client: init, server } = await loopback(responder(beta), (port) => initiate(alpha, port, beta.nodeId));
  assert.ok(server.ok);
  const resp = server.value as HandshakeResult;
  const sealed = new Sealer(init.keys.send).seal(new TextEncoder().encode("from alpha to beta"));
  assert.equal(new TextDecoder().decode(new Opener(resp.keys.recv).open(sealed)), "from alpha to beta");
  const reply = new Sealer(resp.keys.send).seal(new TextEncoder().encode("and back"));
  assert.equal(new TextDecoder().decode(new Opener(init.keys.recv).open(reply)), "and back");
});

test("the initiator refuses a peer it did not expect", async () => {
  const alpha = HybridIdentity.generate("alpha");
  const beta = HybridIdentity.generate("beta");
  const stranger = HybridIdentity.generate("stranger");
  await assert.rejects(
    loopback(responder(beta), (port) => initiate(alpha, port, stranger.nodeId)),
    (error: unknown) => error instanceof HandshakeError && /we dialled/.test(error.message),
  );
});

test("the initiator refuses a responder flight that does not verify", async () => {
  const alpha = HybridIdentity.generate("alpha");
  const tampered = hexToBytes(loadVectors("crypto.json").handshake.tampered_responder_flight);
  const serve = async (link: Link): Promise<void> => {
    await readBlob(link.input); // the initiator's flight; the answer below cannot verify
    await writeBlob(link.output, tampered);
  };
  await assert.rejects(
    loopback(serve, (port) => initiate(alpha, port)),
    (error: unknown) => error instanceof HandshakeError && /does not verify/.test(error.message),
  );
});

test("our responder accepts the reference initiator flight", async () => {
  const h = loadVectors("crypto.json").handshake.initiator;
  const beta = HybridIdentity.generate("beta");
  const { client: answer, server } = await loopback(responder(beta), (port) =>
    sendRaw(port, hexToBytes(h.flight)),
  );
  assert.equal(server.ok, true, server.ok ? "" : String(server.error));
  if (server.ok) {
    assert.equal(server.value.peerNodeId, h.node_id);
  }
  // The answer is one length-prefixed responder flight.
  assert.equal(answer.length, 4 + RESPONDER_FLIGHT_LEN);
});

test("our responder refuses a reference flight with a flipped signature bit", async () => {
  const flight = hexToBytes(loadVectors("crypto.json").handshake.initiator.flight);
  flight[flight.length - 1] ^= 0x01;
  const beta = HybridIdentity.generate("beta");
  const { client: answer, server } = await loopback(responder(beta), (port) => sendRaw(port, flight));
  assert.equal(server.ok, false);
  if (!server.ok) {
    assert.ok(server.error instanceof HandshakeError);
  }
  assert.equal(answer.length, 0, "a refused initiator gets no flight back");
});
