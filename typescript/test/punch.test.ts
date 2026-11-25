/**
 * Hole punching between two nodes on one machine: the probes, the route they open, and the gateway envelope.
 *
 * Mirrors `python/tests/test_punch.py`. Each node is a relay client whose socket is open but never registered: the
 * client sends nothing to its relay address (the discard port here), it only reads the address its socket uses. The
 * punch over a relay's candidates is in `relay_hub.test.ts`.
 */

import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import dgram from "node:dgram";
import { test } from "node:test";
import { OverlayError } from "../src/errors.js";
import { Frame, PING, VERSION_CURRENT } from "../src/frames.js";
import type { Route } from "../src/link.js";
import {
  PunchTable,
  derivePunchKeys,
  encodeProbe,
  decodeProbe,
  gatewayUnwrap,
  gatewayWrap,
} from "../src/punch.js";
import type { SocketAddr } from "../src/relay.js";
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

async function node(gateway: SocketAddr | null = null): Promise<{ client: RelayClient; table: PunchTable }> {
  const client = new RelayClient({ host: "127.0.0.1", port: 9 });
  await client.open();
  return { client, table: new PunchTable(client, { gateway, relayIsLoopback: true }) };
}

/** The address a node's socket uses, which is what its peers name it by. */
function localOf(client: RelayClient): SocketAddr {
  const addr = client.localAddr;
  assert.ok(addr !== null, "the node's socket is open");
  return addr;
}

/** Waits for the next frame a route delivers, or fails. */
async function nextFrame(route: Route, ms = 5_000): Promise<Frame> {
  const deadline = Date.now() + ms;
  for (;;) {
    const frame = route.tryRecv();
    if (frame !== undefined) {
      return frame;
    }
    if (Date.now() > deadline) {
      throw new Error("no frame arrived over the punched route");
    }
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

function text(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("utf8");
}

function filled(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte);
}

test("a loopback punch opens a route that carries frames both ways", { timeout: 30_000 }, async () => {
  const a = await node();
  const b = await node();
  try {
    const keys = derivePunchKeys(7n, randomBytes(32), randomBytes(32));
    const aRun = a.table.begin({ id: 7n, initiator: true, keys, candidates: [localOf(b.client)], linkId: 1 });
    const bRun = b.table.begin({ id: 7n, initiator: false, keys, candidates: [localOf(a.client)], linkId: 2 });
    const [aLink, bLink] = await within(
      Promise.all([aRun.finish(), bRun.finish()]),
      15_000,
      "the punch to open a route",
    );
    assert.equal(aLink.kind, "holepunch");
    assert.equal(bLink.kind, "holepunch");

    aLink.send(new Frame(VERSION_CURRENT, PING, 0, 1, new TextEncoder().encode("from a")));
    assert.equal(text((await nextFrame(bLink)).body), "from a");
    bLink.send(new Frame(VERSION_CURRENT, PING, 0, 2, new TextEncoder().encode("from b")));
    assert.equal(text((await nextFrame(aLink)).body), "from b");
  } finally {
    a.client.close();
    b.client.close();
  }
});

test("a peer naming no usable address is refused", { timeout: 10_000 }, async () => {
  const { client, table } = await node();
  try {
    // Unspecified, and port 0: neither can be a peer, so nothing is probed.
    const params = {
      id: 9n,
      initiator: true,
      keys: derivePunchKeys(9n, filled(1), filled(2)),
      candidates: [
        ["0.0.0.0", 4000],
        ["127.0.0.1", 0],
      ] as SocketAddr[],
      linkId: 3,
    };
    assert.throws(
      () => table.begin(params),
      (error: unknown) => error instanceof OverlayError && /no usable address/.test(error.message),
    );
  } finally {
    client.close();
  }
});

test("a probe through the gateway is unwrapped and answered through it", { timeout: 10_000 }, async () => {
  // A stand-in gateway: a plain socket that sends and receives what the node sends through it.
  const gateway = dgram.createSocket("udp4");
  const received = new Promise<Uint8Array>((resolve) => {
    gateway.once("message", (datagram) => resolve(new Uint8Array(datagram)));
  });
  await new Promise<void>((resolve) => gateway.bind(0, "127.0.0.1", resolve));
  const { address, port } = gateway.address();
  const { client, table } = await node([address, port]);
  try {
    const peer: SocketAddr = ["127.0.0.1", 40123]; // an address the peer names; the envelope carries it to the node
    const keys = derivePunchKeys(5n, filled(3), filled(4));
    table.begin({ id: 5n, initiator: false, keys, candidates: [peer], linkId: 1 });
    const probe = encodeProbe(keys, { kind: "probe", fromInitiator: true, id: 5n, seq: 0 });
    const [nodeAddress, nodePort] = localOf(client);
    gateway.send(gatewayWrap(peer, probe), nodePort, nodeAddress);

    const unwrapped = gatewayUnwrap(await within(received, 5_000, "the answer through the gateway"));
    assert.ok(unwrapped !== null, "the answer comes back through the gateway, wrapped");
    assert.deepEqual(unwrapped.addr, peer, "the answer is addressed to the peer");
    const reply = decodeProbe(keys, unwrapped.datagram);
    assert.ok(reply !== null, "the answer is an authenticated probe");
    assert.equal(reply.kind, "reply");
    assert.deepEqual([reply.id, reply.seq, reply.fromInitiator], [5n, 0, false]);
  } finally {
    client.close();
    gateway.close();
  }
});
