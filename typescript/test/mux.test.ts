import assert from "node:assert/strict";
import { test } from "node:test";
import { DEFAULT_WINDOW, MAX_FRAME, Mux, RecvSide, SendSide, type OutFrame } from "../src/mux.js";

function payload(n: number, seed: number): Uint8Array {
  return Uint8Array.from({ length: n }, (_, i) => (i + seed) & 0xff);
}

function frame(stream: number, seq: number, bytes: number[], fin = false): OutFrame {
  return { stream, seq, payload: Uint8Array.from(bytes), fin };
}

test("a stream frames data up to the window and then applies backpressure", () => {
  const s = new SendSide(1, "http", 100);
  let frames = s.frame(payload(60, 0), false);
  assert.equal(frames.length, 1);
  assert.equal(frames[0]!.payload.length, 60);
  assert.equal(s.credit(), 40, "the window shrank by what was sent");

  frames = s.frame(payload(60, 60), false);
  assert.equal(frames.length, 1, "only 40 bytes of credit are left");
  assert.equal(frames[0]!.payload.length, 40);
  assert.equal(s.credit(), 0);
  assert.deepEqual(s.frame(payload(10, 120), false), [], "no credit, no frames");
});

test("a zero window blocks until credit is granted", () => {
  const s = new SendSide(1, "ssh", 0);
  assert.deepEqual(s.frame(new TextEncoder().encode("hello"), false), []);
  s.grant(10);
  const frames = s.frame(new TextEncoder().encode("hello"), false);
  assert.equal(frames.length, 1);
  assert.equal(new TextDecoder().decode(frames[0]!.payload), "hello");
});

test("a large write is split and only the last frame is fin", () => {
  const s = new SendSide(1, "http", 1_000_000);
  const frames = s.frame(payload(MAX_FRAME * 2 + 5, 0), true);
  assert.equal(frames.length, 3);
  assert.ok(frames.slice(0, 2).every((f) => !f.fin));
  assert.ok(frames[2]!.fin, "only the last frame ends the stream");
  assert.equal(frames.reduce((n, f) => n + f.payload.length, 0), MAX_FRAME * 2 + 5);
});

test("frames are sequenced and acknowledged cumulatively", () => {
  const s = new SendSide(1, "http");
  s.frame(payload(100, 0), false);
  assert.equal(s.unackedFrames(), 1);
  s.ack(0);
  assert.equal(s.unackedFrames(), 0);
  assert.equal(s.acked(), 0);
});

test("unacknowledged frames are kept for resending in order", () => {
  const s = new SendSide(1, "http");
  s.frame(payload(10, 0), false);
  s.frame(payload(10, 10), false);
  s.frame(payload(10, 20), false);
  assert.deepEqual(
    s.retransmit().map((f) => f.seq),
    [0, 1, 2],
  );
  s.ack(1);
  assert.deepEqual(
    s.retransmit().map((f) => f.seq),
    [2],
    "only what is missing",
  );
});

test("a receiver delivers in order even when frames arrive out of order", () => {
  const r = new RecvSide(1, "http");
  const a = frame(1, 0, [...new TextEncoder().encode("first ")]);
  const b = frame(1, 1, [...new TextEncoder().encode("second")]);
  const c = frame(1, 2, [...new TextEncoder().encode(" third")], true);
  assert.deepEqual(r.accept(c), [], "nothing is deliverable before frame 0");
  assert.deepEqual(r.accept(b), [], "still waiting for frame 0");
  const ready = r.accept(a).map((chunk) => new TextDecoder().decode(chunk));
  assert.deepEqual(ready, ["first ", "second", " third"]);
  assert.equal(new TextDecoder().decode(r.take()!), "first second third");
  assert.ok(r.finished(), "the fin flag arrived");
});

test("a receiver ignores duplicates and anything after the end", () => {
  const r = new RecvSide(1, "http");
  const f = frame(1, 0, [120], true);
  assert.equal(r.accept(f).length, 1);
  assert.deepEqual(r.accept(f), [], "the same frame twice delivers nothing more");
  assert.deepEqual(r.accept(frame(1, 1, [121])), [], "nothing is accepted after fin");
});

test("a receiver refuses to buffer more than its reorder window", () => {
  const r = new RecvSide(1, "http");
  let accepted = 0;
  for (let seq = 1; seq <= 2 * 256; seq++) {
    accepted += r.accept(frame(1, seq, [0, 0, 0, 0])).length;
  }
  assert.equal(accepted, 0, "no frame is deliverable without frame 0");
  assert.ok(r.dropped() > 0, "frames past the reorder window are refused, not buffered");
});

test("the receiver grants credit only up to its window", () => {
  const r = new RecvSide(1, "http", 1000);
  r.accept({ stream: 1, seq: 0, payload: payload(400, 0), fin: false });
  assert.equal(r.credit(), 600, "400 of the 1000-byte window is in use");
  assert.equal(r.windowUpdate(), 0, "nothing is returned until the application reads");
  assert.equal(r.take()!.length, 400);
  assert.equal(r.windowUpdate(), 400, "reading 400 bytes returns 400 of credit");
  assert.equal(r.windowUpdate(), 0, "and the credit is only handed out once");
  assert.equal(r.credit(), 1000, "the whole window is free again");
});

test("a slow reader throttles the sender instead of buffering without bound", () => {
  const window = 4096;
  const send = new SendSide(1, "http", window);
  const recv = new RecvSide(1, "http", window);
  const total = window * 4;
  let written = 0;
  let read = 0;
  while (read < total) {
    const want = Math.min(1024, total - written);
    const chunk = payload(want, written % 251);
    for (const f of send.frame(chunk, false)) {
      written += f.payload.length;
      recv.accept(f);
    }
    const taken = recv.take();
    if (taken !== null) {
      read += taken.length;
      send.grant(recv.windowUpdate());
    }
    assert.ok(recv.buffered() <= window, "the receiver never buffers more than its window");
  }
  assert.equal(read, total, "every byte arrived, exactly once");
});

test("the mux allocates distinct stream ids and tracks both directions", () => {
  const m = new Mux();
  const a = m.open("http");
  const b = m.open("ssh");
  assert.notEqual(a, b);
  assert.deepEqual(m.counts(), [2, 2], "a stream we open carries bytes both ways");
  m.accept(98, "http");
  assert.deepEqual(m.counts(), [3, 3], "and so does one the peer opened");
  m.removeSend(a);
  assert.deepEqual(m.counts(), [2, 3]);
});

test("the end of a stream goes out even with no credit left", () => {
  const send = new SendSide(1, "x", 0);
  assert.deepEqual(send.frame(new TextEncoder().encode("data"), false), [], "no credit, no data");
  const end = send.frame(new Uint8Array(0), true);
  assert.equal(end.length, 1);
  assert.ok(end[0]!.fin && end[0]!.payload.length === 0, "an empty FIN frame needs no credit");
  assert.deepEqual(send.frame(new Uint8Array(0), false), [], "and nothing at all is not a frame");
});

test("the two ends of a session never allocate the same stream id", () => {
  const odd = new Mux(true);
  const even = new Mux(false);
  const ours = Array.from({ length: 50 }, () => odd.open("x"));
  const theirs = Array.from({ length: 50 }, () => even.open("x"));
  assert.ok(ours.every((id) => id % 2 === 1) && theirs.every((id) => id % 2 === 0));
  assert.ok(theirs.every((id) => id !== 0), "0 is never a stream id");
  assert.ok(odd.isPeerStream(theirs[0]!) && !odd.isPeerStream(ours[0]!));
  assert.ok(even.isPeerStream(ours[0]!) && !even.isPeerStream(0));
});

test("pending resends cover every open stream", () => {
  const m = new Mux();
  const a = m.open("http");
  const b = m.open("ssh");
  m.sendSide(a)!.frame(new TextEncoder().encode("one"), false);
  m.sendSide(b)!.frame(new TextEncoder().encode("two"), false);
  const pending = m.pendingRetransmits();
  assert.equal(pending.length, 2);
  assert.deepEqual(
    pending.map((f) => f.stream),
    [a, b].sort((x, y) => x - y),
  );
});

test("the default window is 256 KiB", () => {
  assert.equal(DEFAULT_WINDOW, 256 * 1024);
  assert.equal(new SendSide(1).credit(), DEFAULT_WINDOW);
});
