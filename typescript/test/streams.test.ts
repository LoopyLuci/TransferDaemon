/**
 * The stream engine's rules, driven with an explicit clock and no sockets.
 *
 * Two engines stand for the two ends of a session. `deliver` hands one end's messages to the other, so each rule
 * (OPEN refusal, in-order delivery, SACK and duplicate-ACK losses, the retransmission timeout, window backpressure,
 * CLOSE) can be checked at a known time.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { ACK, CLOSE, DATA, OPEN, OPEN_ERR, WINDOW, type Ack, type Close, type Data, type Window } from "../src/frames.js";
import { StreamReset } from "../src/errors.js";
import { MAX_FRAME } from "../src/mux.js";
import {
  INITIAL_RTO_MS,
  MAX_RTO_MS,
  MIN_RTO_MS,
  RtoEstimator,
  StreamEngine,
  type Event,
  type Outbound,
} from "../src/streams.js";

function deliver(dst: StreamEngine, out: Outbound[], now: number): [Outbound[], Event[]] {
  const back: Outbound[] = [];
  const events: Event[] = [];
  for (const message of out) {
    const [sent, seen] = dst.onFrame(message.kind, message.body, now);
    back.push(...sent);
    events.push(...seen);
  }
  return [back, events];
}

/** Engine `a` allocates odd stream ids and `b` even ones, as the two ends of a session do. */
function pair(): [StreamEngine, StreamEngine] {
  return [new StreamEngine({ odd: true, nodeId: "a" }), new StreamEngine({ odd: false, nodeId: "b" })];
}

function openStream(a: StreamEngine, b: StreamEngine, service = "x", now = 0): number {
  const [sid, out] = a.open(service);
  const [, events] = deliver(b, out, now);
  assert.deepEqual(events, [{ kind: "open_request", stream: sid, service }]);
  const [, okEvents] = deliver(a, b.accept(sid), now);
  assert.deepEqual(okEvents, [{ kind: "open_ok", stream: sid }]);
  return sid;
}

function dataBodies(out: Outbound[]): Data[] {
  return out.filter((m) => m.kind === DATA).map((m) => m.body as Data);
}

function bytesOf(n: number, fill = 7): Uint8Array {
  return new Uint8Array(n).fill(fill);
}

test("a stream opens, carries bytes and ends", () => {
  const [a, b] = pair();
  const sid = openStream(a, b);
  const payload = Uint8Array.from({ length: 128000 }, (_, i) => i & 0xff); // well inside one window
  const frames = a.write(sid, payload, true, 1);
  const [acks, events] = deliver(b, frames, 2);
  assert.equal(events[0]?.kind, "readable");
  const [back] = deliver(a, acks, 3);
  assert.deepEqual(back, [], "acknowledgements need no answer");
  assert.equal(a.mux.sendSide(sid)!.unackedFrames(), 0, "everything sent is acknowledged");
  assert.equal(a.pending(sid), 0);

  const [got, out] = b.read(sid);
  assert.deepEqual(got, payload);
  assert.equal(out[0]?.kind, WINDOW);
  assert.equal((out[0]!.body as Window).credit, payload.length, "reading returns the credit");
  const [ended] = b.read(sid);
  assert.equal(ended?.length, 0, "the end of the stream reads as empty");
});

test("an open for an id from our own half is refused with protocol", () => {
  const a = new StreamEngine({ odd: true });
  const [out, events] = a.onFrame(OPEN, { stream: 3, service: "x", nodeId: "z" }, 0);
  assert.deepEqual(events, []);
  assert.equal(out[0]?.kind, OPEN_ERR);
  assert.equal((out[0]!.body as { code: string }).code, "protocol");
});

test("an open for an id already pending is refused with protocol", () => {
  const [, b] = pair();
  const body = { stream: 1, service: "x", nodeId: "z" }; // 1 is odd: the peer's half, since b allocates even ids
  const [, first] = b.onFrame(OPEN, body, 0);
  assert.deepEqual(
    first.map((e) => e.kind),
    ["open_request"],
  );
  const [out, events] = b.onFrame(OPEN, body, 0);
  assert.deepEqual(events, []);
  assert.equal((out[0]!.body as { code: string }).code, "protocol");
});

test("data for a stream we do not have is not acknowledged", () => {
  const [, b] = pair();
  const [out, events] = b.onFrame(DATA, { stream: 99, seq: 0, fin: false, payload: bytesOf(1) }, 0);
  assert.deepEqual(out, []);
  assert.deepEqual(events, []);
});

test("a duplicate data frame is acknowledged again but delivered once", () => {
  const [a, b] = pair();
  const sid = openStream(a, b);
  const frame = dataBodies(a.write(sid, new TextEncoder().encode("once"), false, 0))[0]!;
  const [first, events] = b.onFrame(DATA, frame, 1);
  const [again, events2] = b.onFrame(DATA, frame, 2);
  assert.deepEqual(
    first.map((m) => m.kind),
    [ACK],
  );
  assert.deepEqual(
    again.map((m) => m.kind),
    [ACK],
  );
  assert.equal(events.length, 1);
  assert.deepEqual(events2, [], "a duplicate does not wake the reader again");
  assert.equal(new TextDecoder().decode(b.read(sid)[0]!), "once");
});

test("a gap reported by SACK resends the missing frame before its timeout", () => {
  const [a, b] = pair();
  const sid = openStream(a, b);
  a.rto.onRtt(20); // a measured round trip of 20 ms: the SACK wait is 25 ms
  const frames = dataBodies(a.write(sid, bytesOf(MAX_FRAME * 3), false, 100));
  assert.deepEqual(
    frames.map((f) => f.seq),
    [0, 1, 2],
  );

  // Frame 0 is lost. Frames 1 and 2 arrive, and the acknowledgement reports them.
  const acks: Outbound[] = [];
  for (const f of frames.slice(1)) {
    const [back] = b.onFrame(DATA, f, 110);
    acks.push(...back);
  }
  const lastAck = acks.filter((m) => m.kind === ACK).pop()!.body as Ack;
  assert.equal(lastAck.seq, 0);
  assert.deepEqual(lastAck.sack, [[1, 3]]);

  // The acknowledgement arrives 40 ms after the sends: frame 0 is older than the SACK wait, so it is resent now.
  const [resend] = a.onFrame(ACK, lastAck, 140);
  assert.deepEqual(
    dataBodies(resend).map((f) => f.seq),
    [0],
  );
});

test("three duplicate acknowledgements resend the frame at the gap", () => {
  const [a, b] = pair();
  const sid = openStream(a, b);
  a.rto.onRtt(20);
  const frames = dataBodies(a.write(sid, bytesOf(MAX_FRAME * 4), false, 100));
  assert.equal(frames.length, 4);
  const resends: Outbound[] = [];
  for (let i = 0; i < 3; i++) {
    const [out] = a.onFrame(ACK, { stream: sid, seq: 0, sack: [] }, 200);
    resends.push(...out);
  }
  assert.deepEqual(
    dataBodies(resends).map((f) => f.seq),
    [0],
  );
});

test("a frame unacknowledged for a timeout is resent and the timeout backs off", () => {
  const [a, b] = pair();
  const sid = openStream(a, b);
  a.write(sid, new TextEncoder().encode("lost"), false, 0);
  const rto = a.rto.rto();
  assert.equal(rto, INITIAL_RTO_MS, "no round trip measured yet: the reference's initial timeout");
  assert.equal(a.tick(rto - 1).length, 0, "not yet");
  assert.deepEqual(
    dataBodies(a.tick(rto)).map((f) => f.seq),
    [0],
  );
  assert.equal(a.rto.rto(), 2 * INITIAL_RTO_MS, "the timeout doubled after the loss");
  assert.equal(a.tick(rto + 2 * INITIAL_RTO_MS - 1).length, 0);
  assert.equal(a.tick(rto + 2 * INITIAL_RTO_MS).length, 1);
});

test("the window holds back bytes until the peer grants credit", () => {
  const [a, b] = pair();
  const sid = openStream(a, b);
  const payload = bytesOf(256 * 1024 + 44032);
  const out = a.write(sid, payload, false, 0);
  assert.equal(
    dataBodies(out).reduce((n, f) => n + f.payload.length, 0),
    256 * 1024,
  );
  assert.equal(a.pending(sid), 44032, "the rest waits, and nothing is dropped");

  deliver(b, out, 1);
  const [got, readOut] = b.read(sid);
  assert.equal(got?.length, 256 * 1024);
  const window = readOut.find((m) => m.kind === WINDOW)!.body as Window;
  assert.equal(window.credit, 256 * 1024);
  const [more] = deliver(a, readOut, 3);
  assert.equal(a.pending(sid), 0, "the grant lets the rest out");
  assert.equal(
    dataBodies(more).reduce((n, f) => n + f.payload.length, 0),
    44032,
  );

  deliver(b, more, 4);
  const [rest] = b.read(sid);
  assert.deepEqual(rest, bytesOf(44032));
});

test("a close from the peer ends the stream for the reader", () => {
  const [a, b] = pair();
  const sid = openStream(a, b);
  const body: Close = { stream: sid, code: "closed", reason: "" };
  const [back, events] = deliver(b, [{ kind: CLOSE, body }], 1);
  assert.deepEqual(back, []);
  assert.deepEqual(events, [{ kind: "closed", stream: sid, code: "closed", reason: "" }]);
  assert.equal(b.read(sid)[0]?.length, 0, "a closed stream reads as ended");
});

test("a local close sends CLOSE and drops the stream", () => {
  const [a, b] = pair();
  const sid = openStream(a, b);
  const out = a.close(sid);
  assert.equal(out[0]?.kind, CLOSE);
  assert.equal((out[0]!.body as Close).code, "closed");
  assert.equal(a.mux.sendSide(sid), undefined);
  assert.equal(a.mux.recvSide(sid), undefined);
});

test("the RTO estimator follows RFC 6298 with the reference clamps", () => {
  const est = new RtoEstimator();
  assert.equal(est.rto(), INITIAL_RTO_MS);
  est.onRtt(100);
  assert.equal(est.srtt, 100);
  assert.equal(est.rto(), 300, "srtt + max(4 * rttvar, 100 ms)");
  est.onRtt(100);
  assert.equal(est.srtt, 100);
  const small = new RtoEstimator();
  small.onRtt(1);
  assert.equal(small.rto(), MIN_RTO_MS, "never below 200 ms");
  for (let i = 0; i < 20; i++) {
    small.backOff();
  }
  assert.equal(small.rto(), MAX_RTO_MS, "never above 5 s, backoff included");
});

test("nextDeadline is the earliest resend time", () => {
  const [a, b] = pair();
  const sid = openStream(a, b);
  assert.equal(a.nextDeadline(), null);
  a.write(sid, new TextEncoder().encode("one"), false, 10);
  assert.equal(a.nextDeadline(), 10 + INITIAL_RTO_MS);
});

test("a close with a refusal code is an error for the reader", () => {
  const [a, b] = pair();
  const sid = openStream(a, b);
  const body: Close = { stream: sid, code: "refused", reason: "the service did not take the stream" };
  deliver(b, [{ kind: CLOSE, body }], 1);
  assert.throws(() => b.read(sid), StreamReset);
  assert.throws(() => b.read(sid), StreamReset, "and it stays one");
});

test("bytes that arrived before a reset are read before the error", () => {
  const [a, b] = pair();
  const sid = openStream(a, b);
  deliver(b, a.write(sid, bytesOf(7), false, 0), 0);
  const body: Close = { stream: sid, code: "reset", reason: "gave up" };
  deliver(b, [{ kind: CLOSE, body }], 1);
  assert.deepEqual(b.read(sid)[0], bytesOf(7));
  assert.throws(() => b.read(sid), StreamReset);
});

test("a clean close over missing frames is an error, not the end", () => {
  const [a, b] = pair();
  const sid = openStream(a, b);
  a.write(sid, bytesOf(3, 1), false, 0); // frame 0: never delivered
  deliver(b, a.write(sid, bytesOf(3, 2), false, 0), 0); // frame 1 arrives beyond the gap
  const body: Close = { stream: sid, code: "closed", reason: "" };
  deliver(b, [{ kind: CLOSE, body }], 1);
  assert.throws(() => b.read(sid), StreamReset);
});

test("a read on a stream that was never open is an error", () => {
  const [, b] = pair();
  assert.throws(() => b.read(999_999), StreamReset);
});

test("a read after our own clean close is the end, and after our reset an error", () => {
  const [a, b] = pair();
  const sid = openStream(a, b);
  a.close(sid);
  assert.equal(a.read(sid)[0]?.length, 0);
  const sid2 = openStream(a, b);
  a.close(sid2, "reset", "gave up");
  assert.throws(() => a.read(sid2), StreamReset);
});

test("a stream is flushed only once its bytes and end are acknowledged", () => {
  const [a, b] = pair();
  const sid = openStream(a, b);
  const frames = a.write(sid, bytesOf(5000), true, 1.0);
  assert.equal(a.flushed(sid), false, "nothing has been acknowledged yet");
  const [acks] = deliver(b, frames, 2.0);
  assert.equal(a.flushed(sid), false, "the peer's acknowledgement has not arrived yet");
  deliver(a, acks, 3.0);
  assert.equal(a.flushed(sid), true);
});

test("bytes held back by the window keep a stream from being flushed", () => {
  const [a, b] = pair();
  const sid = openStream(a, b);
  a.write(sid, bytesOf(300 * 1024), true, 1.0); // more than the 256 KiB window: the rest waits for credit
  assert.ok(a.pending(sid) > 0);
  assert.equal(a.flushed(sid), false);
});

test("a stream is not flushed until its end is acknowledged", () => {
  const [a, b] = pair();
  const sid = openStream(a, b);
  const frames = a.write(sid, bytesOf(3), false, 1.0);
  const [acks] = deliver(b, frames, 2.0);
  deliver(a, acks, 3.0);
  assert.equal(a.flushed(sid), false, "the bytes are acknowledged, but the end of the stream has not gone out");
  const [endAcks] = deliver(b, a.finish(sid, 4.0), 5.0);
  deliver(a, endAcks, 6.0);
  assert.equal(a.flushed(sid), true);
});

test("a stream with no bytes is flushed once its end is acknowledged", () => {
  const [a, b] = pair();
  const sid = openStream(a, b);
  const frames = a.finish(sid, 1.0);
  assert.equal(a.flushed(sid), false, "the end has not been acknowledged yet");
  const [acks] = deliver(b, frames, 2.0);
  deliver(a, acks, 3.0);
  assert.equal(a.flushed(sid), true);
});
