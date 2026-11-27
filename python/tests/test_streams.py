"""The stream engine's rules, driven with an explicit clock and no sockets.

Two engines stand for the two ends of a session. `deliver` hands one end's frames to the other, so each rule
(OPEN refusal, in-order delivery, SACK and duplicate-ACK losses, the retransmission timeout, window backpressure,
CLOSE) can be checked at a known time.
"""

import pytest

from transferd import frames as F
from transferd.errors import StreamReset
from transferd.mux import MAX_FRAME
from transferd.streams import INITIAL_RTO_MS, MAX_RTO_MS, MIN_RTO_MS, Event, RtoEstimator, StreamEngine


def deliver(dst: StreamEngine, out, now: float):
    """Apply each (kind, body) of `out` to `dst`. Returns the frames `dst` sent back, and its events."""
    back, events = [], []
    for kind, body in out:
        sent, seen = dst.on_frame(kind, body, now)
        back += sent
        events += seen
    return back, events


def pair():
    """Engine `a` allocates odd stream ids and `b` even ones, as the two ends of a session do."""
    return StreamEngine(odd=True, node_id="a"), StreamEngine(odd=False, node_id="b")


def open_stream(a: StreamEngine, b: StreamEngine, service: str = "x", now: float = 0.0) -> int:
    sid, out = a.open(service, now)
    _, events = deliver(b, out, now)
    assert events == [Event("open_request", sid, service=service)]
    ok = b.accept(sid, now)
    _, events = deliver(a, ok, now)
    assert events == [Event("open_ok", sid)]
    return sid


def data_frames(out):
    return [body for kind, body in out if kind == F.DATA]


def test_a_stream_opens_carries_bytes_and_ends():
    a, b = pair()
    sid = open_stream(a, b)
    payload = bytes(range(256)) * 500  # 128000 bytes, well inside one window
    frames = a.write(sid, payload, True, 1.0)
    acks = []
    back, events = deliver(b, frames, 2.0)
    acks += back
    assert events and events[0] == Event("readable", sid)
    back, _ = deliver(a, acks, 3.0)
    assert back == [], "acknowledgements need no answer"
    assert a.mux.send_side(sid).unacked_frames() == 0, "everything sent is acknowledged"
    assert a.pending(sid) == 0

    got, out = b.read(sid, 4.0)
    assert got == payload
    assert out and out[0][0] == F.WINDOW and out[0][1].credit == len(payload), "reading returns the credit"
    got, _ = b.read(sid, 4.0)
    assert got == b"", "the end of the stream reads as empty"


def test_an_open_for_an_id_from_our_own_half_is_refused_with_protocol():
    a = StreamEngine(odd=True)
    out, events = a.on_frame(F.OPEN, F.Open(stream=3, service="x", node_id="z"), 0.0)
    assert events == []
    assert out[0][0] == F.OPEN_ERR and out[0][1].code == "protocol"


def test_an_open_for_an_id_already_pending_is_refused_with_protocol():
    _, b = pair()
    open_body = F.Open(stream=1, service="x", node_id="z")  # 1 is odd: the peer's half, since b allocates even ids
    out, events = b.on_frame(F.OPEN, open_body, 0.0)
    assert [e.kind for e in events] == ["open_request"]
    out, events = b.on_frame(F.OPEN, open_body, 0.0)
    assert events == [] and out[0][1].code == "protocol"


def test_data_for_a_stream_we_do_not_have_is_not_acknowledged():
    _, b = pair()
    out, events = b.on_frame(F.DATA, F.Data(stream=99, seq=0, fin=False, payload=b"x"), 0.0)
    assert out == [] and events == []


def test_a_duplicate_data_frame_is_acknowledged_again_but_delivered_once():
    a, b = pair()
    sid = open_stream(a, b)
    frame = data_frames(a.write(sid, b"once", False, 0.0))[0]
    first, events = b.on_frame(F.DATA, frame, 1.0)
    again, events2 = b.on_frame(F.DATA, frame, 2.0)
    assert [k for k, _ in first] == [F.ACK] and [k for k, _ in again] == [F.ACK]
    assert events2 == [], "a duplicate does not wake the reader again"
    assert b.read(sid, 3.0)[0] == b"once"


def test_a_gap_reported_by_sack_resends_the_missing_frame_before_its_timeout():
    a, b = pair()
    sid = open_stream(a, b)
    a.rto.on_rtt(20.0)  # a measured round trip of 20 ms: the SACK wait is 25 ms
    frames = data_frames(a.write(sid, b"x" * (MAX_FRAME * 3), False, 100.0))
    assert [f.seq for f in frames] == [0, 1, 2]

    # Frame 0 is lost. Frames 1 and 2 arrive, and the acknowledgement reports them.
    acks = []
    for f in frames[1:]:
        back, _ = b.on_frame(F.DATA, f, 110.0)
        acks += back
    last_ack = [body for kind, body in acks if kind == F.ACK][-1]
    assert last_ack.seq == 0 and last_ack.sack == [(1, 3)]

    # The acknowledgement arrives 40 ms after the sends: frame 0 is older than the SACK wait, so it is resent now.
    resend, _ = a.on_frame(F.ACK, last_ack, 140.0)
    assert [(kind, body.seq) for kind, body in resend] == [(F.DATA, 0)]


def test_three_duplicate_acknowledgements_resend_the_frame_at_the_gap():
    a, b = pair()
    sid = open_stream(a, b)
    a.rto.on_rtt(20.0)
    frames = data_frames(a.write(sid, b"x" * (MAX_FRAME * 4), False, 100.0))
    assert len(frames) == 4
    # Frame 0 is lost; the peer keeps answering with the same cumulative point and no SACK ranges.
    resends = []
    for _ in range(3):
        out, _ = a.on_frame(F.ACK, F.Ack(stream=sid, seq=0, sack=[]), 200.0)
        resends += out
    assert [(kind, body.seq) for kind, body in resends] == [(F.DATA, 0)]


def test_a_frame_unacknowledged_for_a_timeout_is_resent_and_the_timeout_backs_off():
    a, b = pair()
    sid = open_stream(a, b)
    a.write(sid, b"lost", False, 0.0)
    rto = a.rto.rto()
    assert rto == INITIAL_RTO_MS, "no round trip measured yet: the reference's initial timeout"
    assert a.tick(rto - 1) == [], "not yet"
    resent = a.tick(rto)
    assert [(kind, body.seq) for kind, body in resent] == [(F.DATA, 0)]
    assert a.rto.rto() == 2 * INITIAL_RTO_MS, "the timeout doubled after the loss"
    assert a.tick(rto + 2 * INITIAL_RTO_MS - 1) == []
    assert len(a.tick(rto + 2 * INITIAL_RTO_MS)) == 1


def test_the_window_holds_back_bytes_until_the_peer_grants_credit():
    a, b = pair()
    sid = open_stream(a, b)
    payload = b"z" * (256 * 1024 + 44032)  # more than the 256 KiB window: 44032 bytes must wait
    out = a.write(sid, payload, False, 0.0)
    assert sum(len(f.payload) for f in data_frames(out)) == 256 * 1024
    assert a.pending(sid) == 44032, "the rest waits, and nothing is dropped"

    deliver(b, out, 1.0)
    got, out = b.read(sid, 2.0)
    assert len(got) == 256 * 1024
    window = [body for kind, body in out if kind == F.WINDOW]
    assert window and window[0].credit == 256 * 1024
    more, _ = deliver(a, out, 3.0)
    assert a.pending(sid) == 0, "the grant lets the rest out"
    assert sum(len(f.payload) for f in data_frames(more)) == 44032

    deliver(b, more, 4.0)
    rest, _ = b.read(sid, 5.0)
    assert rest == b"z" * 44032


def test_a_close_from_the_peer_ends_the_stream_for_the_reader():
    a, b = pair()
    sid = open_stream(a, b)
    back, events = deliver(b, [(F.CLOSE, F.Close(stream=sid, code="closed", reason=""))], 1.0)
    assert back == []
    assert events == [Event("closed", sid, code="closed", reason="")]
    assert b.read(sid, 2.0)[0] == b"", "a closed stream reads as ended"


def test_a_local_close_sends_close_and_drops_the_stream():
    a, b = pair()
    sid = open_stream(a, b)
    out = a.close(sid)
    assert out[0][0] == F.CLOSE and out[0][1].code == "closed"
    assert a.mux.send_side(sid) is None and a.mux.recv_side(sid) is None


def test_the_rto_estimator_follows_rfc_6298_with_the_reference_clamps():
    est = RtoEstimator()
    assert est.rto() == INITIAL_RTO_MS
    est.on_rtt(100.0)
    assert est.srtt == 100.0 and est.rttvar == 50.0
    assert est.rto() == 300.0, "srtt + max(4 * rttvar, 100 ms)"
    est.on_rtt(100.0)
    assert est.srtt == 100.0 and est.rttvar == 37.5
    small = RtoEstimator()
    small.on_rtt(1.0)
    assert small.rto() == MIN_RTO_MS, "never below 200 ms"
    for _ in range(20):
        small.back_off()
    assert small.rto() == MAX_RTO_MS, "never above 5 s, backoff included"


def test_next_deadline_is_the_earliest_resend_time():
    a, b = pair()
    sid = open_stream(a, b)
    assert a.next_deadline() is None
    a.write(sid, b"one", False, 10.0)
    assert a.next_deadline() == 10.0 + INITIAL_RTO_MS


def test_a_close_with_a_refusal_code_is_an_error_for_the_reader():
    a, b = pair()
    sid = open_stream(a, b)
    deliver(b, [(F.CLOSE, F.Close(stream=sid, code="refused", reason="the service did not take the stream"))], 1.0)
    with pytest.raises(StreamReset):
        b.read(sid, 2.0)
    with pytest.raises(StreamReset):
        b.read(sid, 3.0)


def test_bytes_that_arrived_before_a_reset_are_read_before_the_error():
    a, b = pair()
    sid = open_stream(a, b)
    deliver(b, a.write(sid, b"partial", False, 0.0), 0.0)
    deliver(b, [(F.CLOSE, F.Close(stream=sid, code="reset", reason="gave up"))], 1.0)
    assert b.read(sid, 2.0)[0] == b"partial"
    with pytest.raises(StreamReset):
        b.read(sid, 3.0)


def test_a_clean_close_over_missing_frames_is_an_error_not_the_end():
    a, b = pair()
    sid = open_stream(a, b)
    a.write(sid, b"first", False, 0.0)  # frame 0: never delivered
    deliver(b, a.write(sid, b"second", False, 0.0), 0.0)  # frame 1 arrives beyond the gap
    deliver(b, [(F.CLOSE, F.Close(stream=sid, code="closed", reason=""))], 1.0)
    with pytest.raises(StreamReset):
        b.read(sid, 2.0)


def test_a_read_on_a_stream_that_was_never_open_is_an_error():
    _, b = pair()
    with pytest.raises(StreamReset):
        b.read(999_999, 0.0)


def test_a_read_after_our_own_clean_close_is_the_end_and_after_our_reset_an_error():
    a, b = pair()
    sid = open_stream(a, b)
    a.close(sid)
    assert a.read(sid, 1.0)[0] == b"", "a clean close of ours is the end"
    sid2 = open_stream(a, b)
    a.close(sid2, code="reset", reason="gave up")
    with pytest.raises(StreamReset):
        a.read(sid2, 1.0)


def test_a_stream_is_flushed_only_once_its_bytes_and_end_are_acknowledged():
    a, b = pair()
    sid = open_stream(a, b)
    frames = a.write(sid, b"x" * 5000, True, 1.0)
    assert not a.flushed(sid), "nothing has been acknowledged yet"
    acks, _ = deliver(b, frames, 2.0)
    assert not a.flushed(sid), "the peer's acknowledgement has not arrived yet"
    deliver(a, acks, 3.0)
    assert a.flushed(sid)


def test_bytes_held_back_by_the_window_keep_a_stream_from_being_flushed():
    a, b = pair()
    sid = open_stream(a, b)
    a.write(sid, bytes(300 * 1024), True, 1.0)  # more than the 256 KiB window: the rest waits for credit
    assert a.pending(sid) > 0
    assert not a.flushed(sid)


def test_a_stream_is_not_flushed_until_its_end_is_acknowledged():
    a, b = pair()
    sid = open_stream(a, b)
    frames = a.write(sid, b"abc", False, 1.0)
    acks, _ = deliver(b, frames, 2.0)
    deliver(a, acks, 3.0)
    assert not a.flushed(sid), "the bytes are acknowledged, but the end of the stream has not gone out"
    frames = a.finish(sid, 4.0)
    acks, _ = deliver(b, frames, 5.0)
    deliver(a, acks, 6.0)
    assert a.flushed(sid)


def test_a_stream_with_no_bytes_is_flushed_once_its_end_is_acknowledged():
    a, b = pair()
    sid = open_stream(a, b)
    frames = a.finish(sid, 1.0)
    assert not a.flushed(sid), "the end has not been acknowledged yet"
    acks, _ = deliver(b, frames, 2.0)
    deliver(a, acks, 3.0)
    assert a.flushed(sid)
