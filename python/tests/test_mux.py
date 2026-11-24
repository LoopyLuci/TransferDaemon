"""The stream multiplexer, ported from crates/transferd-overlay/src/mux.rs and checked against the same behaviour."""

from transferd.mux import MAX_FRAME, DEFAULT_WINDOW, Mux, OutFrame, RecvSide, SendSide


def payload(n: int, seed: int) -> bytes:
    return bytes((i + seed) % 256 for i in range(n))


def test_a_stream_frames_data_up_to_the_window_and_then_applies_backpressure():
    s = SendSide.with_window(1, "http", 100)
    frames = s.frame(payload(60, 0), False)
    assert len(frames) == 1 and len(frames[0].payload) == 60
    assert s.credit() == 40, "the window shrank by what was sent"

    frames = s.frame(payload(60, 60), False)
    assert len(frames) == 1 and len(frames[0].payload) == 40, "only 40 bytes of credit are left"
    assert s.credit() == 0
    assert s.frame(payload(10, 120), False) == [], "no credit, no frames"


def test_a_zero_window_blocks_until_credit_is_granted():
    s = SendSide.with_window(1, "ssh", 0)
    assert s.frame(b"hello", False) == [], "a zero window is closed"
    s.grant(10)
    frames = s.frame(b"hello", False)
    assert len(frames) == 1 and frames[0].payload == b"hello"


def test_a_large_write_is_split_and_only_the_last_frame_is_fin():
    s = SendSide.with_window(1, "http", 1_000_000)
    frames = s.frame(payload(MAX_FRAME * 2 + 5, 0), True)
    assert len(frames) == 3
    assert all(not f.fin for f in frames[:2])
    assert frames[2].fin, "only the last frame ends the stream"
    assert sum(len(f.payload) for f in frames) == MAX_FRAME * 2 + 5


def test_frames_are_sequenced_and_acknowledged_cumulatively():
    s = SendSide(id=1, service="http")
    s.frame(payload(100, 0), False)
    assert s.unacked_frames() == 1
    s.ack(0)
    assert s.unacked_frames() == 0
    assert s.acked() == 0


def test_unacknowledged_frames_are_kept_for_resending_in_order():
    s = SendSide(id=1, service="http")
    s.frame(payload(10, 0), False)
    s.frame(payload(10, 10), False)
    s.frame(payload(10, 20), False)
    assert [f.seq for f in s.retransmit()] == [0, 1, 2]
    s.ack(1)
    assert [f.seq for f in s.retransmit()] == [2], "only what is missing"


def test_a_receiver_delivers_in_order_even_when_frames_arrive_out_of_order():
    r = RecvSide(id=1, service="http")
    a = OutFrame(1, 0, b"first ", False)
    b = OutFrame(1, 1, b"second", False)
    c = OutFrame(1, 2, b" third", True)

    assert r.accept(c) == [], "nothing is deliverable before frame 0"
    assert r.accept(b) == [], "still waiting for frame 0"
    assert r.accept(a) == [b"first ", b"second", b" third"]
    assert r.take() == b"first second third"
    assert r.finished(), "the fin flag arrived"


def test_a_receiver_ignores_duplicates_and_anything_after_the_end():
    r = RecvSide(id=1, service="http")
    f = OutFrame(1, 0, b"x", True)
    assert len(r.accept(f)) == 1
    assert r.accept(f) == [], "the same frame twice delivers nothing more"
    assert r.accept(OutFrame(1, 1, b"y", False)) == [], "nothing is accepted after fin"


def test_a_receiver_refuses_to_buffer_more_than_its_reorder_window():
    r = RecvSide(id=1, service="http")
    accepted = 0
    for seq in range(1, 2 * 256 + 1):
        if r.accept(OutFrame(1, seq, bytes(4), False)):
            accepted += 1
    assert accepted == 0, "no frame is deliverable without frame 0"
    assert r.dropped() > 0, "frames past the reorder window are refused, not buffered"


def test_the_receiver_grants_credit_only_up_to_its_window():
    r = RecvSide.with_window(1, "http", 1000)
    r.accept(OutFrame(1, 0, payload(400, 0), False))
    assert r.credit() == 600, "400 of the 1000-byte window is in use"
    assert r.window_update() == 0, "nothing is returned until the application reads"
    assert len(r.take()) == 400
    assert r.window_update() == 400, "reading 400 bytes returns 400 of credit"
    assert r.window_update() == 0, "and the credit is only handed out once"
    assert r.credit() == 1000, "the whole window is free again"


def test_a_slow_reader_throttles_the_sender_instead_of_buffering_without_bound():
    window = 4096
    send = SendSide.with_window(1, "http", window)
    recv = RecvSide.with_window(1, "http", window)
    total = window * 4
    written = 0
    read = 0
    while read < total:
        want = min(1024, total - written)
        chunk = payload(want, written % 251)
        frames = send.frame(chunk, False)
        written += sum(len(f.payload) for f in frames)
        for f in frames:
            recv.accept(f)
        taken = recv.take()
        if taken is not None:
            read += len(taken)
            send.grant(recv.window_update())
        assert recv.buffered() <= window, "the receiver never buffers more than its window"
    assert read == total, "every byte arrived, exactly once"


def test_the_mux_allocates_distinct_stream_ids_and_tracks_both_directions():
    m = Mux()
    a = m.open("http")
    b = m.open("ssh")
    assert a != b
    assert m.counts() == (2, 2), "a stream we open carries bytes both ways"
    m.accept(98, "http")
    assert m.counts() == (3, 3), "and so does one the peer opened"
    m.remove_send(a)
    assert m.counts() == (2, 3)


def test_the_end_of_a_stream_goes_out_even_with_no_credit_left():
    send = SendSide.with_window(1, "x", 0)
    assert send.frame(b"data", False) == [], "no credit, no data"
    end = send.frame(b"", True)
    assert len(end) == 1 and end[0].fin and end[0].payload == b"", "an empty FIN frame needs no credit"
    assert send.frame(b"", False) == [], "and nothing at all is not a frame"


def test_the_two_ends_of_a_session_never_allocate_the_same_stream_id():
    odd = Mux(odd=True)
    even = Mux(odd=False)
    ours = [odd.open("x") for _ in range(50)]
    theirs = [even.open("x") for _ in range(50)]
    assert all(i % 2 == 1 for i in ours) and all(i % 2 == 0 for i in theirs)
    assert all(i != 0 for i in theirs), "0 is never a stream id"
    assert odd.is_peer_stream(theirs[0]) and not odd.is_peer_stream(ours[0])
    assert even.is_peer_stream(ours[0]) and not even.is_peer_stream(0)


def test_pending_resends_cover_every_open_stream():
    m = Mux()
    a = m.open("http")
    b = m.open("ssh")
    m.send_side(a).frame(b"one", False)
    m.send_side(b).frame(b"two", False)
    pending = m.pending_retransmits()
    assert len(pending) == 2
    assert [f.stream for f in pending] == sorted([a, b])


def test_the_default_window_is_256_kib():
    assert DEFAULT_WINDOW == 256 * 1024
    assert SendSide(id=1).credit() == DEFAULT_WINDOW
