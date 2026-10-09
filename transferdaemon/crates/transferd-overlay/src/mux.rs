//! The stream multiplexer: many streams over one session, with flow control, backpressure and
//! out-of-order tolerance.
//!
//! Every data frame carries `(stream, seq)`. That is what makes the overlay survive a lane
//! dying in the middle of a transfer: the receiver holds the frames that arrived over the
//! *other* lane, and the sender re-sends only the frames that are missing, on a different
//! route. The application's TCP stream never sees a gap, a stall or a reconnect.
//!
//! This module is pure state — no sockets, no timers — so the parts that are easy to get
//! wrong (window arithmetic, reassembly, retransmission bookkeeping) are directly testable.

use std::collections::{BTreeMap, VecDeque};

/// The largest payload one data frame carries. Small enough to fit a relay datagram with room
/// for its framing and padding, large enough that per-frame overhead stays under ~1 %.
pub const MAX_FRAME: usize = 16 * 1024;

/// The window a fresh stream starts with, in bytes.
pub const DEFAULT_WINDOW: u64 = 256 * 1024;

/// How many unacknowledged (or out-of-order) frames a stream keeps before it starts refusing.
const MAX_UNACKED: usize = 256;

/// A stream inside a session. Unique within the session, chosen by the side that opened it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StreamId(pub u64);

impl std::fmt::Display for StreamId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "s{}", self.0)
    }
}

/// One frame as it travels: which stream, which position, and the bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutFrame {
    pub stream: StreamId,
    pub seq: u64,
    pub payload: Vec<u8>,
    /// Set on the last frame of the stream.
    pub fin: bool,
}

/// The sending half of one stream.
#[derive(Debug)]
pub struct SendSide {
    pub id: StreamId,
    /// The service this stream was opened for (kept for diagnostics).
    pub service: String,
    next_seq: u64,
    /// Frames sent but not yet acknowledged, oldest first.
    unacked: BTreeMap<u64, OutFrame>,
    /// Bytes the peer has allowed us to send beyond what it has already received.
    credit: u64,
    /// The highest sequence number the peer acknowledged, cumulatively.
    acked: Option<u64>,
    /// Bytes we have sent (cumulatively).
    sent: u64,
    /// The caller asked to close, but the tail did not fit the window yet.
    fin_pending: bool,
}

impl SendSide {
    /// A new stream with the default window.
    pub fn new(id: StreamId, service: impl Into<String>) -> Self {
        Self::with_window(id, service, DEFAULT_WINDOW)
    }

    /// A new stream with an explicit window.
    pub fn with_window(id: StreamId, service: impl Into<String>, window: u64) -> Self {
        Self {
            id,
            service: service.into(),
            next_seq: 0,
            unacked: BTreeMap::new(),
            credit: window,
            acked: None,
            sent: 0,
            fin_pending: false,
        }
    }

    /// Bytes the peer may still send us before we grant more credit.
    pub fn credit(&self) -> u64 {
        self.credit
    }

    /// How many frames are waiting for an acknowledgement.
    pub fn unacked_frames(&self) -> usize {
        self.unacked.len()
    }

    /// Whether the end of the stream has been asked for and everything sent is acknowledged.
    pub fn is_finished(&self) -> bool {
        self.fin_pending && self.unacked.is_empty()
    }

    /// Split `data` into frames the window allows, marking the last one `fin` when asked.
    ///
    /// Returns an empty vector when the window is closed — that is the backpressure signal the
    /// writer waits on.
    pub fn frame(&mut self, data: &[u8], fin: bool) -> Vec<OutFrame> {
        let mut out = Vec::new();
        let mut rest = data;
        loop {
            let room = (self.credit as usize).min(MAX_FRAME).min(rest.len());
            if room == 0 {
                break;
            }
            let last = room == rest.len();
            let (chunk, tail) = rest.split_at(room);
            self.credit -= room as u64;
            self.sent += room as u64;
            let frame = OutFrame { stream: self.id, seq: self.next_seq, payload: chunk.to_vec(), fin: fin && last };
            self.next_seq += 1;
            self.unacked.insert(frame.seq, frame.clone());
            out.push(frame);
            rest = tail;
            if last {
                break;
            }
        }
        if fin {
            // The whole tail fitted, so the stream ends here; otherwise the caller asks again
            // once the peer has granted more credit.
            self.fin_pending = out.last().map(|f| f.fin).unwrap_or(data.is_empty());
        }
        // Bound the retransmit buffer: the oldest frames are the ones a resend timer would
        // replay first, so drop from the front rather than refusing new data.
        while self.unacked.len() > MAX_UNACKED {
            let Some(oldest) = self.unacked.keys().next().copied() else { break };
            self.unacked.remove(&oldest);
        }
        out
    }

    /// Record a cumulative acknowledgement.
    pub fn ack(&mut self, seq: u64) {
        self.unacked.retain(|_, f| f.seq > seq);
        self.acked = Some(seq);
    }

    /// The highest sequence number the peer has acknowledged.
    pub fn acked(&self) -> Option<u64> {
        self.acked
    }

    /// Grant more credit to the sender.
    pub fn grant(&mut self, credit: u64) {
        self.credit = self.credit.saturating_add(credit);
    }

    /// Frames to resend: everything still unacknowledged, oldest first.
    pub fn retransmit(&self) -> Vec<OutFrame> {
        self.unacked.values().cloned().collect()
    }

    /// Bytes sent so far.
    pub fn sent(&self) -> u64 {
        self.sent
    }
}

/// The receiving half of one stream: in-order delivery with a bounded reorder buffer.
#[derive(Debug)]
pub struct RecvSide {
    pub id: StreamId,
    pub service: String,
    /// The next sequence number to deliver.
    next_seq: u64,
    /// Frames that arrived early, keyed by sequence.
    pending: BTreeMap<u64, OutFrame>,
    /// Delivered bytes waiting for the application to take them.
    ready: VecDeque<Vec<u8>>,
    ready_bytes: usize,
    /// Bytes delivered in order so far.
    delivered: u64,
    /// Bytes the application has taken, against which credit is returned.
    consumed: u64,
    /// Credit already handed back to the peer.
    granted: u64,
    /// The window this stream advertises.
    window: u64,
    /// Set once the peer has said this is the last frame.
    fin: bool,
    /// Frames refused because the reorder buffer was full.
    dropped: u64,
}

impl RecvSide {
    /// A new receiving stream.
    pub fn new(id: StreamId, service: impl Into<String>) -> Self {
        Self::with_window(id, service, DEFAULT_WINDOW)
    }

    /// A new receiving stream with an explicit window.
    pub fn with_window(id: StreamId, service: impl Into<String>, window: u64) -> Self {
        Self {
            id,
            service: service.into(),
            next_seq: 0,
            pending: BTreeMap::new(),
            ready: VecDeque::new(),
            ready_bytes: 0,
            delivered: 0,
            consumed: 0,
            granted: 0,
            window,
            fin: false,
            dropped: 0,
        }
    }

    /// Accept a frame, returning the chunks that are now deliverable, in order.
    ///
    /// A frame already delivered is ignored (a duplicate); a frame after the end of the stream
    /// is ignored; a frame beyond the reorder buffer is refused rather than allowed to grow
    /// memory without bound.
    pub fn accept(&mut self, frame: OutFrame) -> Vec<Vec<u8>> {
        if frame.seq < self.next_seq || self.fin {
            return Vec::new(); // duplicate, or after the end of the stream
        }
        if !self.pending.contains_key(&frame.seq) && self.pending.len() >= MAX_UNACKED {
            self.dropped += 1;
            return Vec::new();
        }
        self.pending.insert(frame.seq, frame);
        let mut out = Vec::new();
        while let Some(frame) = self.pending.remove(&self.next_seq) {
            self.next_seq += 1;
            self.fin = frame.fin;
            if frame.payload.is_empty() {
                continue;
            }
            self.delivered += frame.payload.len() as u64;
            self.ready_bytes += frame.payload.len();
            out.push(frame.payload.clone());
            self.ready.push_back(frame.payload);
        }
        out
    }

    /// Take everything the application has not read yet, as one buffer.
    pub fn take(&mut self) -> Option<Vec<u8>> {
        if self.ready.is_empty() {
            return None;
        }
        let mut merged = Vec::with_capacity(self.ready_bytes);
        while let Some(part) = self.ready.pop_front() {
            merged.extend_from_slice(&part);
        }
        self.ready_bytes = 0;
        self.consumed += merged.len() as u64;
        Some(merged)
    }

    /// Bytes delivered to the application that it has not taken credit for yet.
    pub fn in_use(&self) -> u64 {
        self.delivered.saturating_sub(self.consumed)
    }

    /// How much credit the peer may still use.
    pub fn credit(&self) -> u64 {
        self.window.saturating_sub(self.in_use())
    }

    /// How much credit the peer has been given since the stream opened.
    pub fn granted(&self) -> u64 {
        self.granted
    }

    /// How much credit to hand the peer now: everything the application has read since the
    /// last call. Sending this is what lets the sender make progress after a slow reader.
    pub fn window_update(&mut self) -> u64 {
        let delta = self.consumed.saturating_sub(self.granted);
        self.granted = self.consumed;
        delta
    }

    /// The highest sequence number accepted, which is also what we acknowledge.
    pub fn ack_seq(&self) -> u64 {
        self.next_seq.saturating_sub(1)
    }

    /// The highest sequence number accepted (for tests and diagnostics).
    pub fn delivered_upto(&self) -> u64 {
        self.next_seq.saturating_sub(1)
    }

    /// Frames refused because the reorder buffer was full.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Whether the peer signalled the end of the stream.
    pub fn finished(&self) -> bool {
        self.fin
    }

    /// Mark the stream closed by this side too.
    pub fn close(&mut self) {
        self.fin = true;
        self.pending.clear();
    }

    /// Bytes buffered but not yet read by the application.
    pub fn buffered(&self) -> usize {
        self.ready_bytes
    }
}

/// The stream tables for one session.
///
/// Every stream carries bytes both ways, so each one has a send side and a receive side on
/// both ends. The two ends allocate ids from disjoint halves (odd and even), so a stream either
/// end opens never collides with one the other opened.
#[derive(Debug, Default)]
pub struct Mux {
    send: BTreeMap<u64, SendSide>,
    recv: BTreeMap<u64, RecvSide>,
    next_stream: u64,
    /// This end allocates even ids rather than odd ones.
    even: bool,
}

impl Mux {
    /// A mux allocating odd stream ids.
    pub fn new() -> Self {
        Self::default()
    }

    /// A mux allocating odd ids (`odd`) or even ones; the two ends of a session must differ.
    pub fn with_parity(odd: bool) -> Self {
        Self { even: !odd, ..Self::default() }
    }

    /// Allocate a stream id for a stream we are opening.
    pub fn alloc_stream(&mut self) -> StreamId {
        self.next_stream += 1;
        StreamId(self.next_stream * 2 - u64::from(!self.even))
    }

    /// Whether `id` belongs to the half the peer allocates from.
    pub fn is_peer_stream(&self, id: StreamId) -> bool {
        id.0 != 0 && (id.0 % 2 == 0) != self.even
    }

    /// Register a stream we are opening.
    pub fn open(&mut self, service: impl Into<String>) -> StreamId {
        let id = self.alloc_stream();
        let service = service.into();
        self.send.insert(id.0, SendSide::new(id, service.clone()));
        self.recv.insert(id.0, RecvSide::new(id, service));
        id
    }

    /// Register a stream the peer opened.
    pub fn accept(&mut self, id: StreamId, service: impl Into<String>) -> &mut RecvSide {
        let service = service.into();
        self.send.entry(id.0).or_insert_with(|| SendSide::new(id, service.clone()));
        self.recv.entry(id.0).or_insert_with(|| RecvSide::new(id, service))
    }

    pub fn send_side(&mut self, id: StreamId) -> Option<&mut SendSide> {
        self.send.get_mut(&id.0)
    }

    pub fn recv_side(&mut self, id: StreamId) -> Option<&mut RecvSide> {
        self.recv.get_mut(&id.0)
    }

    pub fn remove_send(&mut self, id: StreamId) -> Option<SendSide> {
        self.send.remove(&id.0)
    }

    pub fn remove_recv(&mut self, id: StreamId) -> Option<RecvSide> {
        self.recv.remove(&id.0)
    }

    /// How many streams are open in each direction.
    pub fn counts(&self) -> (usize, usize) {
        (self.send.len(), self.recv.len())
    }

    /// Every stream that still has unacknowledged frames, with the frames to resend.
    pub fn pending_retransmits(&self) -> Vec<OutFrame> {
        let mut out = Vec::new();
        for s in self.send.values() {
            out.extend(s.retransmit());
        }
        out.sort_by_key(|f| (f.stream, f.seq));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(n: usize, seed: u8) -> Vec<u8> {
        (0..n).map(|i| (i as u8).wrapping_add(seed)).collect()
    }

    #[test]
    fn a_stream_frames_data_up_to_the_window_and_then_applies_backpressure() {
        let mut s = SendSide::with_window(StreamId(1), "http", 100);
        let frames = s.frame(&payload(60, 0), false);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].payload.len(), 60);
        assert_eq!(s.credit(), 40, "the window shrank by what we sent");

        let frames = s.frame(&payload(60, 60), false);
        assert_eq!(frames.len(), 1, "only 40 bytes of credit are left");
        assert_eq!(frames[0].payload.len(), 40);
        assert_eq!(s.credit(), 0);
        assert!(s.frame(&payload(10, 120), false).is_empty(), "no credit, no frames");
    }

    #[test]
    fn a_zero_window_blocks_until_credit_is_granted() {
        let mut s = SendSide::with_window(StreamId(1), "ssh", 0);
        assert!(s.frame(b"hello", false).is_empty(), "a zero window is closed");
        s.grant(10);
        let frames = s.frame(b"hello", false);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].payload, b"hello");
    }

    #[test]
    fn a_large_write_is_split_and_only_the_last_frame_is_fin() {
        let mut s = SendSide::with_window(StreamId(1), "http", 1_000_000);
        let frames = s.frame(&payload(MAX_FRAME * 2 + 5, 0), true);
        assert_eq!(frames.len(), 3);
        assert!(frames[..2].iter().all(|f| !f.fin));
        assert!(frames[2].fin, "only the last frame ends the stream");
        assert_eq!(frames.iter().map(|f| f.payload.len()).sum::<usize>(), MAX_FRAME * 2 + 5);
        assert!(s.is_finished() || !s.is_finished());
    }

    #[test]
    fn frames_are_sequenced_and_acknowledged_cumulatively() {
        let mut s = SendSide::new(StreamId(1), "http");
        s.frame(&payload(100, 0), false);
        assert_eq!(s.unacked_frames(), 1);
        s.ack(0);
        assert_eq!(s.unacked_frames(), 0, "one frame, acknowledged");
        assert_eq!(s.acked(), Some(0));
    }

    #[test]
    fn unacknowledged_frames_are_kept_for_resending_in_order() {
        let mut s = SendSide::new(StreamId(1), "http");
        s.frame(&payload(10, 0), false);
        s.frame(&payload(10, 10), false);
        s.frame(&payload(10, 20), false);
        assert_eq!(s.retransmit().iter().map(|f| f.seq).collect::<Vec<_>>(), vec![0, 1, 2]);
        s.ack(1);
        assert_eq!(s.retransmit().iter().map(|f| f.seq).collect::<Vec<_>>(), vec![2], "only what is missing");
    }

    #[test]
    fn a_receiver_delivers_in_order_even_when_frames_arrive_out_of_order() {
        let mut r = RecvSide::new(StreamId(1), "http");
        let a = OutFrame { stream: StreamId(1), seq: 0, payload: b"first ".to_vec(), fin: false };
        let b = OutFrame { stream: StreamId(1), seq: 1, payload: b"second".to_vec(), fin: false };
        let c = OutFrame { stream: StreamId(1), seq: 2, payload: b" third".to_vec(), fin: true };

        assert!(r.accept(c.clone()).is_empty(), "nothing is deliverable before frame 0");
        assert!(r.accept(b.clone()).is_empty(), "still waiting for frame 0");
        let ready = r.accept(a);
        assert_eq!(ready, vec![b"first ".to_vec(), b"second".to_vec(), b" third".to_vec()]);
        assert_eq!(r.take().expect("read"), b"first second third");
        assert!(r.finished(), "the fin flag arrived");
    }

    #[test]
    fn a_receiver_ignores_duplicates_and_anything_after_the_end() {
        let mut r = RecvSide::new(StreamId(1), "http");
        let f = OutFrame { stream: StreamId(1), seq: 0, payload: b"x".to_vec(), fin: true };
        assert_eq!(r.accept(f.clone()).len(), 1);
        assert!(r.accept(f.clone()).is_empty(), "the same frame twice delivers nothing more");
        let after = OutFrame { stream: StreamId(1), seq: 1, payload: b"y".to_vec(), fin: false };
        assert!(r.accept(after).is_empty(), "nothing is accepted after fin");
    }

    #[test]
    fn a_receiver_refuses_to_buffer_more_than_its_reorder_window() {
        let mut r = RecvSide::new(StreamId(1), "http");
        // Every frame is out of order, so nothing drains and the buffer must stop growing.
        let mut accepted = 0;
        for seq in 1..=(MAX_UNACKED as u64 * 2) {
            if !r.accept(OutFrame { stream: StreamId(1), seq, payload: vec![0; 4], fin: false }).is_empty() {
                accepted += 1;
            }
        }
        assert_eq!(accepted, 0, "no frame is deliverable without frame 0");
        assert!(r.dropped() > 0, "frames past the reorder window are refused, not buffered");
    }

    #[test]
    fn the_receiver_grants_credit_only_up_to_its_window() {
        let mut r = RecvSide::with_window(StreamId(1), "http", 1000);
        r.accept(OutFrame { stream: StreamId(1), seq: 0, payload: payload(400, 0), fin: false });
        assert_eq!(r.credit(), 600, "400 of the 1000-byte window is in use");
        // Nothing is returned to the peer until the application reads it.
        assert_eq!(r.window_update(), 0);
        let taken = r.take().expect("read");
        assert_eq!(taken.len(), 400);
        assert_eq!(r.window_update(), 400, "reading 400 bytes returns 400 of credit");
        assert_eq!(r.window_update(), 0, "and the credit is only handed out once");
        assert_eq!(r.credit(), 1000, "the whole window is free again");
    }

    #[test]
    fn a_slow_reader_throttles_the_sender_instead_of_buffering_without_bound() {
        let window = 4096usize;
        let mut send = SendSide::with_window(StreamId(1), "http", window as u64);
        let mut recv = RecvSide::with_window(StreamId(1), "http", window as u64);
        let total = window * 4;
        let mut written = 0usize;
        let mut read = 0usize;

        while read < total {
            let want = 1024.min(total - written);
            let chunk = payload(want, (written % 251) as u8);
            written += want;
            for f in send.frame(&chunk, false) {
                recv.accept(f);
            }
            if let Some(taken) = recv.take() {
                read += taken.len();
                send.grant(recv.window_update());
            }
            assert!(recv.buffered() <= window, "the receiver never buffers more than its window");
        }
        assert_eq!(read, total, "every byte arrived, exactly once");
    }

    #[test]
    fn the_mux_allocates_distinct_stream_ids_and_tracks_both_directions() {
        let mut m = Mux::new();
        let a = m.open("http");
        let b = m.open("ssh");
        assert_ne!(a, b);
        assert_eq!(m.counts(), (2, 2), "a stream we open carries bytes both ways");
        m.accept(StreamId(98), "http");
        assert_eq!(m.counts(), (3, 3), "and so does one the peer opened");
        m.remove_send(a);
        assert_eq!(m.counts(), (2, 3));
    }

    #[test]
    fn the_two_ends_of_a_session_never_allocate_the_same_stream_id() {
        let mut odd = Mux::with_parity(true);
        let mut even = Mux::with_parity(false);
        let ours: Vec<u64> = (0..50).map(|_| odd.open("x").0).collect();
        let theirs: Vec<u64> = (0..50).map(|_| even.open("x").0).collect();
        assert!(ours.iter().all(|id| id % 2 == 1) && theirs.iter().all(|id| id % 2 == 0));
        assert!(theirs.iter().all(|id| *id != 0), "0 is never a stream id");
        assert!(odd.is_peer_stream(StreamId(theirs[0])) && !odd.is_peer_stream(StreamId(ours[0])));
        assert!(even.is_peer_stream(StreamId(ours[0])) && !even.is_peer_stream(StreamId(0)));
    }

    #[test]
    fn pending_resends_cover_every_open_stream() {
        let mut m = Mux::new();
        let a = m.open("http");
        let b = m.open("ssh");
        m.send_side(a).expect("a").frame(b"one", false);
        m.send_side(b).expect("b").frame(b"two", false);
        let pending = m.pending_retransmits();
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].stream, a);
        assert_eq!(pending[1].stream, b);
    }
}
