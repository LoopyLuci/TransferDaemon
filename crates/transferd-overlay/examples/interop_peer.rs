//! Interop peer for the Python and TypeScript implementations.
//!
//! Not part of the protocol API. It runs the reference's handshake and HELLO exchange over TCP, so
//! the other implementations can be tested against it in both directions.
//!
//! Run from the repository root:
//!
//!     cargo run -p transferd-overlay --example interop_peer -- serve <port> <seed-hex>
//!     cargo run -p transferd-overlay --example interop_peer -- echo <port> <seed-hex>
//!     cargo run -p transferd-overlay --example interop_peer -- dial <port> <seed-hex> <expected-node-id>
//!     cargo run -p transferd-overlay --example interop_peer -- stream <port> <seed-hex> <expected-node-id>
//!     cargo run -p transferd-overlay --example interop_peer -- overlay-echo <port> <seed-hex>
//!     cargo run -p transferd-overlay --example interop_peer -- overlay-stream <port> <seed-hex> <expected-node-id>
//!
//! `overlay-echo` and `overlay-stream` run the node's own session engine (`session.rs`) over TCP, the
//! code a running node uses, rather than the minimal engine above. `overlay-echo` answers every stream
//! for the service `echo`, and the other implementations dial it. `overlay-stream` dials, opens `echo`,
//! sends 600 KiB and checks the echo, so the other implementations listen and echo it.
//!
//! `serve` binds 127.0.0.1:<port> (0 picks a free port), prints `{"listening": "<addr>"}`, accepts
//! one connection, answers one HELLO with a HELLO_ACK, and prints a summary of the session.
//! `echo` does the same, then runs the stream side with the reference's own multiplexer: every
//! stream the peer opens for the service `echo` is echoed back, and the run ends at the peer's CLOSE.
//! `dial` connects to 127.0.0.1:<port>, sends one HELLO, and prints the summary of the HELLO_ACK.
//! `stream` dials the same way, then opens a stream for the service `echo` and sends it 600 KiB,
//! which the peer echoes back. It checks every byte that comes back, and the run ends at the peer's
//! CLOSE. So the stream opens from the reference's side this time.
//! Each run prints JSON lines on stdout and exits non-zero on failure.

use std::collections::{BTreeSet, HashSet};
use std::error::Error;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use serde_json::json;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use transferd_overlay::identity::NodeIdentity;
use transferd_overlay::lanes::{accept_tcp, dial_tcp};
use transferd_overlay::link::{Link, RouteKind};
use transferd_overlay::session::{spawn as spawn_session, SessionEvent, SessionHandle, SessionSetup};
use transferd_overlay::mux::{Mux, OutFrame, StreamId};
use transferd_overlay::protocol::{
    Ack, Close, CtrlAck, Data, Frame, Hello, HelloAck, HelloExt, Open, OpenErr, OpenOk,
    ServiceInfo, VERSION_CURRENT, VERSION_MIN, Window, kind, negotiate,
};
use transferd_overlay::wire::{
    LinkKeys, Tunnel, TunnelReader, handshake_initiator, handshake_responder, write_frame,
};

type Fail = Box<dyn Error>;

/// The nonce the dialling side sends in its HELLO, so the answer can be checked as a reply to it.
const DIAL_NONCE: [u8; 16] = [0x5a; 16];

/// The stack for the peer's threads. An unoptimised build keeps the node's session futures on the stack, and the
/// default stack of the main thread (1 MiB on Windows) overflows before the first message is sent.
const STACK_BYTES: usize = 64 * 1024 * 1024;

fn main() -> Result<(), Fail> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .thread_stack_size(STACK_BYTES)
        .enable_all()
        .build()?;
    // The run happens on a thread with a large stack. Its error is passed back as text, since `Fail` is not `Send`.
    let outcome: Result<(), String> = std::thread::Builder::new()
        .name("interop-peer".into())
        .stack_size(STACK_BYTES)
        .spawn(move || runtime.block_on(run()).map_err(|error| error.to_string()))?
        .join()
        .unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    outcome.map_err(Into::into)
}

async fn run() -> Result<(), Fail> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("serve") if args.len() == 4 => serve(&args[2], &args[3], false).await,
        Some("echo") if args.len() == 4 => serve(&args[2], &args[3], true).await,
        Some("dial") if args.len() == 5 => dial(&args[2], &args[3], &args[4]).await,
        Some("stream") if args.len() == 5 => stream(&args[2], &args[3], &args[4]).await,
        Some("overlay-echo") if args.len() == 4 => overlay_echo(&args[2], &args[3]).await,
        Some("overlay-stream") if args.len() == 5 => overlay_stream(&args[2], &args[3], &args[4]).await,
        _ => Err("usage: interop_peer serve|echo|overlay-echo <port> <seed-hex> | dial|stream|overlay-stream <port> <seed-hex> <expected-node-id>".into()),
    }
}

fn identity(seed_hex: &str, name: &str) -> Result<NodeIdentity, Fail> {
    let bytes = hex::decode(seed_hex)?;
    let seed: [u8; 64] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "an identity seed is 64 bytes")?;
    Ok(NodeIdentity::from_seed(&seed, name))
}

async fn serve(port: &str, seed_hex: &str, echo: bool) -> Result<(), Fail> {
    let me = identity(seed_hex, "interop-responder")?;
    let listener = TcpListener::bind(("127.0.0.1", port.parse::<u16>()?)).await?;
    println!(
        "{}",
        json!({ "listening": listener.local_addr()?.to_string() })
    );

    let (mut socket, _) = listener.accept().await?;
    let session = handshake_responder(&mut socket, &me).await?;

    let mut inbound = TunnelReader::new(&session.keys);
    let hello_frame = inbound.next_frame(&mut socket).await?;
    if hello_frame.kind != kind::HELLO {
        return Err(format!("expected HELLO, got kind {:#04x}", hello_frame.kind).into());
    }
    let hello: Hello = hello_frame.decode()?;

    let agreed = negotiate(
        hello.min_version,
        hello.max_version,
        VERSION_MIN,
        VERSION_CURRENT,
    );
    let ack = HelloAck {
        version: agreed.unwrap_or(0),
        node_id: me.node_id().to_string(),
        name: "interop-responder".into(),
        services: Vec::new(),
        nonce: hello.nonce,
        reason: if agreed.is_some() {
            String::new()
        } else {
            "no common version".into()
        },
        ext: Vec::new(),
    };
    let frame = Frame::new(2, kind::HELLO_ACK, 1, &ack)?;
    write_frame(&mut socket, &Tunnel::sender(&session.keys), &frame).await?;

    if echo {
        let version = agreed.ok_or("no common version: nothing to echo")?;
        let summary = echo_streams(&mut socket, &session.keys, version, &mut inbound).await?;
        println!(
            "{}",
            json!({
                "role": "echo",
                "peer": session.peer_node_id,
                "stream_bytes_in": summary.bytes_in,
                "stream_bytes_out": summary.bytes_out,
                "streams": summary.streams,
            })
        );
        return Ok(());
    }

    println!(
        "{}",
        json!({
            "role": "responder",
            "peer": session.peer_node_id,
            "peer_name": hello.name,
            "version": agreed,
        })
    );
    Ok(())
}

/// What the echo side moved, reported when the run ends.
#[derive(Default)]
struct EchoSummary {
    bytes_in: u64,
    bytes_out: u64,
    streams: u64,
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, Fail> {
    Ok(bincode::serialize(value)?)
}

/// Echo every stream the peer opens for the service `echo`, using the reference's multiplexer for the
/// flow control, the ordering and the SACK bookkeeping. Ends at the peer's CLOSE.
async fn echo_streams(
    socket: &mut TcpStream,
    keys: &LinkKeys,
    version: u16,
    inbound: &mut TunnelReader,
) -> Result<EchoSummary, Fail> {
    let mut mux = Mux::new();
    let mut summary = EchoSummary::default();
    // Bytes received on each stream and not yet echoed, the streams whose end has arrived, and those whose end we sent.
    let mut echo: std::collections::HashMap<u64, Vec<u8>> = std::collections::HashMap::new();
    let mut fin_wanted: HashSet<u64> = HashSet::new();
    let mut fin_sent: HashSet<u64> = HashSet::new();
    let mut seq: u64 = 1_000_000;

    loop {
        let frame = inbound.next_frame(socket).await?;
        let mut out: Vec<(u8, Vec<u8>)> = Vec::new();
        let mut done = false;
        match frame.kind {
            kind::CTRL_ACK => {}
            kind::OPEN => {
                let open: Open = frame.decode()?;
                let id = StreamId(open.stream);
                if !mux.is_peer_stream(id) {
                    out.push((
                        kind::OPEN_ERR,
                        encode(&OpenErr {
                            stream: open.stream,
                            code: "protocol".into(),
                            reason: "that stream id is not yours to open".into(),
                        })?,
                    ));
                } else if open.service == "echo" {
                    mux.accept(id, "echo");
                    summary.streams += 1;
                    out.push((
                        kind::OPEN_OK,
                        encode(&OpenOk {
                            stream: open.stream,
                            route: "interop".into(),
                        })?,
                    ));
                } else {
                    out.push((
                        kind::OPEN_ERR,
                        encode(&OpenErr {
                            stream: open.stream,
                            code: "no_such_service".into(),
                            reason: format!("no service named {}", open.service),
                        })?,
                    ));
                }
                out.push((kind::CTRL_ACK, encode(&CtrlAck { seq: frame.seq })?));
            }
            kind::DATA => {
                let data: Data = frame.decode()?;
                let id = StreamId(data.stream);
                if let Some(recv) = mux.recv_side(id) {
                    recv.accept(OutFrame {
                        stream: id,
                        seq: data.seq,
                        payload: data.payload,
                        fin: data.fin,
                    });
                    let ack = Ack {
                        stream: data.stream,
                        seq: recv.next_expected(),
                        sack: recv.sack_ranges(4),
                    };
                    out.push((kind::ACK, encode(&ack)?));
                    if let Some(bytes) = recv.take() {
                        summary.bytes_in += bytes.len() as u64;
                        echo.entry(data.stream)
                            .or_default()
                            .extend_from_slice(&bytes);
                    }
                    let granted = recv.window_update();
                    if granted > 0 {
                        out.push((
                            kind::WINDOW,
                            encode(&Window {
                                stream: data.stream,
                                credit: granted,
                            })?,
                        ));
                    }
                    if recv.finished() {
                        fin_wanted.insert(data.stream);
                    }
                }
            }
            kind::ACK => {
                let ack =
                    transferd_overlay::protocol::Ack::parse(&frame).ok_or("an unreadable ACK")?;
                if let Some(send) = mux.send_side(StreamId(ack.stream)) {
                    send.ack_below(ack.seq);
                }
            }
            kind::WINDOW => {
                let w: Window = frame.decode()?;
                if let Some(send) = mux.send_side(StreamId(w.stream)) {
                    send.grant(w.credit);
                }
                out.push((kind::CTRL_ACK, encode(&CtrlAck { seq: frame.seq })?));
            }
            kind::CLOSE => {
                let c: Close = frame.decode()?;
                mux.remove_send(StreamId(c.stream));
                mux.remove_recv(StreamId(c.stream));
                out.push((kind::CTRL_ACK, encode(&CtrlAck { seq: frame.seq })?));
                done = true;
            }
            _ => {}
        }

        // Echo what has arrived, as far as the peer's window allows; end the echo once its end has arrived.
        let ids: BTreeSet<u64> = echo
            .keys()
            .copied()
            .chain(fin_wanted.iter().copied())
            .collect();
        for id in ids {
            let Some(send) = mux.send_side(StreamId(id)) else {
                continue;
            };
            let buf = echo.entry(id).or_default();
            let fin_now = fin_wanted.contains(&id)
                && !fin_sent.contains(&id)
                && buf.len() as u64 <= send.credit();
            let frames = send.frame(buf, fin_now);
            let taken: usize = frames.iter().map(|f| f.payload.len()).sum();
            buf.drain(..taken);
            for f in frames {
                if f.fin {
                    fin_sent.insert(id);
                }
                summary.bytes_out += f.payload.len() as u64;
                out.push((
                    kind::DATA,
                    encode(&Data {
                        stream: id,
                        seq: f.seq,
                        fin: f.fin,
                        payload: f.payload,
                    })?,
                ));
            }
        }

        let tunnel = Tunnel::sender(keys);
        for (k, body) in out {
            let frame = Frame {
                version: version as u8,
                kind: k,
                flags: 0,
                seq,
                body,
            };
            seq += 1;
            write_frame(socket, &tunnel, &frame).await?;
        }
        if done {
            return Ok(summary);
        }
    }
}

/// What the dialling side ends up with: the socket, the session keys, the agreed version, and
/// the reader for everything the peer sends after the HELLO_ACK.
struct Dialled {
    socket: TcpStream,
    keys: LinkKeys,
    /// This side's node id, as the OPEN names it.
    node_id: String,
    peer: String,
    peer_name: String,
    version: u16,
    inbound: TunnelReader,
}

/// Handshake as the initiator and exchange HELLO / HELLO_ACK, as `dial` does.
async fn dial_session(port: &str, seed_hex: &str, expected: &str) -> Result<Dialled, Fail> {
    let me = identity(seed_hex, "interop-initiator")?;
    let mut socket = TcpStream::connect(("127.0.0.1", port.parse::<u16>()?)).await?;
    let session = handshake_initiator(&mut socket, &me, Some(expected)).await?;

    let hello = Hello {
        min_version: VERSION_MIN,
        max_version: VERSION_CURRENT,
        node_id: me.node_id().to_string(),
        name: "interop-initiator".into(),
        services: Vec::new(),
        ext: bincode::serialize(&HelloExt {
            pairing: None,
            direct: Vec::new(),
        })?,
        nonce: DIAL_NONCE,
    };
    let frame = Frame::new(2, kind::HELLO, 1, &hello)?;
    write_frame(&mut socket, &Tunnel::sender(&session.keys), &frame).await?;

    let mut inbound = TunnelReader::new(&session.keys);
    let reply = inbound.next_frame(&mut socket).await?;
    if reply.kind != kind::HELLO_ACK {
        return Err(format!("expected HELLO_ACK, got kind {:#04x}", reply.kind).into());
    }
    let ack: HelloAck = reply.decode()?;
    if ack.nonce != DIAL_NONCE {
        return Err("the answer echoes a different nonce".into());
    }
    if ack.version == 0 {
        return Err(format!("refused: {}", ack.reason).into());
    }
    Ok(Dialled {
        socket,
        keys: session.keys,
        node_id: me.node_id().to_string(),
        peer: ack.node_id,
        peer_name: ack.name,
        version: ack.version,
        inbound,
    })
}

async fn dial(port: &str, seed_hex: &str, expected: &str) -> Result<(), Fail> {
    let d = dial_session(port, seed_hex, expected).await?;
    println!(
        "{}",
        json!({
            "role": "initiator",
            "peer": d.peer,
            "peer_name": d.peer_name,
            "version": d.version,
        })
    );
    Ok(())
}

/// The bytes a stream sends: 600 KiB of a fixed pattern, more than one window, so credit must come
/// back from the peer before all of it can go.
const STREAM_BYTES: usize = 600 * 1024;

/// What the overlay echo side moved, counted as it runs and reported when the run ends.
#[derive(Default)]
struct OverlayTotals {
    streams: AtomicU64,
    bytes: AtomicU64,
}

/// How long one overlay run may last before it ends on its own.
const OVERLAY_RUN_LIMIT: Duration = Duration::from_secs(120);

/// The session setup both overlay modes use: this build's whole version range, no extension bytes.
fn overlay_setup(me: &NodeIdentity, peer: &str, services: Vec<ServiceInfo>) -> SessionSetup {
    SessionSetup {
        peer_node_id: peer.to_string(),
        peer_name: "interop-peer".into(),
        identity: me.clone(),
        services,
        max_version: VERSION_CURRENT as u8,
        ext: Vec::new(),
    }
}

/// Accept one TCP connection and run the node's session engine over it, echoing every stream for `echo`.
async fn overlay_echo(port: &str, seed_hex: &str) -> Result<(), Fail> {
    let me = identity(seed_hex, "interop-overlay-echo")?;
    let listener = TcpListener::bind(("127.0.0.1", port.parse::<u16>()?)).await?;
    println!(
        "{}",
        json!({ "listening": listener.local_addr()?.to_string() })
    );

    let (socket, _) = listener.accept().await?;
    let (link, _keys, peer, _peer_pk) = accept_tcp(1, RouteKind::Direct, socket, &me).await?;
    let link: Arc<dyn Link> = link;
    let services = vec![ServiceInfo {
        name: "echo".into(),
        description: "echoes every byte back".into(),
    }];
    let (events_tx, mut events) = mpsc::unbounded_channel::<SessionEvent>();
    let handle = Arc::new(spawn_session(overlay_setup(&me, &peer, services), vec![link], events_tx).await);
    let totals = Arc::new(OverlayTotals::default());

    let deadline = tokio::time::sleep(OVERLAY_RUN_LIMIT);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            event = events.recv() => match event {
                Some(SessionEvent::OpenRequest { stream, service, .. }) => {
                    if service == "echo" {
                        handle.authorize(stream, service, true, String::new()).await?;
                        totals.streams.fetch_add(1, Ordering::Relaxed);
                        tokio::spawn(echo_stream(handle.clone(), stream, totals.clone()));
                    } else {
                        let reason = format!("no service named {service}");
                        handle.authorize(stream, service, false, reason).await?;
                    }
                }
                Some(SessionEvent::Down { .. }) | None => break,
                Some(_) => {}
            },
            _ = &mut deadline => break,
        }
    }
    handle.shutdown().await;
    println!(
        "{}",
        json!({
            "role": "overlay_echo",
            "peer": peer,
            "streams": totals.streams.load(Ordering::Relaxed),
            "bytes": totals.bytes.load(Ordering::Relaxed),
        })
    );
    Ok(())
}

/// Echo one stream to its end: each chunk the peer sends goes straight back, and the end is answered with an end.
async fn echo_stream(handle: Arc<SessionHandle>, stream: StreamId, totals: Arc<OverlayTotals>) {
    while let Ok(Some(bytes)) = handle.recv(stream).await {
        totals.bytes.fetch_add(bytes.len() as u64, Ordering::Relaxed);
        if handle.send(stream, bytes, false).await.is_err() {
            return;
        }
    }
    let _ = handle.send(stream, Vec::new(), true).await;
}

/// Dial the peer, open a stream for `echo`, send the payload and read back what the peer echoes.
async fn overlay_exchange(handle: &SessionHandle, payload: &[u8]) -> Result<Vec<u8>, Fail> {
    if !handle.ready(Duration::from_secs(10)).await {
        return Err("the peer did not answer our hello".into());
    }
    let stream = handle.open("echo").await?;
    handle.send(stream, payload.to_vec(), true).await?;
    let mut received = Vec::with_capacity(payload.len());
    while let Some(chunk) = handle.recv(stream).await? {
        received.extend_from_slice(&chunk);
    }
    Ok(received)
}

/// Dial the peer over TCP with the node's session engine, and check the echo of one 600 KiB stream.
async fn overlay_stream(port: &str, seed_hex: &str, expected: &str) -> Result<(), Fail> {
    let me = identity(seed_hex, "interop-overlay-stream")?;
    let target = format!("127.0.0.1:{port}");
    let (link, _keys, peer, _peer_pk) =
        dial_tcp(1, RouteKind::Direct, &target, &me, Some(expected)).await?;
    let link: Arc<dyn Link> = link;
    let (events_tx, mut events) = mpsc::unbounded_channel::<SessionEvent>();
    let handle = Arc::new(spawn_session(overlay_setup(&me, &peer, Vec::new()), vec![link], events_tx).await);
    tokio::spawn(async move { while events.recv().await.is_some() {} });

    let payload = stream_payload();
    let outcome = tokio::time::timeout(OVERLAY_RUN_LIMIT, overlay_exchange(&handle, &payload)).await;
    handle.shutdown().await;
    let received = outcome.map_err(|_| -> Fail { "the echo did not finish in time".into() })??;
    if received != payload {
        return Err("the echoed bytes differ from what was sent".into());
    }
    println!(
        "{}",
        json!({
            "role": "overlay_stream",
            "peer": peer,
            "bytes": received.len(),
            "verified": true,
        })
    );
    Ok(())
}

fn stream_payload() -> Vec<u8> {
    (0..STREAM_BYTES as u64)
        .map(|i| (i.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 56) as u8 ^ (i / 1021) as u8)
        .collect()
}

/// Dial, open a stream for `echo`, send [`STREAM_BYTES`] and check each echoed byte.
async fn stream(port: &str, seed_hex: &str, expected: &str) -> Result<(), Fail> {
    let mut d = dial_session(port, seed_hex, expected).await?;
    let summary = open_echo_stream(&mut d).await?;
    println!(
        "{}",
        json!({
            "role": "stream",
            "peer": d.peer,
            "stream_bytes_out": summary.bytes_out,
            "stream_bytes_in": summary.bytes_in,
            "streams": summary.streams,
        })
    );
    Ok(())
}

/// Open one stream for `echo` and run it to the peer's CLOSE, on the reference's multiplexer.
async fn open_echo_stream(d: &mut Dialled) -> Result<EchoSummary, Fail> {
    let mut mux = Mux::with_parity(true);
    let id = mux.open("echo");
    let data = stream_payload();
    let mut summary = EchoSummary {
        streams: 1,
        ..EchoSummary::default()
    };
    let mut seq: u64 = 1_000_000;

    // Ask for the stream, and wait for the peer to accept it.
    let open = Open {
        stream: id.0,
        service: "echo".into(),
        node_id: d.node_id.clone(),
    };
    write_out(&mut d.socket, &d.keys, d.version, &mut seq, vec![(kind::OPEN, encode(&open)?)]).await?;
    loop {
        let frame = d.inbound.next_frame(&mut d.socket).await?;
        match frame.kind {
            kind::OPEN_OK => break,
            kind::OPEN_ERR => {
                let e: OpenErr = frame.decode()?;
                return Err(format!("the peer refused the stream: {}: {}", e.code, e.reason).into());
            }
            kind::CTRL_ACK => {}
            other => return Err(format!("expected OPEN_OK, got kind {other:#04x}").into()),
        }
    }

    let mut sent: usize = 0; // bytes of `data` handed to the send side
    let mut fin_sent = false;
    let mut got: usize = 0; // bytes of the echo checked so far
    let mut peer_closed = false;

    loop {
        // Send what the peer's window allows, and the end once everything has gone.
        let mut out: Vec<(u8, Vec<u8>)> = Vec::new();
        if !fin_sent {
            let send = mux.send_side(id).ok_or("the stream is not open")?;
            let rest = &data[sent..];
            let fin_now = rest.len() as u64 <= send.credit();
            let frames = send.frame(rest, fin_now);
            let taken: usize = frames.iter().map(|f| f.payload.len()).sum();
            sent += taken;
            for f in frames {
                if f.fin {
                    fin_sent = true;
                }
                summary.bytes_out += f.payload.len() as u64;
                out.push((
                    kind::DATA,
                    encode(&Data {
                        stream: id.0,
                        seq: f.seq,
                        fin: f.fin,
                        payload: f.payload,
                    })?,
                ));
            }
        }
        write_out(&mut d.socket, &d.keys, d.version, &mut seq, out).await?;
        if peer_closed {
            break;
        }

        let frame = d.inbound.next_frame(&mut d.socket).await?;
        let mut reply: Vec<(u8, Vec<u8>)> = Vec::new();
        match frame.kind {
            kind::CTRL_ACK | kind::OPEN_OK | kind::OPEN_ERR => {}
            kind::ACK => {
                let ack = Ack::parse(&frame).ok_or("an unreadable ACK")?;
                if let Some(send) = mux.send_side(StreamId(ack.stream)) {
                    send.ack_below(ack.seq);
                }
            }
            kind::WINDOW => {
                let w: Window = frame.decode()?;
                if let Some(send) = mux.send_side(StreamId(w.stream)) {
                    send.grant(w.credit);
                }
                reply.push((kind::CTRL_ACK, encode(&CtrlAck { seq: frame.seq })?));
            }
            kind::DATA => {
                let chunk: Data = frame.decode()?;
                let recv = mux
                    .recv_side(StreamId(chunk.stream))
                    .ok_or("data for a stream we do not have")?;
                recv.accept(OutFrame {
                    stream: StreamId(chunk.stream),
                    seq: chunk.seq,
                    payload: chunk.payload,
                    fin: chunk.fin,
                });
                if let Some(bytes) = recv.take() {
                    if data.get(got..got + bytes.len()) != Some(bytes.as_slice()) {
                        return Err(format!("the echo differs from what was sent, at byte {got}").into());
                    }
                    got += bytes.len();
                    summary.bytes_in += bytes.len() as u64;
                }
                let ack = Ack {
                    stream: chunk.stream,
                    seq: recv.next_expected(),
                    sack: recv.sack_ranges(4),
                };
                reply.push((kind::ACK, encode(&ack)?));
                let granted = recv.window_update();
                if granted > 0 {
                    reply.push((
                        kind::WINDOW,
                        encode(&Window {
                            stream: chunk.stream,
                            credit: granted,
                        })?,
                    ));
                }
            }
            kind::CLOSE => {
                let c: Close = frame.decode()?;
                if c.stream == id.0 {
                    peer_closed = true;
                }
                reply.push((kind::CTRL_ACK, encode(&CtrlAck { seq: frame.seq })?));
            }
            _ => {}
        }
        write_out(&mut d.socket, &d.keys, d.version, &mut seq, reply).await?;
    }

    if got != data.len() {
        return Err(format!("the echo is {got} bytes, expected {}", data.len()).into());
    }
    Ok(summary)
}

/// Frame each body under the session's keys and write it, numbering the frames as they go out.
async fn write_out(
    socket: &mut TcpStream,
    keys: &LinkKeys,
    version: u16,
    seq: &mut u64,
    out: Vec<(u8, Vec<u8>)>,
) -> Result<(), Fail> {
    let tunnel = Tunnel::sender(keys);
    for (k, body) in out {
        let frame = Frame {
            version: version as u8,
            kind: k,
            flags: 0,
            seq: *seq,
            body,
        };
        *seq += 1;
        write_frame(socket, &tunnel, &frame).await?;
    }
    Ok(())
}
