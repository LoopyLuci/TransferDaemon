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
//!
//! `serve` binds 127.0.0.1:<port> (0 picks a free port), prints `{"listening": "<addr>"}`, accepts
//! one connection, answers one HELLO with a HELLO_ACK, and prints a summary of the session.
//! `echo` does the same, then runs the stream side with the reference's own multiplexer: every
//! stream the peer opens for the service `echo` is echoed back, and the run ends at the peer's CLOSE.
//! `dial` connects to 127.0.0.1:<port>, sends one HELLO, and prints the summary of the HELLO_ACK.
//! Each run prints JSON lines on stdout and exits non-zero on failure.

use std::collections::{BTreeSet, HashSet};
use std::error::Error;

use serde::Serialize;
use serde_json::json;
use tokio::net::{TcpListener, TcpStream};
use transferd_overlay::identity::NodeIdentity;
use transferd_overlay::mux::{Mux, OutFrame, StreamId};
use transferd_overlay::protocol::{
    Ack, Close, CtrlAck, Data, Frame, Hello, HelloAck, HelloExt, Open, OpenErr, OpenOk,
    VERSION_CURRENT, VERSION_MIN, Window, kind, negotiate,
};
use transferd_overlay::wire::{
    LinkKeys, Tunnel, TunnelReader, handshake_initiator, handshake_responder, write_frame,
};

type Fail = Box<dyn Error>;

/// The nonce the dialling side sends in its HELLO, so the answer can be checked as a reply to it.
const DIAL_NONCE: [u8; 16] = [0x5a; 16];

#[tokio::main]
async fn main() -> Result<(), Fail> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("serve") if args.len() == 4 => serve(&args[2], &args[3], false).await,
        Some("echo") if args.len() == 4 => serve(&args[2], &args[3], true).await,
        Some("dial") if args.len() == 5 => dial(&args[2], &args[3], &args[4]).await,
        _ => Err("usage: interop_peer serve|echo <port> <seed-hex> | dial <port> <seed-hex> <expected-node-id>".into()),
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

async fn dial(port: &str, seed_hex: &str, expected: &str) -> Result<(), Fail> {
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

    println!(
        "{}",
        json!({
            "role": "initiator",
            "peer": ack.node_id,
            "peer_name": ack.name,
            "version": ack.version,
        })
    );
    Ok(())
}
