//! Interop peer for the Python and TypeScript implementations.
//!
//! Not part of the protocol API. It runs the reference's handshake and HELLO exchange over TCP, so
//! the other implementations can be tested against it in both directions.
//!
//! Run from the repository root:
//!
//!     cargo run -p transferd-overlay --example interop_peer -- serve <port> <seed-hex>
//!     cargo run -p transferd-overlay --example interop_peer -- dial <port> <seed-hex> <expected-node-id>
//!
//! `serve` binds 127.0.0.1:<port> (0 picks a free port), prints `{"listening": "<addr>"}`, accepts
//! one connection, answers one HELLO with a HELLO_ACK, and prints a summary of the session.
//! `dial` connects to 127.0.0.1:<port>, sends one HELLO, and prints the summary of the HELLO_ACK.
//! Each run prints JSON lines on stdout and exits non-zero on failure.

use std::error::Error;

use serde_json::json;
use tokio::net::{TcpListener, TcpStream};
use transferd_overlay::identity::NodeIdentity;
use transferd_overlay::protocol::{
    Frame, Hello, HelloAck, HelloExt, VERSION_CURRENT, VERSION_MIN, kind, negotiate,
};
use transferd_overlay::wire::{
    Tunnel, TunnelReader, handshake_initiator, handshake_responder, write_frame,
};

type Fail = Box<dyn Error>;

/// The nonce the dialling side sends in its HELLO, so the answer can be checked as a reply to it.
const DIAL_NONCE: [u8; 16] = [0x5a; 16];

#[tokio::main]
async fn main() -> Result<(), Fail> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("serve") if args.len() == 4 => serve(&args[2], &args[3]).await,
        Some("dial") if args.len() == 5 => dial(&args[2], &args[3], &args[4]).await,
        _ => Err("usage: interop_peer serve <port> <seed-hex> | dial <port> <seed-hex> <expected-node-id>".into()),
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

async fn serve(port: &str, seed_hex: &str) -> Result<(), Fail> {
    let me = identity(seed_hex, "interop-responder")?;
    let listener = TcpListener::bind(("127.0.0.1", port.parse::<u16>()?)).await?;
    println!("{}", json!({ "listening": listener.local_addr()?.to_string() }));

    let (mut socket, _) = listener.accept().await?;
    let session = handshake_responder(&mut socket, &me).await?;

    let mut inbound = TunnelReader::new(&session.keys);
    let hello_frame = inbound.next_frame(&mut socket).await?;
    if hello_frame.kind != kind::HELLO {
        return Err(format!("expected HELLO, got kind {:#04x}", hello_frame.kind).into());
    }
    let hello: Hello = hello_frame.decode()?;

    let agreed = negotiate(hello.min_version, hello.max_version, VERSION_MIN, VERSION_CURRENT);
    let ack = HelloAck {
        version: agreed.unwrap_or(0),
        node_id: me.node_id().to_string(),
        name: "interop-responder".into(),
        services: Vec::new(),
        nonce: hello.nonce,
        reason: if agreed.is_some() { String::new() } else { "no common version".into() },
        ext: Vec::new(),
    };
    let frame = Frame::new(2, kind::HELLO_ACK, 1, &ack)?;
    write_frame(&mut socket, &Tunnel::sender(&session.keys), &frame).await?;

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
