//! Writes `vectors/wire.json`: the reference implementation's bytes for the overlay's wire formats
//! (tunnel frames, overlay frames, invites, hole-punch probes, relay messages and padding). The
//! Python and TypeScript implementations check their own output against this file.
//!
//! Run from the repository root:
//!
//!     cargo run -p transferd-overlay --example gen_wire_vectors -- vectors/wire.json
//!
//! Every value is fixed except the invite nonce and expiry, which are random per invite. Those
//! vectors are checked for their signature and fields, not for fixed bytes.

use std::fmt::Write as _;

use relayd::pow;
use relayd::protocol as rp;
use transferd_overlay::identity::{
    NodeIdentity, accept_invite, base64_url_decode, base64_url_encode, make_invite_with_nonce,
};
use transferd_overlay::protocol::{
    Ack, AckBase, Candidate, Close, CtrlAck, Data, Frame, Hello, HelloAck, HelloExt, Open,
    OpenErr, OpenOk, Ping, Pong, PunchMsg, RouteReport, Routes, ServiceInfo, Window, kind,
};
use transferd_overlay::punch::{PunchKeys, Probe, ProbeKind, encode_probe};
use transferd_overlay::relay::pad;
use transferd_overlay::wire::{Tunnel, derive_link_keys};

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// A recognisable, non-trivial byte pattern.
fn pattern(len: usize, tag: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(13).wrapping_add(tag))
        .collect()
}

fn pattern32(tag: u8) -> [u8; 32] {
    pattern(32, tag).try_into().expect("32 bytes")
}

fn frame_entry(name: &str, f: &Frame) -> String {
    format!(
        r#"    {{"name": "{name}", "kind": {}, "version": {}, "flags": {}, "seq": {}, "body": "{}", "frame": "{}"}}"#,
        f.kind,
        f.version,
        f.flags,
        f.seq,
        hex(&f.body),
        hex(&f.encode()),
    )
}

fn main() {
    let out_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "vectors/wire.json".to_string());
    let mut sections: Vec<String> = Vec::new();

    // --- Tunnel (§2): per-direction keys and sealed frames with counters 0, 1, 2 ------------
    let session = pattern32(40);
    let keys = derive_link_keys(&session);
    let tx = Tunnel::sender(&keys);
    let mut tunnel_frames = Vec::new();
    for (i, len) in [0usize, 1, 17, 200].into_iter().enumerate() {
        let plain = pattern(len, 50 + i as u8);
        let sealed = tx.seal(&plain).expect("seal");
        tunnel_frames.push(format!(
            r#"      {{"counter": {i}, "plaintext": "{}", "sealed": "{}"}}"#,
            hex(&plain),
            hex(&sealed),
        ));
    }
    sections.push(format!(
        r#"  "tunnel": {{
    "session_key": "{}",
    "c2s": "{}",
    "s2c": "{}",
    "frames": [
{}
    ]
  }}"#,
        hex(&session),
        hex(&keys.send),
        hex(&keys.recv),
        tunnel_frames.join(",\n"),
    ));

    // --- Overlay frames (§4) and their bodies (§5) -------------------------------------------
    let node_a = "ab".repeat(32);
    let node_b = "cd".repeat(32);
    let services = vec![ServiceInfo {
        name: "chat".into(),
        description: "text".into(),
    }];
    let ext = HelloExt {
        pairing: Some([7u8; 16]),
        direct: vec!["192.0.2.1:4000".into()],
    };
    let ext_bytes = bincode::serialize(&ext).expect("ext");
    let mut frames = Vec::new();
    frames.push(frame_entry(
        "HELLO",
        &Frame::new(
            2,
            kind::HELLO,
            1,
            &Hello {
                min_version: 1,
                max_version: 3,
                node_id: node_a.clone(),
                name: "node-a".into(),
                services: services.clone(),
                ext: ext_bytes.clone(),
                nonce: [9u8; 16],
            },
        )
        .expect("HELLO"),
    ));
    frames.push(frame_entry(
        "HELLO_ACK",
        &Frame::new(
            2,
            kind::HELLO_ACK,
            2,
            &HelloAck {
                version: 2,
                node_id: node_b.clone(),
                name: String::new(),
                services: Vec::new(),
                nonce: [9u8; 16],
                reason: String::new(),
                ext: Vec::new(),
            },
        )
        .expect("HELLO_ACK"),
    ));
    frames.push(frame_entry(
        "OPEN",
        &Frame::new(
            2,
            kind::OPEN,
            3,
            &Open {
                stream: 3,
                service: "chat".into(),
                node_id: node_a.clone(),
            },
        )
        .expect("OPEN"),
    ));
    frames.push(frame_entry(
        "OPEN_OK",
        &Frame::new(
            2,
            kind::OPEN_OK,
            4,
            &OpenOk {
                stream: 3,
                route: "relay".into(),
            },
        )
        .expect("OPEN_OK"),
    ));
    frames.push(frame_entry(
        "OPEN_ERR",
        &Frame::new(
            2,
            kind::OPEN_ERR,
            5,
            &OpenErr {
                stream: 3,
                code: "denied".into(),
                reason: "nope".into(),
            },
        )
        .expect("OPEN_ERR"),
    ));
    frames.push(frame_entry(
        "DATA",
        &Frame::new(
            2,
            kind::DATA,
            6,
            &Data {
                stream: 3,
                seq: 5,
                fin: false,
                payload: b"hello".to_vec(),
            },
        )
        .expect("DATA"),
    ));
    frames.push(frame_entry(
        "DATA_FIN",
        &Frame::new(
            2,
            kind::DATA,
            7,
            &Data {
                stream: 3,
                seq: 6,
                fin: true,
                payload: Vec::new(),
            },
        )
        .expect("DATA_FIN"),
    ));
    frames.push(frame_entry(
        "ACK",
        &Frame::new(
            2,
            kind::ACK,
            8,
            &Ack {
                stream: 3,
                seq: 6,
                sack: vec![(8, 10), (12, 13)],
            },
        )
        .expect("ACK"),
    ));
    frames.push(frame_entry(
        "ACK_BASE",
        &Frame::new(
            2,
            kind::ACK,
            9,
            &AckBase {
                stream: 3,
                seq: 6,
            },
        )
        .expect("ACK_BASE"),
    ));
    frames.push(frame_entry(
        "WINDOW",
        &Frame::new(
            2,
            kind::WINDOW,
            10,
            &Window {
                stream: 3,
                credit: 262_144,
            },
        )
        .expect("WINDOW"),
    ));
    frames.push(frame_entry(
        "CLOSE",
        &Frame::new(
            2,
            kind::CLOSE,
            11,
            &Close {
                stream: 3,
                code: "ok".into(),
                reason: "bye".into(),
            },
        )
        .expect("CLOSE"),
    ));
    frames.push(frame_entry(
        "CTRL_ACK",
        &Frame::new(2, kind::CTRL_ACK, 12, &CtrlAck { seq: 42 }).expect("CTRL_ACK"),
    ));
    frames.push(frame_entry(
        "PING",
        &Frame::new(
            2,
            kind::PING,
            13,
            &Ping {
                nonce: 7,
                sent_us: 1_234_567,
            },
        )
        .expect("PING"),
    ));
    frames.push(frame_entry(
        "PONG",
        &Frame::new(
            2,
            kind::PONG,
            14,
            &Pong {
                nonce: 7,
                sent_us: 1_234_567,
            },
        )
        .expect("PONG"),
    ));
    frames.push(frame_entry(
        "ROUTES",
        &Frame::new(
            2,
            kind::ROUTES,
            15,
            &Routes {
                routes: vec![RouteReport {
                    kind: "relay".into(),
                    rtt_ms: 12.5,
                    loss: 0.01,
                    mbps: 2.0,
                    active: true,
                    cwnd: 65_536,
                    in_flight: 1024,
                    srtt_ms: 13.0,
                    rto_ms: 300.0,
                    sent_bytes: 1000,
                    retx_bytes: 10,
                }],
            },
        )
        .expect("ROUTES"),
    ));
    frames.push(frame_entry(
        "CANDIDATE",
        &Frame::new(
            3,
            kind::CANDIDATE,
            16,
            &PunchMsg {
                id: 99,
                reply: false,
                nonce: [5u8; 32],
                candidates: vec![
                    Candidate {
                        addr: "203.0.113.7:50000".into(),
                        private: false,
                    },
                    Candidate {
                        addr: "10.0.0.2:50000".into(),
                        private: true,
                    },
                ],
            },
        )
        .expect("CANDIDATE"),
    ));
    frames.push(frame_entry("BYE", &Frame::bare(2, kind::BYE, 17)));
    let flagged = Frame::bare(2, kind::DATA, 18).mirrored().bulk();
    frames.push(frame_entry("flags_mirror_bulk", &flagged));
    sections.push(format!(
        "  \"hello_ext\": {{\"pairing\": \"{}\", \"direct\": [\"192.0.2.1:4000\"], \"bytes\": \"{}\"}},\n  \"frames\": [\n{}\n  ]",
        hex(&[7u8; 16]),
        hex(&ext_bytes),
        frames.join(",\n")
    ));

    // --- Invites (§6) -------------------------------------------------------------------------
    let id = NodeIdentity::from_seed(&pattern(64, 60).try_into().expect("64 bytes"), "alpha");
    let relay = "relay.example:4433".to_string();
    let direct = "192.0.2.10:4000".to_string();
    let (invite, nonce, expires_at) = make_invite_with_nonce(
        &id,
        vec![relay.clone()],
        vec![direct.clone()],
        86_400,
    );
    let verified = accept_invite(&invite).expect("the reference accepts its own invite");
    let body = invite.strip_prefix("tdov2:").expect("prefix");
    let json = String::from_utf8(base64_url_decode(body).expect("base64")).expect("utf8");
    let tampered_relays = format!(
        "tdov2:{}",
        base64_url_encode(json.replace(&relay, "evil.example:1").as_bytes())
    );
    let tampered_expiry = format!(
        "tdov2:{}",
        base64_url_encode(json.replacen(&format!("\"expires_at\":{expires_at}"), "\"expires_at\":1", 1).as_bytes())
    );
    let v1 = invite.replacen("tdov2:", "tdov1:", 1);
    let oversized = format!(
        "tdov2:{}",
        base64_url_encode(json.replacen("\"name\":\"alpha\"", &format!("\"name\":\"{}\"", "x".repeat(5000)), 1).as_bytes())
    );
    for refused in [&tampered_relays, &tampered_expiry, &v1, &oversized] {
        assert!(accept_invite(refused).is_err(), "the reference must refuse {refused:.40}");
    }
    sections.push(format!(
        r#"  "invite": {{
    "invite": "{invite}",
    "node_id": "{}",
    "name": "{}",
    "key_fingerprint": "{}",
    "nonce": "{}",
    "expires_at": {expires_at},
    "relays": ["{relay}"],
    "direct": ["{direct}"],
    "verified_name": "{}",
    "refused": [
      {{"case": "tampered_relays", "invite": "{tampered_relays}"}},
      {{"case": "tampered_expiry", "invite": "{tampered_expiry}"}},
      {{"case": "tdov1_prefix", "invite": "{v1}"}},
      {{"case": "oversized", "invite": "{oversized}"}}
    ]
  }}"#,
        id.node_id(),
        id.name(),
        hex(&verified_fingerprint(&id)),
        hex(&nonce),
        verified.name,
    ));

    // --- Hole-punch probes (§8) ----------------------------------------------------------
    let init_nonce = pattern32(70);
    let resp_nonce = pattern32(71);
    let punch_id: u64 = 0x0102_0304_0506_0708;
    let punch_keys = PunchKeys::derive(punch_id, &init_nonce, &resp_nonce);
    let mut material = Vec::new();
    material.extend_from_slice(&punch_id.to_be_bytes());
    material.extend_from_slice(&init_nonce);
    material.extend_from_slice(&resp_nonce);
    let probe_key = blake3::derive_key("transferd-overlay-punch-probe-v1", &material);
    let link_key = blake3::derive_key("transferd-overlay-punch-link-v1", &material);
    let link_tunnel = derive_link_keys(&link_key);
    let probes = [
        (ProbeKind::Probe, true, 3u32),
        (ProbeKind::Probe, false, 4),
        (ProbeKind::Reply, true, 5),
        (ProbeKind::Reply, false, 6),
    ]
    .iter()
    .map(|(kind_, from_initiator, seq)| {
        let probe = Probe {
            kind: *kind_,
            from_initiator: *from_initiator,
            id: punch_id,
            seq: *seq,
        };
        format!(
            r#"      {{"kind": "{}", "from_initiator": {from_initiator}, "seq": {seq}, "datagram": "{}"}}"#,
            match kind_ {
                ProbeKind::Probe => "probe",
                ProbeKind::Reply => "reply",
            },
            hex(&encode_probe(&punch_keys, &probe)),
        )
    })
    .collect::<Vec<_>>();
    sections.push(format!(
        r#"  "punch": {{
    "id": {punch_id},
    "initiator_nonce": "{}",
    "responder_nonce": "{}",
    "probe_key": "{}",
    "link_key": "{}",
    "link_c2s": "{}",
    "link_s2c": "{}",
    "probes": [
{}
    ]
  }}"#,
        hex(&init_nonce),
        hex(&resp_nonce),
        hex(&probe_key),
        hex(&link_key),
        hex(&link_tunnel.send),
        hex(&link_tunnel.recv),
        probes.join(",\n"),
    ));

    // --- Relay padding and encapsulation (§3) -------------------------------------------
    let pads = [0usize, 1, 59, 60, 61, 124, 125, 500]
        .iter()
        .map(|len| {
            let data = pattern(*len, 80);
            format!(
                r#"      {{"input": "{}", "padded": "{}"}}"#,
                hex(&data),
                hex(&pad(&data)),
            )
        })
        .collect::<Vec<_>>();
    let token = pattern32(90);
    let mut payload_body = vec![0x02u8];
    payload_body.extend_from_slice(&token);
    payload_body.extend_from_slice(&pattern(100, 91));
    sections.push(format!(
        "  \"padding\": [\n{}\n  ],\n  \"payload\": {{\"prefix\": 2, \"sender_token\": \"{}\", \"body\": \"{}\", \"padded\": \"{}\"}}",
        pads.join(",\n"),
        hex(&token),
        hex(&payload_body[33..]),
        hex(&pad(&payload_body)),
    ));

    // --- Relay protocol messages (relayd) and proof of work ----------------------------
    let challenge: [u8; 16] = pattern(16, 100).try_into().expect("16 bytes");
    let nonce = (0u64..)
        .find(|n| pow::leading_zeros(8, &challenge, &token, *n))
        .expect("a nonce");
    let check_nonce = nonce.wrapping_add(1);
    let located_v4 = rp::LocatedMsg {
        self_addr: "203.0.113.5:4433".parse().expect("addr"),
        peer_addr: Some("198.51.100.9:50000".parse().expect("addr")),
        request: 5,
    };
    let located_v6 = rp::LocatedMsg {
        self_addr: "[2001:db8::1]:4433".parse().expect("addr"),
        peer_addr: None,
        request: 6,
    };
    let relay_msgs = [
        (
            "register",
            rp::encode(
                rp::Tag::Register,
                &rp::RegisterMsg {
                    session_token: token,
                    pow_nonce: nonce,
                    seq: 7,
                },
            ),
        ),
        (
            "forward",
            rp::encode(
                rp::Tag::Forward,
                &rp::ForwardMsg {
                    session_token: token,
                    pow_nonce: nonce,
                    sender_seq: 9,
                    ciphertext: pattern(40, 92),
                },
            ),
        ),
        (
            "keepalive",
            rp::encode(
                rp::Tag::Keepalive,
                &rp::KeepaliveMsg {
                    session_token: token,
                    pow_nonce: nonce,
                    seq: 8,
                },
            ),
        ),
        (
            "challenge",
            rp::encode(
                rp::Tag::Challenge,
                &rp::ChallengeMsg {
                    challenge,
                    expires_at: 1_900_000_000,
                    difficulty: 12,
                },
            ),
        ),
        (
            "locate",
            rp::encode(
                rp::Tag::Locate,
                &rp::LocateMsg {
                    self_token: token,
                    peer_token: pattern32(93),
                    pow_nonce: nonce,
                    seq: 11,
                },
            ),
        ),
        ("located_v4", rp::encode(rp::Tag::Locate, &located_v4)),
        ("located_v6", rp::encode(rp::Tag::Locate, &located_v6)),
        (
            "error",
            rp::encode(
                rp::Tag::Error,
                &rp::ErrorMsg {
                    code: rp::ErrorCode::TokenNotFound,
                    seq: 3,
                    detail: "no such token".into(),
                },
            ),
        ),
        (
            "ack",
            rp::encode(rp::Tag::Ack, &rp::AckMsg { sender_seq: 9 }),
        ),
        (
            "delivered",
            rp::encode(
                rp::Tag::Ack,
                &rp::DeliveredMsg {
                    sender_seq: 9,
                    ciphertext: pattern(40, 94),
                },
            ),
        ),
    ]
    .into_iter()
    .map(|(name, bytes)| {
        format!(
            r#"      {{"name": "{name}", "bytes": "{}"}}"#,
            hex(&bytes.expect("encode")),
        )
    })
    .collect::<Vec<_>>();
    sections.push(format!(
        r#"  "relay": {{
    "challenge": "{}",
    "token": "{}",
    "difficulty": 8,
    "valid_nonce": {nonce},
    "check_nonce": {check_nonce},
    "check_result": {},
    "messages": [
{}
    ]
  }}"#,
        hex(&challenge),
        hex(&token),
        pow::leading_zeros(8, &challenge, &token, check_nonce),
        relay_msgs.join(",\n"),
    ));

    let json = format!("{{\n{}\n}}\n", sections.join(",\n"));
    if let Some(dir) = std::path::Path::new(&out_path).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    std::fs::write(&out_path, json).expect("write vectors");
    println!("wrote {out_path}");
}

/// The fingerprint of an identity's hybrid public key, as the invite format defines it.
fn verified_fingerprint(id: &NodeIdentity) -> [u8; 32] {
    transferd_overlay::identity::key_fingerprint(&id.hybrid_public_key())
}
