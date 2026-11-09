# PTP as an offline payload carrier in TransferDaemon

Status: design, not yet agreed. Branch `docs/ptp-lane-design`.
Scope: how Photon Transfer Protocol (PTP, `H:\Projects\photon-transfer-protocol`, `core/`) fits into
TransferDaemon / Transferd. Read alongside `CONTEXT.md` (decisions 3, 8, 20, 37).

## 1. Decision

PTP is **not** a `TransportLane`. It is a second kind of transfer medium, a **payload carrier**,
that sits beside the lane scheduler and carries whole file payloads, one way, with no acknowledgement path.

Why the lane trait does not fit. `TransportLane` (`transferd-core/src/transport.rs`) assumes:

- `send(Chunk)` followed by an `Ack { session_id, gsn }` control message. Acks advance the send base,
  free in-flight budget and drive retransmit.
- `ping()` / `Pong` for RTT, which the ECF-RG scheduler (`ate.rs`) reads per lane.
- `recv()` for inbound chunks on the same lane.

An optical link has none of these. Nothing flows back to the displaying device, so an ECF-RG lane would
retransmit onto a channel that can never acknowledge. Fountain coding removes the need for per-packet
retransmission, but it also means the sender never learns delivery. Implementing the trait would hide
that mismatch behind a fake ack and a fake RTT.

So the model is:

- **Lanes** (TCP, relay UDP, relay WS, DMI, ...) remain the online path, scheduled by ATE.
- **Carriers** (PTP optical, later a file/USB carrier) move a whole sealed transfer and report
  delivery only through a return message over an online lane.

## 2. Carrier abstraction

New module `transferd-core/src/carrier.rs`. Sketch, not final:

```rust
pub trait PayloadCarrier: Send + Sync {
    fn kind(&self) -> CarrierKind;            // Optical | FileDrop
    fn max_payload_bytes(&self) -> u64;       // bounded by throughput and the 200 MB outbox cap
    /// Turn one sealed transfer into the medium's units (PTP packets, or one file on disk).
    fn emit(&self, transfer: &SealedTransfer) -> Result<Vec<Vec<u8>>, CarrierError>;
    /// Feed one unit read from the medium. Ok(Some) once the transfer is complete and verified.
    fn ingest(&mut self, unit: &[u8]) -> Result<Option<VerifiedTransfer>, CarrierError>;
}
```

`SealedTransfer` and `VerifiedTransfer` are defined in TransferDaemon. `SealedTransfer` contains
the transfer id (the message id, see CONTEXT #37), the plaintext file bytes and the header in section 4.
PTP is one implementation, behind a `carrier-ptp` cargo feature so that default builds do not depend on it.

Receiver side: one `ingest` state per in-flight inbound transfer, keyed by transfer id. The PTP decoder
rejects a unit from a different transfer ("packet belongs to a different transfer"), so the receiver
routes each unit by its header before feeding it.

## 3. Selection policy

Per transfer, not per lane. A per-contact default can be overridden per send.

| Policy | Behaviour |
|---|---|
| `Online` (default) | Online lanes only. Current behaviour. |
| `OpticalIfOffline` | Online if a healthy ACK-capable lane exists; otherwise carrier. |
| `OpticalOnly` | Carrier only. The user explicitly chose the air gap. |

Rules:

- Never choose the carrier silently for an online peer. Bandwidth is 46 KB/s to 720 KB/s
  (PTP README), so an optical send is a deliberate act.
- Respect the peer's advertised `TransferLimits` (CONTEXT #31) and the carrier's own
  `max_payload_bytes`. Refuse early, before the sender renders anything.
- The carrier never sees a message that is still pending on an online lane, to avoid double delivery.

## 4. Handoff: what travels, and under which key

### 4.1 Payload header (new, inside the carrier payload)

PTP carries bytes only, so Transferd needs its own header. It is encoded before PTP sees the payload:

```
magic "TDCH"  | version u8 = 1 | header_len u32
transfer_id   16 bytes   (message id, see CONTEXT #37)
sender_pk     32 bytes   (Ed25519 node id)
file_sha256   32 bytes   (SHA-256 of the plaintext file)
size          u64
name, mime    length-prefixed UTF-8
then: file bytes
```

PTP's own SHA-256 covers the transmitted body and its GCM tag covers the ciphertext. `file_sha256`
is checked again after decryption, so the file is verified end to end regardless of PTP internals.

### 4.2 Key: no ratchet on the carrier

Do **not** run the payload through `DoubleRatchet`. CONTEXT #20 records that the ratchet assumes in-order
delivery, and a fountain decoder emits symbols in arbitrary order. Ratchet state would be lost or
corrupted by ordinary packet loss.

Instead, derive a per-transfer key from the established session root:

```
carrier_key = BLAKE3_derive_key("transferd carrier ptp v1", session_root || transfer_id)
```

Pass it as `SessionConfig.encryption_key` (`EncryptionKey([u8; 32])`). The receiver computes the same key
from its copy of the session root and the `transfer_id` in the header. Because the key is unique per
transfer, the nonce that PTP generates per body is safe.

Requirements:

- The receiver must already hold a session with the sender (the root exists only after a handshake).
  So the **first contact cannot happen optically** in this design (open decision D1).
- The session root must never leave the daemon. The carrier only sees the derived key.
- `compress` stays on in PTP for plaintext files. The PTP encode path already compresses before it encrypts.

`transferd-crypto` has no key-derivation helper for this today; `blake3` is used directly
(`auth_handshake.rs:127`). The label string is new and needs review.

## 5. Return path and "verified result"

The sender cannot observe the optical receive, so delivery is a message over an online lane:

1. The receiver's `ingest` returns `VerifiedTransfer` only after PTP's body SHA-256, the GCM tag and
   `file_sha256` have all passed.
2. The receiver stores the file through the existing inbound-file path (`write_inbound_file`,
   `transport.rs:314`) and sends a receipt over any online lane. The existing `send_read_receipt`
   (`transport.rs:345`) is the closest precedent; a new "carrier receipt" frame may be needed (D3).
3. The sender marks the transfer `Delivered` only when that receipt arrives. Until then the state is
   `CarrierSent`, which must not be shown as delivered.

Status names are not verified here. `transferd-store` owns the message/transfer state; the new state
needs a migration review.

## 6. Failure and fallback

| Failure | Behaviour |
|---|---|
| Receiver never completes (packets lost, user stops scanning) | Sender stays `CarrierSent`. No automatic re-emit. The user can re-emit, and the decoder can keep the transfer open. |
| `take_file` error (SHA mismatch, wrong key) | Drop the transfer state, surface "integrity failed", write no partial file. Session stays up. |
| Foreign or corrupt unit | Route error for that unit only. Log, skip, continue. |
| Online lane becomes available during `CarrierSent` | With `OpticalIfOffline`, the existing outbox retry may send over the lane. Dedupe on transfer id so the receiver writes the file once. |
| Receiver restarts mid-transfer | Decoder state is in memory only (`Decoder` has no serialisation). Restart means re-scan from the beginning (D4). |
| Peer key changed | Refused by the existing TOFU check (CONTEXT #15); the carrier does not bypass it. |

Lanes and carriers never fall back into each other mid-stream. A transfer is one or the other,
and a switch is a new transfer id.

## 7. What changes in each repo

### 7.1 photon-transfer-protocol (PTP)

- Done in this session (branch `feat/ptp-carrier-roundtrip`): a test that encrypted packets delivered in
  shuffled order decode exactly. This backs the claim in 4.2 that out-of-order arrival is safe for the
  codec. Existing tests already cover loss, duplicates, wrong key and foreign packets.
- Needed: a stable public API for the carrier (`encode` / `decode` with a caller-supplied key and
  symbol size), instead of reaching into `codec::*`. A minimal wrapper is enough.
- Needed: decoder state serialisation, for D4. Not started.
- Needed: correct the stale crate doc in `core/src/lib.rs`, which still says zstd and AES-GCM are not
  implemented. They are. Not changed here.
- Blocker for the optical end-to-end path: CGG rendering and camera scanning are not implemented
  (README "Status"). The file carrier (7.2, phase P1) does not need them.

### 7.2 TransferDaemon

- `transferd-core`: `carrier.rs` (trait + `FileDropCarrier`). The file carrier is first because it
  needs no optics and proves the header, key and receipt flow end to end.
- `transferd-core` with `carrier-ptp` feature: `PtpCarrier`, wrapping PTP.
- `transferd` (outbox / `send_file`, `grpc.rs:805`): select a carrier per policy in section 3.
- `transferd-store`: `CarrierSent` state and receipt handling.
- `transferd-api` proto: a send-policy field on `SendFileRequest`. Additive, so older clients still work.
- `transferd-crypto`: the carrier key-derivation helper and label.
- UI/TUI: show `CarrierSent` distinctly from `Delivered`.
- Dependency: pin PTP as a git dependency at a commit. Do not use a path dependency, which would tie
  two working trees together.

### 7.3 Transferd (protocol repo)

- The carrier payload header, the key-derivation label and the receipt frame are wire-level facts.
  CONTEXT says protocol changes are proposed in the protocol repo first.
- The local clone's `docs/PROTOCOL.md` is a 99-byte placeholder ("See the full specification at the end of
  this process..."), not a specification. The Transferd README links to it as canonical. Until that is
  fixed, the new wire facts have nowhere authoritative to land (D5).

## 8. Out of scope

- Cold-start pairing over optics (first contact without a prior session).
- Camera capture and CGG glyph rendering (PTP side, separate work).
- RaptorQ, QR fallback.
- Optical or file carrier used as a lane for chunked streams (only whole payloads).
- Bidirectional optical traffic. The return path stays online.
- Striping one transfer across an optical carrier and an online lane.
- Android JNI bridge for PTP, and mobile carriers.
- Changing the ratchet for unordered transports (we avoid the ratchet instead).

## 9. Phases

| Phase | Work | Verifiable by |
|---|---|---|
| P0 | Shuffled-delivery codec test (PTP) | `cargo test` in PTP (done, branch `feat/ptp-carrier-roundtrip`) |
| P1 | `carrier.rs`, `FileDropCarrier`, payload header, receipt, `CarrierSent` state. Carrier = directory of packet files. | TransferDaemon unit tests + two-daemon test over a temp dir |
| P2 | Per-transfer key derivation; `PtpCarrier` behind feature | Round-trip through PTP with a derived key |
| P3 | Policy field in proto, UI/TUI state | Existing gRPC integration tests plus new cases |
| P4 | PTP decoder persistence; CGG render + camera scan | PTP tests; device test (out of this session) |

## 10. Open decisions for the user

- **D1.** Is first contact over optics needed? If yes, a separate handshake-over-carrier is required,
  which is a larger protocol change. This design assumes an existing session.
- **D2.** Should the receipt frame be a new kind, or can an existing message receipt carry the transfer id?
- **D3.** Is the file carrier (P1, USB or folder copy) acceptable as the first carrier, or is optical
  the only target? The design assumes P1 first.
- **D4.** Decoder persistence: needed for long optical transfers. Yes/no, and where is state kept?
- **D5.** The Transferd protocol spec is a placeholder in the local clone. Should it be restored from
  TransferDaemon's `docs/` before wire changes are proposed there?
- **D6.** Is the "optical only when the user chooses" rule the right default? The alternative is
  `OpticalIfOffline` on by default for contacts that have no online lane.
- **D7.** Who owns `CONTEXT.md` updates for the carrier decisions (carrier vs lane, no ratchet on carrier)?
  Proposed: a new decision entry 39 in this repo, written when P1 lands.
