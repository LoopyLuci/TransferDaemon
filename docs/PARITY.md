# Parity with cockroach, freenet/web, crosstalk and tailcat

What each project does well, what the matching TransferD capability is, and how far it has got. "Done" means built
and tested here; "Designed" means the shape is settled but not yet built.

| Project | What it does | TransferD's matching capability | State |
|---|---|---|---|
| **freenet/web** (Ghost Keys) | Anonymous identities vouched for by an issuer that never learns which key it signed: blind RSA signatures, tiered by donation | `transferd_crypto::ghostkey`: RFC 9474 RSABSSA-SHA384-PSS-Randomized. An issuer key per tier; Ed25519 ghost keys; certificates any RSA-PSS verifier accepts. `transferd-cli ghostkey issuer-new / request / sign / finish / verify` | **Done** (crate tests plus an end-to-end CLI run). **Relays**: `relayd` and `relayd-ws` accept `RegisterGhost` (tag 0x07: the usual registration with its PoW, plus a certificate from a trusted issuer and the ghost key's signature over this token and sequence number, so a seen certificate can't be reused). `RELAYD_GHOST_ISSUERS`, `RELAYD_REQUIRE_GHOST=1` (plain registrations get `GhostRequired`), and `RELAYD_GHOST_SESSIONS` (sessions per ghost key, default 8). Old clients are unaffected unless an operator requires ghost keys. The daemon's relay client registers with its ghost key when one is configured (`TRANSFERD_GHOST_FILE`, or `RelayClient::set_ghost`) |
| **tailcat** | netcat over WireGuard + DERP: two processes join through a short out-of-band address, NAT hole-punching, relay of last resort, no accounts | `transferd-cat` and `transferd-cli cat listen [--relay host:port]` / `cat <tdcat:address>`: a one-time address (relay, rendezvous token, 32-byte secret, the listener's direct endpoints) shared out of band. TransferD's hybrid X25519 + ML-KEM-768 handshake, keyed with the address secret (only its holder can connect; the relay sees opaque datagrams); AES-256-GCM per direction; the dialer tries the direct endpoints and the relay at once and keeps the first that answers; sequence numbers, cumulative acks, retransmission and end frames over UDP, both directions at once | **Done**: crate tests (2 MB each way direct, through relayd's own dispatch loop, a wrong secret refused) and real processes (relayd.exe + two transferd-cli: 10 MB intact both ways, 3.9 s direct, 11.4 s relayed, debug builds). Not yet: hole-punching between two NATed peers (today: a listener reachable directly, else the relay); relays limit datagrams per address (`RELAYD_RATE_PER_30S`, default 300) |
| **crosstalk** (Reticulum MeshChat) | LXMF messaging over Reticulum: store-and-forward propagation nodes, LoRa/packet radio/Iridium links, network map of interfaces and hops | A `reticulum` lane plugin (`ProtocolPlugin`, scheme `rns`) speaking Reticulum's TCP interface framing to a local `rnsd`; LXMF bridge for messages; a high-latency lane profile (bounded retries, no striping) for satellite links; Reticulum interfaces in the network view | **Designed** |
| **cockroach** | Raft-replicated, strongly consistent SQL; survives node loss; placement control | Device-group state (contacts, groups, settings, transfer catalogue) replicated across a person's own devices with Raft: one group per person, leader leases, linearizable reads. SQL-style queries over the catalogue through the control hub | **Designed**: transferd-store is single-device SQLite today |

## Notes

* A ghost certificate never reveals the person's TransferD identity. The ghost key is a separate Ed25519 key, and the
  issuer sees only a blinded value (tested: two requests for one key look unrelated, and the key's bytes never
  appear in a request).
* Issuers choose their own gate (a donation, an invite, proof of work). TransferD only verifies the certificate.
* "ADB" in the request is read as ABP (AgenticBotPlatform), which drives TransferDaemon as a module. If it meant
  Android Debug Bridge, the Android app's ADB-based test and deploy paths are the place.
