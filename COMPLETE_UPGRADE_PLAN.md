# TransferDaemon — Complete Comms Upgrade Plan

This document tracks the actual state of the codebase against the original UPGRADE_PLAN.md, then defines the remaining real gaps and phases required to fulfill the vision: **complete Signal/Telegram/WhatsApp/Discord parity, plus next-generation enhancements**.

---



## Verified Current State

| Area | Status | Evidence |
|------|--------|----------|
| Transfer cancel / pause / resume | ✅ Wired | `home.rs:show_transfers()` handles `TransferActionKind::{Cancel,Pause,Resume}` and calls `DaemonApi` directly |
| OS notifications / new message toast | ✅ Wired | `app.rs:diff_and_notify()` already detects new messages by per-contact timestamp and fires `NotificationLevel::NewMessage` |
| Release profile optimization | ✅ Done | `Cargo.toml` has `[profile.release]` with LTO/fat/strip/panic=abort |
| Chat attachment button | ✅ Present | `chat.rs` has `📎` toggle, file path input, `send_file()` flow |
| Chat search UI | ✅ Present | Chat header already has search UI with `search_query` filtering in message render loop |
| Drag-and-drop file | ✅ Present | `app.rs` handles `DroppedFile` events to chat's `pending_file_path` |
| Keyboard shortcuts | ✅ Present | `Ctrl+N`, `Ctrl+,`, `Escape`, `Ctrl+Tab`, etc. already implemented |
| Encrypted persistent store | ✅ Present | `transferd-store` crate with write-through snapshot from daemon state, loaded by identity phrase |
| WebRTC call signaling + desktop capture | ✅ Present | `transferd-webrtc` crate, desktop-capture feature |
| TUI + terminal video | ✅ Present | `transferd-tui`, `transferd-tui-video` |
| Android/iOS mobile scaffold | ✅ Partial | Android camera/mic noted in README; iOS is still a stub |
| gRPC services | ✅ Present | 6 services: Account, Friend, Message, Transfer, Settings, Call |
| Blind relay | ✅ Present | `relayd` crate with BLAKE3 PoW |
| DMI ring / crypto core | ✅ Present | `ring-channel`, `transferd-crypto`, `transferd-core` |
| Tests / pentest | ✅ Present | README/PLAN claim 130+ tests and 22 pentest scenarios |

---



## Real Gap Delta vs. UPGRADE_PLAN

The following items from the original `UPGRADE_PLAN.md` are **still missing real implementation**:

### Persistence gaps
- Reusable `search_messages(contact_id_or_thread_id, query)` RPC gRPC + UI backend for encrypted local full-text search
- Per-thread draft persistence backed by `transferd-store`
- Group/thread persistence schema in `transferd-store`
- Reliable message history ordering by `timestamp_ts` across sessions

### Media/messaging gaps
- Inline media preview: image/video thumbnails rendered inside `message_bubble` and click-to-expand viewer
- Voice/video message clips capture flow and in-chat playback with waveform scrubber
- Reactions, replies, mentions data model + UI
- Link previews mapper (opt-in local fetcher)

### Calling gaps
- Real WebRTC media stack replacing simulated session
- Adaptive bitrate driven by ECF-RG lane metrics
- Group calling / SFU relay lane
- Screen-share track
- Mute/deafen, noise suppression, background blur

### Groups/communities
- Persistent group/thread/channel data model
- Public server/channel hierarchy
- Permissions model
- Bot webhook adapter

### UX gaps
- True cross-device identity sync via QR
- Linked-device pairing flow
- E2E safety number verification
- Export/import identity blob
- Delete identity flow
- Export archive format

### Security gaps
- Full Double Ratchet + X3DH replacing static hybrid session
- Verified contacts with safety numbers
- Sealed/anonymous sender extension
- App lock biometric path
- Ephemeral session mode

### Advanced transport gaps
- Real swarm/DHT lane implementation
- Completed Tor/onion transport
- Multi-relay fallback engine

### Developer/bridge gaps
- Bridge framework adapters
- Plugin transport hot-reload rules
- Automation DSL

### Packaging/ops gaps
- Auto-updater implementation
- Reproducible builds pipeline
- Crash/telemetry handler
- Fuzzing harness integration
- CI workflow file

### 100-year protocol gaps
- Self-describing message envelope with crypto lineage
- Hash-chain conversation log
- Ciphersuite sunset negotiation
- Reference decoder `tools/tdecode.py`

---



## Remaining Implementation Plan

### Phase 0 — Off-by-One Fixes & Foundations
**Goal**: close remaining real P0 gaps.

1. Implement `search_messages` RPC in `transferd.proto` -> gRPC -> `DaemonApi` -> UI
2. Add drafts persistence schema in `transferd-store`
3. Wire message history ordering from persisted store into initial UI load
4. Verify all 130+ tests remain green; add missing coverage for state restore

### Phase 1 — Rich Media Messenger
**Goal**: match WhatsApp/Telegram signal-quality messaging.

1. Implement media thumbnail pipeline in `transferd-media`
2. Render inline media previews in `message_bubble`
3. Add reactions/replies/mentions to `MessageContent` + UI
4. Add voice/video message clips + local playback

### Phase 2 — Calling Upgrade
**Goal**: replace simulated session with real media + adaptive bitrate.

1. Start `transferd-voip` crate
2. Integrate WebRTC stack + SRTP
3. Add group calling SFU lane
4. Implement screen-share track

### Phase 3 — Groups / Communities
**Goal**: Discord-grade channels.

1. Add `Group`, `Channel`, `Server`, `Role` schemas to `transferd-store`
2. Build server/channel sidebar UI
3. Implement permissions scoping

### Phase 4 — Security Hardening
**Goal**: post-quantum + double ratchet + verified contacts.

1. Implement X3DH handshake in `transferd-crypto`
2. Implement Double Ratchet in `transferd-core`
3. Add verified contacts + safety numbers UI
4. Add biometrics-backed app lock path

### Phase 5 — Transport Future-Proofing
**Goal**: close remaining transport gaps.

1. Replace swarm stub with real DHT lane
2. Complete `tor_lane.rs`
3. Add multi-relay fallback selector

### Phase 6 — Developer Platform
**Goal**: bridges + automation.

1. Build local-only bridge framework
2. Build plugin transport loader
3. Build rules DSL

### Phase 7 — Packaging & Observability
**Goal**: craftsmanship at scale.

1. Implement GitHub Actions CI workflow
2. Implement auto-updater channel
3. Implement crash dumps + telemetry handler
4. Integrate `proptest` fuzz targets

### Phase 8 — 100-Year Protocol
**Goal**: durability guarantee.

1. Embed `crypto_lineage` in every message
2. Build hash-chain log
3. Deliver `tools/tdecode.py`
4. Implement sunset mechanism

---



## Suggested Execution Order

| Week | Focus | Expected outcome |
|------|-------|------------------|
| 1 | Phase 0 foundations | Tests pass, search RPC wired, drafts exist |
| 2–3 | Phase 1 media | Inline previews, reactions, replies, mentions shipped |
| 3–4 | Phase 2 calling | Real media stack replacing simulation |
| 5–6 | Phase 3 communities | Servers, channels, threads, roles |
| 5–6 | Phase 4 security | Double Ratchet + verified contacts |
| 7 | Phase 5 transport | DHT + Tor + relay fallback |
| 8 | Phase 7 packaging | CI/crash reports/updater |
| 9+ | Phase 6 + Phase 8 | Bridges, plugins, 100-year durability |

---



## How to Proceed

If you want, I can start Phase 0 tonight with one concrete deliverable: **“Wire `search_messages` RPC end-to-end and show real messages in search results.”** This is a single, testable change that unblocks later media/community work because message history becomes queryable.
