# TransferDaemon — Complete Upgrade & Enhancement Plan

This document catalogs every gap, missing feature, and long-term requirement discovered across the full codebase survey. Each item is scoped to concrete file changes and prioritized by user impact.

---

## How to read this plan

Each entry is tagged with:

- **P0** — Ship-blocking. Users notice the absence immediately.
- **P1** — Major quality gap. Degrades daily use.
- **P2** — Polishes the experience. Delightful when present.
- **P3** — Future-proofing. Matters at scale or over decades.

---

## Phase 1 — Fix Broken Things (P0)

### 1.1 Wire the cancel transfer button

The "X" button renders on every transfer bar but does nothing — `transfer_bar()` returns a `cancelled` boolean that is discarded.

**Files:** `crates/transferd-ui-shared/src/pages/home.rs:617`, `crates/transferd-ui-shared/src/widgets/transfer_bar.rs:58-72`

**Changes:**
1. Add `cancel_transfer(id: String) -> Result<(), DaemonError>` to `DaemonApi` trait (`daemon.rs`)
2. Implement in `GrpcDaemon` — call the daemon's `TransferServiceClient::cancel_transfer()` (needs new gRPC RPC in `transferd.proto`)
3. Implement in `MockDaemon`
4. Capture the return value in `show_transfers()` and call `cancel_transfer` when true
5. Update the transfer display to remove/ghost cancelled transfers

### 1.2 Wire new-message OS notifications

`diff_and_notify()` in `app.rs` only detects contacts coming online and transfer completion. It never fires a notification for actual new messages.

**Files:** `crates/transferd-ui-shared/src/app.rs`, `crates/transferd-ui-shared/src/pages/chat.rs`

**Changes:**
1. Add `last_msg_count: HashMap<String, u64>` tracking to `AppState` (or `diff_and_notify`)
2. In the periodic refresh, also fetch the latest message timestamp per contact via a lightweight RPC (e.g. `get_last_message_ts(contact_id)` in `DaemonApi`)
3. When a contact's latest message timestamp advances, fire `send_notification("New message from {name}", preview, NotificationLevel::NewMessage)`
4. On click of the notification, open the chat for that contact (platform-dependent; fallback to app focus)

### 1.3 Add release profile optimization

No `[profile.release]` section exists. Release builds use default `opt-level = 3` but lack LTO and other size/speed tuning.

**File:** `transferdaemon/Cargo.toml`

**Changes:**
```toml
[profile.release]
opt-level = 3
lto = "fat"
codegen-units = 1
strip = "symbols"
panic = "abort"
```

---

## Phase 2 — Core UX Gaps (P1)

### 2.1 Drag-and-drop file transfer

Users expect to drag files from Explorer/Finder into the chat window.

**Files:** `crates/transferd-ui-shared/src/pages/chat.rs`, `crates/transferd-ui-shared/src/app.rs`

**Changes:**
1. Handle `egui::Event::DroppedFile` in the app's `update()` method
2. If the current page is Chat and a file is dropped, populate `pending_file_path` and trigger `send_file`
3. Show a drop-target overlay highlight during drag (check `egui::Event::FileHover`)

### 1.2 Transfer queue management (pause/resume)

Cancel is the only transfer control. Users need pause and resume for managing bandwidth.

**Files:** `crates/transferd-ui-shared/src/daemon.rs`, `crates/transferd-ui-shared/src/grpc_daemon.rs`, `crates/transferd-ui-shared/src/widgets/transfer_bar.rs`, `crates/transferd-api/proto/transferd.proto`

**Changes:**
1. Add `pause_transfer(id)` / `resume_transfer(id)` to `DaemonApi` trait
2. Add corresponding gRPC RPCs to `transferd.proto` → implement in backend
3. Add pause/resume buttons to `transfer_bar` widget
4. Visually distinguish paused transfers (greyed out, "⏸ Paused" label)

### 2.3 Keyboard shortcuts

Only `Enter` to send exists.

**Files:** `crates/transferd-ui-shared/src/app.rs` (global shortcuts), `crates/transferd-ui-shared/src/pages/chat.rs`

**Changes:**
- `Ctrl+N` — new conversation / add contact
- `Ctrl+,` — open settings
- `Ctrl+Tab` / `Ctrl+Shift+Tab` — cycle tabs
- `Escape` — go back from chat to contact list
- `Ctrl+F` — search messages (when search is implemented)

### 2.4 Message search

No way to find old messages.

**Files:** `crates/transferd-ui-shared/src/pages/home.rs`, `crates/transferd-ui-shared/src/pages/chat.rs`, `crates/transferd-ui-shared/src/db.rs`

**Changes:**
1. Add search bar to Chat page header
2. Implement full-text search via SQLite FTS5 on the local `messages` table
3. Show matching messages with highlighted snippets
4. Filter contacts list when searching from home page

---

## Phase 3 — Advanced Features (P2)

### 3.1 Inline media preview

Image/video files appear as text descriptions only.

**Files:** `crates/transferd-ui-shared/src/widgets/message_bubble.rs`, `crates/transferd-ui-shared/src/pages/chat.rs`

**Changes:**
1. When a file transfer completes and the file is an image (by MIME type), load and display it inline using `egui::ColorImage` + `egui::TextureHandle`
2. Add thumbnail generation for large images (max 400px wide in chat)
3. Add click-to-expand overlay for full-size view
4. Video files show a play button overlay → future WebRTC or external player

### 3.2 Typing indicators

No way to see if the other person is typing.

**Files:** `crates/transferd-api/proto/transferd.proto`, `crates/transferd-ui-shared/src/pages/chat.rs`

**Changes:**
1. Add `TypingNotification { contact_id }` gRPC streaming message
2. Add `set_typing()` to `DaemonApi` (fires after 500ms of continuous input)
3. Show `"{name} is typing…"` in the chat header or input area
4. Auto-hide after 3 seconds of no typing signal

### 3.3 Read receipts

Currently shows a dot for Delivered but no Read indicator.

**Files:** `crates/transferd-ui-shared/src/widgets/message_bubble.rs:133-138`

**Changes:**
1. Add a second dot (or checkmark) when status transitions to `Read`
2. Show "Read at 14:32" on hover of the indicator
3. Visual: single checkmark = Sent, double checkmark = Delivered, blue double checkmark = Read

### 3.4 Export/import identity

No way to export identity as a file for backup or transfer to another device.

**Files:** `crates/transferd-ui-shared/src/pages/settings.rs`, `crates/transferd-ui-shared/src/daemon.rs`

**Changes:**
1. Add "Export Identity" button → saves encrypted identity blob (reuse backup format from `backup.rs`)
2. Add "Import Identity" button with file picker → decrypts and restores
3. Export includes: private key (encrypted), public key, display name, recovery phrase

### 3.5 Delete identity/data

No way for a user to delete their data.

**Files:** `crates/transferd-ui-shared/src/pages/settings.rs`, `crates/transferd-ui-shared/src/daemon.rs`

**Changes:**
1. Add "Delete Identity" with confirmation dialog ("This cannot be undone")
2. Calls `daemon.delete_identity()` + clears local DB
3. Returns to onboarding page

### 3.6 E2E identity verification (safety numbers)

Users have no way to verify they're talking to the right person.

**Files:** `crates/transferd-ui-shared/src/pages/settings.rs`, `crates/transferd-ui-shared/src/widgets/qr_widget.rs`, `crates/transferd-ui-shared/src/types.rs`

**Changes:**
1. Generate a 12-word safety number from the double-hash of both public keys: `BLAKE3(alice_pk || bob_pk)` take first 128 bits → BIP-39 encode
2. Display side-by-side in chat settings panel
3. Add verification toggle: "Verified" flag on `Contact`
4. QR code comparison: scan partner's QR, compare safety numbers

---

## Phase 4 — Privacy & Security Hardening (P2)

### 4.1 Double Ratchet (Perfect Forward Secrecy)

Currently session keys are static per handshake. A compromised long-term key reveals all past messages.

**Files:** `crates/transferd-core/src/`, `crates/transferd/src/handshake_manager.rs`, `crates/transferd/src/message_crypto.rs`

**Changes:**
1. Implement X3DH for initial key agreement (replaces simple handshake)
2. Implement Double Ratchet: DH ratchet + symmetric ratchet per message
3. Rotate session keys with every 100 messages or 24h, whichever comes first
4. Store old ratchet keys zeroized on rotation

### 4.2 Tor/Proxy transport

Users in restrictive networks cannot use the app.

**Files:** `crates/transferd-ui-shared/src/pages/settings.rs`, `crates/transferd/src/`

**Changes:**
1. Add SOCKS5 proxy settings to Settings page (host, port, auth)
2. Support `onion3:` addresses in contact addresses
3. Route gRPC and relay connections through the proxy
4. Future: embedded Tor client (via `arti` crate)

### 4.3 Hardware-bound keys

`KeyStore` trait exists in `transferd-crypto` but only `RamKeyStore` is implemented.

**Files:** `crates/transferd-crypto/src/keystore.rs`

**Changes:**
1. Implement `TpmKeyStore` for Windows TPM 2.0 via `tss-esapi` or WinRT
2. Implement `SecureEnclaveKeyStore` for macOS/iOS via `Security.framework`
3. Wire into identity creation flow — user chooses "Hardware-bound key" vs "Software key"

---

## Phase 5 — Quality Infrastructure (P2)

### 5.1 CI/CD pipeline

No CI/CD exists. Every commit is manually built and tested.

**Files:** `.github/workflows/ci.yml` (new), `.github/workflows/release.yml` (new)

**Changes:**
1. CI: `cargo check`, `test --workspace`, `clippy --workspace`, `bench --workspace`, `audit` on every push
2. Release: build all platform binaries on tag, upload as release artifacts
3. Fuzz: run fuzz targets on Linux for 10 minutes each

### 5.2 Property-based testing

No `proptest` usage anywhere.

**Files:** `Cargo.toml` (dev-deps), `crates/transferd-crypto/src/` (tests), `crates/transferd-relay/src/` (tests)

**Changes:**
1. Add `proptest = "1"` to workspace dev-deps
2. Test: random plaintexts × random keys → encrypt → decrypt → matches
3. Test: random valid/invalid handshake messages → no panic
4. Test: random byte sequences → relay protocol decode → no panic

### 5.3 GUI test harness

No automated way to test UI rendering.

**Files:** `crates/transferd-ui-shared/tests/` (new)

**Changes:**
1. Add `eframe::HardwareAcceleration::Off` screenshot tests using `egui_kittest`
2. Capture each page (onboarding, home, chat, settings) and compare to baseline
3. Add mock daemon with pre-seeded data for repeatable UI tests

### 5.4 Crash reporting (opt-in)

No crash handler. Panics produce no diagnostic data.

**Files:** `crates/transferd-ui/src/main.rs`, `crates/transferd/src/main.rs`

**Changes:**
1. Set `std::panic::set_hook` to capture panic info + last 100 log lines
2. Write crash dump to `~/.local/share/TransferDaemon/crash/` or `%APPDATA%/TransferDaemon/crash/`
3. On next launch, prompt user: "TransferDaemon crashed. Send diagnostic report?"
4. POST report to self-hosted endpoint (optional, configurable)

---

## Phase 6 — Global Reach (P3)

### 6.1 Internationalization (i18n)

All ~120 user-facing strings are hardcoded in English.

**Files:** All `.rs` files in `crates/transferd-ui-shared/src/`

**Changes:**
1. Add `rust-i18n` or `fluent-rs` to shared crate dependencies
2. Extract all user-facing strings into `.ftl` files
3. Ship initial translations: `en`, `de`, `fr`, `ja`, `zh`
4. Add a language picker in Settings page

### 6.2 Accessibility (a11y)

No screen reader support. Only the minimal egui defaults.

**Files:** `crates/transferd-ui/src/main.rs`, `crates/transferd-ui-shared/src/app.rs`

**Changes:**
1. Enable `accesskit` in eframe options (already in egui 0.28)
2. Set `ui.labelled_by()` and `ui.id()` on all interactive elements
3. Add ARIA roles via egui's accessibility node API
4. Keyboard navigation: tab order, focus rings, Enter/Space activation
5. Test with Windows Narrator, macOS VoiceOver, Linux Orca

### 6.3 macOS app store / iOS TestFlight

The `transferd-mobile` crate exists but iOS is a stub.

**Files:** `crates/transferd-mobile/src/ios_app.rs`, `installer/macos/`

**Changes:**
1. Finish iOS native shell: `UNUserNotificationCenter`, AVFoundation capture, Keychain identity storage
2. Create Xcode project wrapper for iOS app
3. macOS: wrap in `.xcworkspace` for App Store submission
4. Code signing for all platforms (Windows Authenticode, macOS notarization, Linux GPG)

---

## Phase 7 — 100-Year Protocol (P3)

### 7.1 Self-describing messages

Every message blob must carry its own decoder ring so future readers can decode it without the original protobuf schema.

**Changes:**
1. Embed **CBOR-encoded CDDL schema** in a preamble before every encrypted message
2. Add plain-text header: `TransferDaemon/v1|epoch:1829304050|cipher:X25519+MLKEM768|schema:cid:sha256:<hash>`
3. Store **canonical schema** as a standalone `schema.cddl` file in the repo and in every build artifact

### 7.2 Append-only message log

Messages should form an immutable chain, verifiable without any software.

**Changes:**
1. Each message header includes `parent: <BLAKE3 hash of previous message>`
2. The conversation log is a hash chain — tampering is detectable
3. Export format: standalone CBOR file containing the full chain + metadata

### 7.3 Threat model for archival

Write a document that assumes all current crypto is broken by 2100:

1. Which message fields reveal metadata even after decryption? (Length, timestamps, sender order)
2. How should someone in 2125 verify a message's integrity if the public key infrastructure no longer exists?
3. What should they know to attempt decryption if the KEM is broken but the symmetric cipher isn't?
4. Answer: every message should include a "crypto lineage" field: `{KEM: X25519+MLKEM768, KEM_OID: 1.3.6.1.4.1.54392.5.1858.1, SYMMETRIC: AES-256-GCM, SYMMETRIC_OID: 2.16.840.1.101.3.4.1.46, HASH: BLAKE3-256}` so a future attacker knows exactly what algorithms were used and can attempt to break them.

### 7.4 Reference decoder

A standalone tool that can extract plaintext from any TransferDaemon message with zero dependencies.

**File:** `tools/tdecode.py` (new)

**Changes:**
1. Write `< 100 lines of Python 3 stdlib` that:
   - Reads the CBOR preamble
   - Verifies the hash chain
   - Given a hex private key, decrypts the payload
   - Prints the plaintext
2. Include in every tagged release
3. `tools/tdecode.py --input message.bin --key deadbeef...`

### 7.5 Protocol sunset mechanism

Algorithm deprecation must be automatic, not manual.

**Changes:**
1. Every ciphersuite has a `sunset: u64` field (Unix timestamp)
2. Clients refuse to negotiate algorithms past their sunset date
3. The protocol negotiates the *most recent allowed algorithm* during handshake
4. When AES-256-GCM is deprecated in 2060, clients seamlessly migrate to the replacement
5. The `transferd-core` crate publishes a list of "currently safe" ciphersuites that can be updated independently of the app

---

## Summary by Impact

| Priority | Items | Effort | User impact |
|----------|-------|--------|-------------|
| **P0** | Cancel wiring, notifications, release profile | 2-3 days | Bug fixes |
| **P1** | Drag-drop, transfer queue, shortcuts, search | 1-2 weeks | Daily UX |
| **P2** | Media preview, typing, receipts, export, delete, verify, ratchet, Tor, HSM, CI, proptest, GUI tests, crash reports | 4-8 weeks | Professional quality |
| **P3** | i18n, a11y, macOS/iOS, self-describing messages, hash chain, reference decoder, sunset mechanism | 4-8 weeks | 100-year durability |

**Total estimated effort: 10-20 weeks for one developer.**

---

## Immediate next step

The P0 items take 2-3 days and remove the most visible bugs. Want me to start with **1.1 (cancel button)** and **1.2 (new-message notifications)**?
