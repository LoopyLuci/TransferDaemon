# TransferDaemon Testing Guide

## Quick Start

```powershell
# Run all automated tests
.\run_tests.ps1

# Run two-instance E2E test
.\test_e2e_two_instance.ps1 -SkipBuild
```

---

## 1. Automated Test Suite

### Unit Tests (59)

```powershell
cargo test --workspace --lib
```

| Crate | Tests | What it covers |
|-------|-------|----------------|
| `transferd-core` | 12 | Identity, contacts, messages, store, crypto helpers |
| `transferd-crypto` | 8 | AES-256-GCM, X25519, ML-KEM-768, key derivation |
| `transferd-relay` | 14 | DHT routing, relay protocol, token bucket, engine |
| `transferd` | 8 | Backup format, mesh network, config |
| `transferd-grpc` | 6 | Protocol buffers, gRPC codec |
| `transferd-ui-shared` | 11 | DB queries, encryption utils, types |

### Integration Tests (34)

```powershell
cargo test --workspace
```

| Test file | Tests | What it covers |
|-----------|-------|----------------|
| `e2e_full_stack.rs` | 5 | Full pipeline: identity → contacts → encrypt → send → receive → decrypt |
| `e2e_lossy_transfer.rs` | 3 | Message delivery under packet loss |
| `e2e_zero_copy.rs` | 2 | Zero-copy buffer paths |
| `relay_integration.rs` | 4 | Relay connect/forward/disconnect |
| `relay_mesh_integration.rs` | 4 | Mesh topology with multiple relays |
| `tcp_lane_integration.rs` | 3 | Direct TCP lane setup/teardown |
| `dual_lane_ate.rs` | 4 | ATE scheduler with TCP + relay lanes |
| `multipath_relay.rs` | 3 | Multi-hop relay routing |
| `handshake_integration.rs` | 3 | PQ+classical handshake |
| `crypto_roundtrip.rs` | 3 | Key exchange → session → encrypt/decrypt |

### Fuzz Tests (requires nightly + Linux)

```bash
# Run each fuzzer for 100k iterations
rustup run nightly cargo fuzz run fuzz_relay_protocol -- -runs=100000
rustup run nightly cargo fuzz run fuzz_handshake -- -runs=100000
rustup run nightly cargo fuzz run fuzz_backup -- -runs=100000
```

### Benchmarks

```powershell
cargo bench --workspace
```

| Benchmark | What it measures |
|-----------|------------------|
| `aes_256_gcm_encrypt` | AES-256-GCM throughput (64KB blocks) |
| `relay_encode_decode` | Relay protocol frame latency |

### Linting

```powershell
cargo clippy --workspace -- -D warnings
```

---

## 2. GUI Test Checklist

### 2.1 Onboarding Flow

| # | Test | Steps | Expected Result |
|---|------|-------|-----------------|
| OB-1 | Create identity | Launch app → enter name → click "Create" | 12-word mnemonic phrase displayed |
| OB-2 | Copy phrase | Click "Copy" button | Feedback says "Copied!" |
| OB-3 | Restore identity | Go back → "Restore from phrase" → paste 12 words | Returns to home screen |
| OB-4 | Invalid phrase | Type garbage → click "Restore" | Error message shown, no crash |
| OB-5 | Empty name | Leave name blank → click "Create" | Error shown or button disabled |

### 2.2 Home / Contacts Screen

| # | Test | Steps | Expected Result |
|---|------|-------|-----------------|
| HM-1 | Default state | After onboarding | Shows empty contacts, "No contacts yet" placeholder |
| HM-2 | Add contact | Click "Add Contact" → enter valid 64-char hex + name + addr → OK | Contact appears in list |
| HM-3 | Invalid hex | Enter short hex → click OK | Error: "Invalid public key" |
| HM-4 | Duplicate contact | Add same contact twice | Error: "Contact already exists" |
| HM-5 | Delete contact | Right-click / long-press contact → Delete | Contact removed from list |
| HM-6 | Click contact | Click on contact | Opens chat view |
| HM-7 | Online indicator | Contact with active daemon | Shows green dot |

### 2.3 Chat View

| # | Test | Steps | Expected Result |
|---|------|-------|-----------------|
| CH-1 | Send text | Type message → press Enter | Message appears as bubble, sent with `√` |
| CH-2 | Sent time | Hover over sent message | Shows timestamp |
| CH-3 | Message ordering | Send 3 messages | Preserved chronological order |
| CH-4 | Long message | Paste 1000+ characters | Render without lag, no overflow |
| CH-5 | Unicode/emoji | Send "Hello 👋 world" | Renders correctly |
| CH-6 | Send file | Click attach → select file | Progress bar appears (see TG-1) |
| CH-7 | Back button | Click back arrow | Returns to contact list |
| CH-8 | Empty chat | Open new contact | Shows "No messages yet" |

### 2.4 File Transfers

| # | Test | Steps | Expected Result |
|---|------|-------|-----------------|
| TG-1 | Send file progress | Send a file (≥10 MB) | Progress bar advances smoothly |
| TG-2 | Cancel transfer | Click cancel during transfer | Transfer stops, no orphan state |
| TG-3 | Receive file | Accept incoming transfer | File saves to downloads folder |
| TG-4 | Large file | Send 1 GB file | No OOM, progress continues |
| TG-5 | Multiple transfers | Send 3 files simultaneously | All show progress, no overlap |

### 2.5 Settings

| # | Test | Steps | Expected Result |
|---|------|-------|-----------------|
| ST-1 | Display identity | Open Settings tab | Public key shown as 64-char hex |
| ST-2 | Copy identity | Click "Copy" next to key | Feedback "Copied!" |
| ST-3 | Change name | Edit name → save | Name updates everywhere |
| ST-4 | Theme toggle | Appearance → switch Dark↔Light | All pages render in new theme |
| ST-5 | Large fonts | Accessibility → increase font size | Text scales, no clipping |
| ST-6 | QR code | Click "Show QR Code" | QR renders, scannable by phone |

### 2.6 Telemetry (daemon required)

| # | Test | Steps | Expected Result |
|---|------|-------|-----------------|
| TL-1 | CPU display | Open Telemetry tab | Shows current CPU % |
| TL-2 | Memory display | Open Telemetry tab | Shows RSS in MB |
| TL-3 | Uptime | Open Telemetry tab | Shows daemon uptime |
| TL-4 | Active transfers | While transferring | Shows transfer count |
| TL-5 | No daemon | Launch UI without daemon | Graceful "daemon unavailable" message |

### 2.7 Navigation & Edge Cases

| # | Test | Steps | Expected Result |
|---|------|-------|-----------------|
| NV-1 | Tab switching | Click Home → Chat → Settings → Telemetry → Home | Smooth transitions, no flicker |
| NV-2 | Window resize | Drag window to 800×600, then 2000×1200 | All elements reflow, no cutoff |
| NV-3 | High DPI | Launch on 4K display | Text renders sharp, no blur |
| NV-4 | Rapid click | Click buttons rapidly | No crashes, no double-trigger |
| NV-5 | No internet | Launch with network off | Shows offline indicator |

---

## 3. Two-Instance E2E Test

Run the automated two-instance test script:

```powershell
.\test_e2e_two_instance.ps1
```

This launches two daemon+UI pairs and walks through:
1. Create identity (Alice on UI1, Bob on UI2)
2. Copy public keys from Settings
3. Add each other as contacts
4. Send messages back and forth
5. Send a file

---

## 4. CLI/Headless Test

```powershell
# Start daemon
cargo run --release -p transferd -- 127.0.0.1:50051

# In another terminal, check it's listening:
netstat -an | findstr 50051
```

Test gRPC endpoints:
| Method | Tool | Command |
|--------|------|---------|
| GetVersion | grpcurl | `grpcurl -plaintext 127.0.0.1:50051 transferd.v1.Daemon/GetVersion` |
| GetIdentity | grpcurl | `grpcurl -plaintext 127.0.0.1:50051 transferd.v1.Daemon/GetIdentity` |
| ListContacts | grpcurl | `grpcurl -plaintext 127.0.0.1:50051 transferd.v1.Daemon/ListContacts` |

---

## 5. Performance & Stress Tests

| # | Test | Steps | Measure | Threshold |
|---|------|-------|---------|-----------|
| PS-1 | Daemon startup | Start daemon | Time to listen | < 200 ms |
| PS-2 | UI startup | Launch UI | Time to render | < 500 ms |
| PS-3 | Contact list (100) | Add 100 contacts | Scroll FPS | > 30 fps |
| PS-4 | Chat history (10K) | Load 10K messages | Scroll FPS | > 30 fps |
| PS-5 | Concurrent streams | Send 10 files at once | Throughput | Within 20% of single |
| PS-6 | Large contact hex | Create identity with max-length name | No crash | No panic |

---

## 6. Security Tests

| # | Test | Steps | Expected Result |
|---|------|-------|-----------------|
| SE-1 | Invalid handshake | Send malformed handshake | Connection rejected, no crash |
| SE-2 | Replay attack | Replay captured message | Rejected (nonce check) |
| SE-3 | Wrong key | Encrypt with wrong public key | Recipient cannot decrypt |
| SE-4 | Bad ciphertext | Tamper encrypted payload | Decrypt fails, no crash |
| SE-5 | Long-lived session | Keep connection 24h | Session still valid |

---

## 7. CI Pipeline

The `.github/workflows/ci.yml` runs on every push:

| Job | Runs | Artifacts |
|-----|------|-----------|
| `check` | `cargo check --workspace` | - |
| `test` | `cargo test --workspace` | - |
| `clippy` | `cargo clippy --workspace -- -D warnings` | - |
| `build` | `cargo build --release` | Binaries |
| `bench` | `cargo bench --workspace` | Benchmark results |
| `audit` | `cargo audit` | Security advisory report |

---

## Test Log Template

When filing a bug, include:

```
**Test ID**: CH-4
**Environment**: Windows 11, 32GB RAM, 4K display
**Steps**: Type long message, press Enter
**Actual**: Lag for 2s, then renders with horizontal overflow
**Expected**: Smooth render, text wraps
**Logs**: (paste from terminal)
```
