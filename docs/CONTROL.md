# Controlling TransferDaemon: the control hub, the CLI, MCP, and driving the GUI and TUI

Everything TransferDaemon does can be done from outside, by a script, another program or an AI agent:

- the daemon's whole API (47 gRPC calls);
- its window;
- its terminal UI;
- local relays.

All of it goes through one place, the **control hub**, which runs inside the daemon.

```
            transferd-cli ─┐                    ┌─ gRPC (account, contacts, groups, messages, transfers,
   MCP clients (stdio) ────┤                    │        connections, settings, calls, telemetry, updates)
  ABP, scripts (HTTP) ─────┼── control hub ─────┤
   MCP clients (HTTP) ─────┘  (in transferd)    ├─ the window (transferd-ui attaches)   gui.*
                                                ├─ the terminal UI (transferd-tui attaches)   tui.*
                                                └─ local relays (relayd, relayd-ws, dhtd)   relay.*
```

## The hub

The hub listens on `127.0.0.1:50060` by default. `TRANSFERD_CONTROL_ADDR` moves it, and `TRANSFERD_CONTROL=off`
turns it off.

When it starts, it writes `control.json` (url, token, pid, version, gRPC address) next to the daemon's gRPC token:

- Windows: `%LOCALAPPDATA%\transferdaemon\`;
- Linux: `~/.local/share/transferdaemon/`;
- macOS: `~/Library/Application Support/transferdaemon/`;
- or `$TRANSFERD_DATA_DIR/transferdaemon/`.

Only the same user can read it. The hub removes the file when it stops, unless a newer daemon has already replaced it.

| Route | |
|---|---|
| `GET /v1/health` | `{ok, pid, version}`; the only route that needs no token |
| `GET /v1/operations` | the catalog: id, group, summary, mutating, destructive, streaming, input and output JSON Schemas |
| `GET /v1/operations/{id}` | one operation |
| `POST /v1/call/{id}` | run it; the body is its arguments. Returns `{result}` or `{error: {code, message}}` |
| `GET /v1/openapi.json` | every operation as OpenAPI 3.1 |
| `POST /mcp` | Model Context Protocol (Streamable HTTP, JSON replies); `?tools=compact` for two tools |
| `GET /v1/audit?limit=` | every call that changed something (secrets redacted) |
| `POST /v1/attach/{gui,tui}`, `GET .../next`, `POST .../reply`, `POST .../detach` | how the window and the TUI attach (long polling) |

How requests are checked:

- Every route except health needs the token, either as `Authorization: Bearer <token>` or as `X-TD-Token`.
- The token is compared in constant time.
- A request carrying a browser `Origin` is refused, so a web page cannot drive the daemon through the user's browser.
- Calls that change something are appended to `control-audit.jsonl`, with phrases, PINs and tokens redacted.

### Operations

- The **daemon API** is one operation per gRPC call, such as `messages.send_text`, `transfers.send_file`,
  `contacts.set_contact_address` and `telemetry.stream_telemetry`. Their schemas are built from `transferd.proto`
  itself, including the field comments. A test fails if the proto and the catalog disagree.
- **Streaming calls** collect events for `seconds` (default 5), up to `max`.
- **Enum fields** accept names as well as numbers, e.g. `role: "admin"`.
- `transfers.send_file` fills in the name, size and MIME type from the file.

The hub also has its own operations:

- `daemon.status`, `daemon.env` and `daemon.stop`;
- `gui.*`;
- `tui.*`;
- `relay.status`, `relay.start`, `relay.stop` and `relay.probe` (UDP challenge, WebSocket handshake, or TCP reachability).

## The window (`gui.*`)

`transferd-ui` attaches to the hub when it starts. `TRANSFERD_GUI_CONTROL=off` opts out. Everything happens inside
the window's normal frame loop, the way a person would do it:

- **Seeing.** `gui.inspect`, `gui.find` and `gui.wait` read every widget from the AccessKit tree egui builds each frame:
  role, label, value, checked, enabled and position.
  - Unlabeled text fields take the label a person reads beside or above them.
  - Icon-only buttons are also known by what they do (`➤` is "send", `📎` is "attach file"...).
- **Acting.** `gui.click`, `gui.set`, `gui.type`, `gui.key` and `gui.scroll` inject real input events before a frame.
  The pointer moves to the widget, then presses and releases over a few frames, so hover, focus and click handling run
  exactly as for a mouse.
- **Shortcuts.** `gui.navigate` and `gui.open_chat` go straight to a page or conversation.
- **The window itself.** `gui.screenshot` returns a PNG. `gui.window` can show, focus, minimize, maximize, restore,
  resize or close it.

`gui.launch` starts the window next to the daemon and waits until it has attached. Its output goes to
`transferd-ui.log`.

## The terminal UI (`tui.*`)

`transferd-tui` attaches the same way.

- **Headless mode.** `transferd-tui --headless --size 120x40` draws into memory instead of a terminal. That is the
  default for `tui.launch`, so it runs, and can be driven, where there is no console at all.
- **What it can do.** `tui.screen` returns exactly what is drawn, as text. `tui.key` and `tui.type` go through the same
  key handler as a real keyboard. `tui.navigate`, `tui.resize` (headless) and `tui.quit` are also available.
- **A visible TUI** (`tui.launch {headless: false}`) opens in its own console window on Windows and can be driven too.

## `transferd-cli`

```
transferd-cli status | id | contacts | add <key> <name> [addr] | address <contact> <addr|->
transferd-cli send <contact> <text...> | send-file <contact> <path> | messages <contact> [query]
transferd-cli transfers | pause|resume|cancel <id> | groups | group-send <group> <text...>
transferd-cli connections | settings get|set ... | telemetry [s] | audit [n]
transferd-cli ops [words] [--group g] | op <id> | call <id> [JSON | key=value...]
transferd-cli gui <action> [...] [--out shot.png] | tui <action> [...]
transferd-cli relay status|start|stop|probe ... | daemon start|stop|status
transferd-cli mcp [--tools all|compact]
```

- Contacts can be named by name, id, or a unique id prefix.
- `--json` prints raw JSON.
- `key=value` arguments are parsed as JSON where possible, and dotted keys build objects (`target.text=Send`).

## MCP

- **stdio:** `transferd-cli mcp`, with one tool per operation (`messages_send_text`, `gui_click`...). Add
  `--tools compact` for just `transferd_operations` and `transferd_call`.
- **HTTP:** `POST /mcp` on the hub, with the token.

Tools carry read-only and destructive hints. A screenshot comes back as an MCP image.

## Also in this release

- **Contacts have addresses.** `AddContactRequest.address`, `ContactReply.address` and `SetContactAddress`. The
  window's Address field used to be silently dropped.
- **The outbox.** A message or file sent while the peer cannot be reached waits in the outbox and goes out once a
  session exists, even after a restart. File paths are kept in the encrypted settings, so the store's schema did not
  change.
- **Transfers:**
  - the sender's progress counts the chunks the lanes dispatched, and the transfer completes on the receiver's
    acknowledgement;
  - the receiver's progress is shown as well;
  - pause and resume work for transfers that have not started;
  - cancel stops a waiting file.
- **Auto-unlock.** A restarted daemon unlocks its store by itself, from a recovery-phrase cache protected by DPAPI on
  Windows and owner-only elsewhere (`TRANSFERD_AUTO_UNLOCK=off` turns it off). Before this, a desktop daemon forgot its
  identity on every restart.
- **One data folder.** `TRANSFERD_DATA_DIR` now moves everything the daemon keeps: the store, token, telemetry,
  downloads and control file.
- **Window fixes:**
  - sending and the typing indicator no longer freeze the window while a peer is reached;
  - arrows, check marks and the send glyph render (the system symbol font is used as a fallback);
  - the message box no longer pushes the send button off screen;
  - the accent color and chat scrolling no longer trip egui's debug assertions.
- **Connection names.** Connections are named the way Windows names them ("Ethernet", "Wi-Fi") instead of by GUID.
