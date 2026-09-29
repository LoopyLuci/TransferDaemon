//! Every operation TransferDaemon offers, described for machines (JSON Schemas) and runnable by id.
//!
//! Two kinds:
//! * **daemon operations**: one per gRPC call of the daemon (47 of them: account, contacts, groups, connections,
//!   messages, transfers, settings, calls, telemetry, updates). They are listed in [`RPCS`], checked against
//!   `transferd.proto` by a test, and run through [`call_rpc`] with the generated message types (serde on the prost
//!   structs turns JSON into requests and replies back into JSON).
//! * **control operations** (`daemon.*`, `gui.*`, `tui.*`, `relay.*`): implemented by the hub itself, listed in
//!   [`control_ops`].

use crate::schema::proto;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{json, Value};
use std::time::Duration;
use transferd_api::auth::AuthChannel;
use transferd_api::proto as pb;

/// One operation in the catalog.
#[derive(Debug, Clone, Serialize)]
pub struct Operation {
    pub id: String,
    pub group: String,
    pub summary: String,
    /// It changes something (anything that is not only a read).
    pub mutating: bool,
    /// It removes or replaces something that cannot be brought back from here.
    pub destructive: bool,
    /// A gRPC server stream: the call collects events for `seconds` (default 5) or until `max` events.
    pub streaming: bool,
    pub input: Value,
    pub output: Value,
    /// "grpc" (the daemon's API) or "control" (the hub: gui, tui, relays, the daemon process).
    pub kind: String,
    #[serde(skip)]
    pub rpc: Option<(&'static str, &'static str)>,
}

/// (service, rpc, summary). Types come from the proto; the dispatch table below maps them to Rust types.
pub const RPCS: &[(&str, &str, &str)] = &[
    ("AccountService", "GetIdentity", "This device's identity: whether it has one, its public key and display name"),
    ("AccountService", "CreateIdentity", "Create a new anonymous identity; returns its 12/24-word recovery phrase (replaces the current one)"),
    ("AccountService", "RestoreIdentity", "Restore an identity from its recovery phrase (replaces the current one)"),
    ("AccountService", "GetPublicKeyHex", "This identity's public key, hex (what friends add)"),
    ("FriendService", "GetContacts", "Every contact: id, name, online, last seen, blocked, typing"),
    ("FriendService", "AddContact", "Add a contact by their public key (hex), with a name and optionally their direct address"),
    ("FriendService", "RenameContact", "Rename a contact"),
    ("FriendService", "RemoveContact", "Remove a contact"),
    ("FriendService", "BlockContact", "Block a contact (no messages or calls from them)"),
    ("FriendService", "UnblockContact", "Unblock a contact"),
    ("FriendService", "GetSafetyNumber", "The safety number for a contact, to compare out of band, and whether it is verified"),
    ("FriendService", "SetContactAddress", "Set a contact's direct address (host:port of their listener, a LAN or Tailscale IP), or clear it"),
    ("GroupService", "CreateGroup", "Create a group with some contacts"),
    ("GroupService", "GetGroups", "Every group"),
    ("GroupService", "GetGroup", "One group: members and roles"),
    ("GroupService", "RenameGroup", "Rename a group"),
    ("GroupService", "AddMembers", "Add contacts to a group"),
    ("GroupService", "RemoveMembers", "Remove members from a group"),
    ("GroupService", "SetMemberRole", "Make a member owner, admin or member (role: 1 owner, 2 admin, 3 member, or the name)"),
    ("GroupService", "LeaveGroup", "Leave a group"),
    ("GroupService", "DeleteGroup", "Delete a group"),
    ("GroupService", "SendGroupText", "Send a text message to a group"),
    ("GroupService", "GetGroupMessages", "A group's messages"),
    ("ConnectionService", "ListConnections", "Every network path the daemon can use (Wi-Fi, Ethernet, USB, relay, direct...), with speed, RTT and policy"),
    ("ConnectionService", "SetConnectionPolicy", "Set a connection's policy: auto, direct, relay or stripe"),
    ("ConnectionService", "StreamConnectionStatus", "Live connection status (RTT, bandwidth, chunks in flight) for a few seconds"),
    ("MessageService", "GetMessages", "The messages with a contact"),
    ("MessageService", "SendText", "Send a text message to a contact (end-to-end encrypted), optionally as a reply"),
    ("MessageService", "SearchMessages", "Search the messages with a contact"),
    ("MessageService", "SendTyping", "Tell a contact you are (or stopped) typing"),
    ("MessageService", "ToggleReaction", "Add or remove an emoji reaction on a message"),
    ("TransferService", "GetTransfers", "Every file transfer: progress, speed, lanes in use"),
    ("TransferService", "SendFile", "Send a file to a contact (file_path; name, size and type are filled in from the file when left out)"),
    ("TransferService", "CancelTransfer", "Cancel a transfer"),
    ("TransferService", "PauseTransfer", "Pause a transfer"),
    ("TransferService", "ResumeTransfer", "Resume a paused or interrupted transfer"),
    ("SettingsService", "GetSetting", "Read a daemon setting by key (e.g. limits.call_kbps, app.lock.pin)"),
    ("SettingsService", "SetSetting", "Change a daemon setting"),
    ("CallService", "StartCall", "Start a voice or video call with a conversation (SDP offer as JSON)"),
    ("CallService", "AcceptCall", "Accept an incoming call (SDP answer as JSON)"),
    ("CallService", "RejectCall", "Reject an incoming call"),
    ("CallService", "EndCall", "End a call"),
    ("CallService", "SendIceCandidate", "Send an ICE candidate for a call"),
    ("CallService", "StreamCallEvents", "Call events (invites, accepts, ICE...) for a few seconds"),
    ("TelemetryService", "StreamTelemetry", "Live telemetry (system health, lane choices) for a few seconds"),
    ("TelemetryService", "GetSnapshot", "The telemetry events kept in memory"),
    ("UpdateService", "CheckForUpdates", "Check for a newer TransferDaemon (the only time it contacts the update server)"),
    ("UpdateService", "ApplyUpdate", "Download and apply the update found by check_for_updates"),
];

fn group_of(service: &str) -> &'static str {
    match service {
        "AccountService" => "account",
        "FriendService" => "contacts",
        "GroupService" => "groups",
        "ConnectionService" => "connections",
        "MessageService" => "messages",
        "TransferService" => "transfers",
        "SettingsService" => "settings",
        "CallService" => "calls",
        "TelemetryService" => "telemetry",
        "UpdateService" => "updates",
        _ => "other",
    }
}

/// `GetIdentity` -> `get_identity`.
pub fn snake(name: &str) -> String {
    let mut out = String::new();
    for (i, ch) in name.chars().enumerate() {
        if ch.is_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.extend(ch.to_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}

fn is_read(rpc: &str) -> bool {
    ["Get", "List", "Search", "Stream", "Check"].iter().any(|p| rpc.starts_with(p))
}

fn is_destructive(rpc: &str) -> bool {
    ["Remove", "Delete", "Leave", "CreateIdentity", "RestoreIdentity", "ApplyUpdate", "Cancel"]
        .iter()
        .any(|p| rpc.starts_with(p))
}

/// The daemon operations, built from [`RPCS`] and the proto.
pub fn grpc_ops() -> Vec<Operation> {
    let p = proto();
    RPCS.iter()
        .map(|(service, rpc, summary)| {
            let r = p.rpcs.iter().find(|r| r.service == *service && r.name == *rpc);
            let (input, output, streaming) = match r {
                Some(r) => (p.schema(&r.input), p.schema(&r.output), r.server_streaming),
                None => (json!({"type": "object"}), json!({"type": "object"}), false),
            };
            let mut input = input;
            if streaming {
                if let Some(props) = input.get_mut("properties").and_then(Value::as_object_mut) {
                    props.insert("seconds".into(), json!({"type": "number", "description": "how long to listen (default 5, at most 120)"}));
                    props.insert("max".into(), json!({"type": "integer", "description": "stop after this many events (default 200)"}));
                }
            }
            Operation {
                id: format!("{}.{}", group_of(service), snake(rpc)),
                group: group_of(service).to_string(),
                summary: summary.to_string(),
                mutating: !is_read(rpc),
                destructive: is_destructive(rpc),
                streaming,
                input,
                output: if streaming { json!({"type": "array", "items": output}) } else { output },
                kind: "grpc".into(),
                rpc: Some((service, rpc)),
            }
        })
        .collect()
}

fn ctl(id: &str, summary: &str, mutating: bool, destructive: bool, input: Value) -> Operation {
    let (group, _) = id.split_once('.').unwrap_or((id, ""));
    Operation {
        id: id.into(),
        group: group.into(),
        summary: summary.into(),
        mutating,
        destructive,
        streaming: false,
        input,
        output: json!({}),
        kind: "control".into(),
        rpc: None,
    }
}

fn obj(props: Value, required: &[&str]) -> Value {
    json!({"type": "object", "properties": props, "required": required})
}

/// A widget in the GUI: by the `id` gui.inspect gave it, or by its visible text / label.
fn target() -> Value {
    json!({"type": "object", "description": "a widget: {id} (from gui.inspect), {text} (its label or text; exact first, then contains), or {role, index}",
           "properties": {"id": {"type": "string"}, "text": {"type": "string", "description": "label, text, or what an icon button means (send, attach file, voice call, back...)"},
                          "role": {"type": "string", "description": "button, text_input, multiline_text_input, checkbox...; alone (with index) it picks the n-th of that role"},
                          "index": {"type": "integer"}}})
}

/// The operations the hub implements itself.
pub fn control_ops() -> Vec<Operation> {
    let e = json!({"type": "object", "properties": {}});
    vec![
        ctl("daemon.status", "The daemon: version, pid, uptime, its addresses (gRPC, peer listener, control), this identity, counts of contacts/transfers/groups, whether the GUI and TUI are attached, local relays", false, false, e.clone()),
        ctl("daemon.stop", "Stop the daemon (the GUI and TUI stay open and reconnect when it is started again)", true, true, e.clone()),
        ctl("daemon.env", "The settings the daemon was started with (TRANSFERD_* environment: relays, bind address, limits, DHT)", false, false, e.clone()),
        ctl("gui.launch", "Open the TransferDaemon window (transferd-ui) and wait until it is attached", true, false,
            obj(json!({"wait_s": {"type": "number"}}), &[])),
        ctl("gui.state", "The window: page (onboarding, home, chat, group chat), home tab, open chat, identity, counts, locked?, size", false, false, e.clone()),
        ctl("gui.pages", "The pages and tabs the window has, for gui.navigate", false, false, e.clone()),
        ctl("gui.navigate", "Go to a page or tab: chats, groups, contacts, transfers, settings, telemetry, connections, home, onboarding", true, false,
            obj(json!({"to": {"type": "string"}}), &["to"])),
        ctl("gui.open_chat", "Open the chat with a contact (by id or name) or a group", true, false,
            obj(json!({"contact": {"type": "string"}, "group": {"type": "string"}}), &[])),
        ctl("gui.inspect", "Every widget on screen now: id, role (button, text input, checkbox, label...), label, value, enabled, checked, position", false, false,
            obj(json!({"query": {"type": "string", "description": "only widgets whose label/value contains this"}, "max": {"type": "integer"}}), &[])),
        ctl("gui.find", "Widgets whose label or value matches", false, false, obj(json!({"query": {"type": "string"}}), &["query"])),
        ctl("gui.click", "Click a widget, as a person would (pointer moves there, presses and releases)", true, false,
            obj(json!({"target": target(), "double": {"type": "boolean"}}), &["target"])),
        ctl("gui.set", "Put a value in a text field: focus it, select everything, type the value (submit: press Enter after)", true, false,
            obj(json!({"target": target(), "value": {"type": "string"}, "submit": {"type": "boolean"}}), &["target", "value"])),
        ctl("gui.type", "Type text into whatever has focus", true, false, obj(json!({"text": {"type": "string"}}), &["text"])),
        ctl("gui.key", "Press keys: Enter, Escape, Tab, ctrl+N, ctrl+comma, ctrl+tab, ArrowDown...", true, false,
            obj(json!({"keys": {"type": "string"}}), &["keys"])),
        ctl("gui.scroll", "Scroll the window (dy > 0 scrolls down) at a widget or the middle", true, false,
            obj(json!({"dy": {"type": "number"}, "target": target()}), &["dy"])),
        ctl("gui.screenshot", "A PNG of the window (base64)", false, false, obj(json!({"max_width": {"type": "integer"}}), &[])),
        ctl("gui.window", "The window itself: show, focus, minimize, maximize, restore, resize (width, height), close", true, false,
            obj(json!({"action": {"type": "string", "enum": ["show", "focus", "minimize", "maximize", "restore", "resize", "close"]},
                       "width": {"type": "number"}, "height": {"type": "number"}}), &["action"])),
        ctl("gui.wait", "Wait until a widget with this text appears (or disappears: gone=true)", false, false,
            obj(json!({"text": {"type": "string"}, "gone": {"type": "boolean"}, "timeout_s": {"type": "number"}}), &["text"])),
        ctl("tui.launch", "Start the terminal UI (transferd-tui): headless (drawn in memory, driven from here) or in a new console window", true, false,
            obj(json!({"headless": {"type": "boolean", "description": "default true"}, "width": {"type": "integer"}, "height": {"type": "integer"},
                       "wait_s": {"type": "number"}}), &[])),
        ctl("tui.state", "The terminal UI: screen, tab, selection, open chat, modal, status line, size", false, false, e.clone()),
        ctl("tui.screen", "The terminal UI's screen as text, exactly as drawn", false, false, e.clone()),
        ctl("tui.key", "Press keys in the terminal UI: F1-F5 (tabs), Enter, Esc, Tab, Up, Down, ctrl+c, a letter...", true, false,
            obj(json!({"keys": {"type": "string"}}), &["keys"])),
        ctl("tui.type", "Type text into the terminal UI", true, false, obj(json!({"text": {"type": "string"}}), &["text"])),
        ctl("tui.navigate", "Switch the terminal UI to a tab: chats, contacts, transfers, settings, telemetry", true, false,
            obj(json!({"to": {"type": "string"}}), &["to"])),
        ctl("tui.resize", "Resize a headless terminal UI", true, false,
            obj(json!({"width": {"type": "integer"}, "height": {"type": "integer"}}), &["width", "height"])),
        ctl("tui.quit", "Close the terminal UI", true, false, e.clone()),
        ctl("relay.status", "The relays: the ones this daemon uses (TRANSFERD_RELAY_ADDR) and the local relay/DHT processes started from here", false, false, e.clone()),
        ctl("relay.start", "Start a local relay: relayd (UDP), relayd-ws (WebSocket) or dhtd (DHT bootstrap), on an address", true, false,
            obj(json!({"kind": {"type": "string", "enum": ["relayd", "relayd-ws", "dhtd"]}, "bind": {"type": "string", "description": "e.g. 0.0.0.0:9000"},
                       "env": {"type": "object", "description": "extra settings, e.g. RELAYD_MAX_MB_PER_DAY"}}), &["kind"])),
        ctl("relay.stop", "Stop a local relay started from here", true, false,
            obj(json!({"kind": {"type": "string", "enum": ["relayd", "relayd-ws", "dhtd"]}}), &["kind"])),
        ctl("relay.probe", "Check that a relay answers: udp://host:port, ws://host:port or wss://host", false, false,
            obj(json!({"addr": {"type": "string"}}), &["addr"])),
    ]
}

/// Everything, sorted by id.
pub fn all() -> Vec<Operation> {
    let mut ops = grpc_ops();
    ops.extend(control_ops());
    ops.sort_by(|a, b| a.id.cmp(&b.id));
    ops
}

pub fn find(id: &str) -> Option<Operation> {
    all().into_iter().find(|o| o.id == id)
}

// ---- running a daemon operation -------------------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum CallError {
    #[error("bad arguments: {0}")]
    BadArgs(String),
    #[error("{0}")]
    Status(String),
    #[error("the daemon is not reachable: {0}")]
    Unreachable(String),
}

impl CallError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::BadArgs(_) => "bad_arguments",
            Self::Status(_) => "failed",
            Self::Unreachable(_) => "unreachable",
        }
    }
}

fn status_err(s: tonic::Status) -> CallError {
    match s.code() {
        tonic::Code::Unavailable => CallError::Unreachable(s.message().to_string()),
        tonic::Code::InvalidArgument | tonic::Code::FailedPrecondition | tonic::Code::NotFound => {
            CallError::BadArgs(format!("{:?}: {}", s.code(), s.message()))
        }
        _ => CallError::Status(format!("{:?}: {}", s.code(), s.message())),
    }
}

/// Enum fields may be given by name (`"ADMIN"`, `"GROUP_ROLE_ADMIN"`) as well as by number.
fn enums_by_name(message: &str, mut args: Value) -> Value {
    for (field, values) in proto().enum_fields(message) {
        if let Some(Value::String(s)) = args.get(&field) {
            let up = s.to_uppercase();
            if let Some(i) = values.iter().position(|v| *v == up || v.ends_with(&format!("_{up}"))) {
                args[&field] = json!(i);
            }
        }
    }
    args
}

async fn unary<Req, Resp>(ch: AuthChannel, service: &str, rpc: &str, args: Value) -> Result<Value, CallError>
where
    Req: prost::Message + DeserializeOwned + Send + Sync + 'static,
    Resp: prost::Message + Default + Serialize + Send + Sync + 'static,
{
    let input = proto().rpcs.iter().find(|r| r.service == service && r.name == rpc).map(|r| r.input.clone()).unwrap_or_default();
    let req: Req = serde_json::from_value(enums_by_name(&input, args)).map_err(|e| CallError::BadArgs(e.to_string()))?;
    let mut grpc = tonic::client::Grpc::new(ch);
    grpc.ready().await.map_err(|e| CallError::Unreachable(e.to_string()))?;
    let path = http::uri::PathAndQuery::try_from(format!("/transferd.{service}/{rpc}"))
        .map_err(|e| CallError::BadArgs(e.to_string()))?;
    let codec = tonic::codec::ProstCodec::<Req, Resp>::default();
    let resp = grpc.unary(tonic::Request::new(req), path, codec).await.map_err(status_err)?;
    serde_json::to_value(resp.into_inner()).map_err(|e| CallError::Status(e.to_string()))
}

async fn streaming<Req, Resp>(ch: AuthChannel, service: &str, rpc: &str, mut args: Value) -> Result<Value, CallError>
where
    Req: prost::Message + DeserializeOwned + Send + Sync + 'static,
    Resp: prost::Message + Default + Serialize + Send + Sync + 'static,
{
    let seconds = args.get("seconds").and_then(Value::as_f64).unwrap_or(5.0).clamp(0.2, 120.0);
    let max = args.get("max").and_then(Value::as_u64).unwrap_or(200).max(1) as usize;
    if let Some(o) = args.as_object_mut() {
        o.remove("seconds");
        o.remove("max");
    }
    let req: Req = serde_json::from_value(args).map_err(|e| CallError::BadArgs(e.to_string()))?;
    let mut grpc = tonic::client::Grpc::new(ch);
    grpc.ready().await.map_err(|e| CallError::Unreachable(e.to_string()))?;
    let path = http::uri::PathAndQuery::try_from(format!("/transferd.{service}/{rpc}"))
        .map_err(|e| CallError::BadArgs(e.to_string()))?;
    let codec = tonic::codec::ProstCodec::<Req, Resp>::default();
    let mut stream = grpc.server_streaming(tonic::Request::new(req), path, codec).await.map_err(status_err)?.into_inner();
    let mut out = vec![];
    let deadline = tokio::time::Instant::now() + Duration::from_secs_f64(seconds);
    while out.len() < max {
        match tokio::time::timeout_at(deadline, stream.message()).await {
            Ok(Ok(Some(m))) => out.push(serde_json::to_value(m).unwrap_or(Value::Null)),
            Ok(Ok(None)) | Err(_) => break,
            Ok(Err(s)) => return Err(status_err(s)),
        }
    }
    Ok(Value::Array(out))
}

macro_rules! dispatch {
    ($ch:expr, $svc:expr, $rpc:expr, $args:expr; $( $s:literal $r:literal => $kind:ident($req:ty, $resp:ty) ),* $(,)?) => {
        match ($svc, $rpc) {
            $( ($s, $r) => $kind::<$req, $resp>($ch, $s, $r, $args).await, )*
            _ => Err(CallError::BadArgs(format!("no rpc {}/{}", $svc, $rpc))),
        }
    };
}

/// Run one gRPC call with JSON arguments; the reply comes back as JSON.
pub async fn call_rpc(ch: AuthChannel, service: &str, rpc: &str, args: Value) -> Result<Value, CallError> {
    let args = if args.is_null() { json!({}) } else { args };
    dispatch!(ch, service, rpc, args;
        "AccountService" "GetIdentity" => unary(pb::Empty, pb::IdentityReply),
        "AccountService" "CreateIdentity" => unary(pb::CreateIdentityRequest, pb::RecoveryPhraseReply),
        "AccountService" "RestoreIdentity" => unary(pb::RestoreIdentityRequest, pb::IdentityReply),
        "AccountService" "GetPublicKeyHex" => unary(pb::Empty, pb::PublicKeyReply),
        "FriendService" "GetContacts" => unary(pb::Empty, pb::ContactList),
        "FriendService" "AddContact" => unary(pb::AddContactRequest, pb::ContactReply),
        "FriendService" "RenameContact" => unary(pb::RenameContactRequest, pb::ContactReply),
        "FriendService" "RemoveContact" => unary(pb::RemoveContactRequest, pb::Empty),
        "FriendService" "BlockContact" => unary(pb::BlockContactRequest, pb::ContactReply),
        "FriendService" "UnblockContact" => unary(pb::BlockContactRequest, pb::ContactReply),
        "FriendService" "GetSafetyNumber" => unary(pb::SafetyNumberRequest, pb::SafetyNumberReply),
        "FriendService" "SetContactAddress" => unary(pb::SetContactAddressRequest, pb::ContactReply),
        "GroupService" "CreateGroup" => unary(pb::CreateGroupRequest, pb::GroupReply),
        "GroupService" "GetGroups" => unary(pb::Empty, pb::GroupList),
        "GroupService" "GetGroup" => unary(pb::GetGroupRequest, pb::GroupReply),
        "GroupService" "RenameGroup" => unary(pb::RenameGroupRequest, pb::GroupReply),
        "GroupService" "AddMembers" => unary(pb::GroupMembersRequest, pb::GroupReply),
        "GroupService" "RemoveMembers" => unary(pb::GroupMembersRequest, pb::GroupReply),
        "GroupService" "SetMemberRole" => unary(pb::SetMemberRoleRequest, pb::GroupReply),
        "GroupService" "LeaveGroup" => unary(pb::GetGroupRequest, pb::Empty),
        "GroupService" "DeleteGroup" => unary(pb::GetGroupRequest, pb::Empty),
        "GroupService" "SendGroupText" => unary(pb::SendGroupTextRequest, pb::MessageReply),
        "GroupService" "GetGroupMessages" => unary(pb::GetGroupRequest, pb::MessageList),
        "ConnectionService" "ListConnections" => unary(pb::Empty, pb::ConnectionList),
        "ConnectionService" "SetConnectionPolicy" => unary(pb::SetConnectionPolicyRequest, pb::Empty),
        "ConnectionService" "StreamConnectionStatus" => streaming(pb::Empty, pb::ConnectionStatusMsg),
        "MessageService" "GetMessages" => unary(pb::GetMessagesRequest, pb::MessageList),
        "MessageService" "SendText" => unary(pb::SendTextRequest, pb::MessageReply),
        "MessageService" "SearchMessages" => unary(pb::SearchMessagesRequest, pb::MessageList),
        "MessageService" "SendTyping" => unary(pb::SendTypingRequest, pb::Empty),
        "MessageService" "ToggleReaction" => unary(pb::ReactionRequest, pb::Empty),
        "TransferService" "GetTransfers" => unary(pb::Empty, pb::TransferList),
        "TransferService" "SendFile" => unary(pb::SendFileRequest, pb::MessageReply),
        "TransferService" "CancelTransfer" => unary(pb::CancelTransferRequest, pb::Empty),
        "TransferService" "PauseTransfer" => unary(pb::CancelTransferRequest, pb::Empty),
        "TransferService" "ResumeTransfer" => unary(pb::CancelTransferRequest, pb::Empty),
        "SettingsService" "GetSetting" => unary(pb::GetSettingRequest, pb::SettingReply),
        "SettingsService" "SetSetting" => unary(pb::SetSettingRequest, pb::Empty),
        "CallService" "StartCall" => unary(pb::CallStartRequest, pb::CallStartResponse),
        "CallService" "AcceptCall" => unary(pb::CallAcceptRequest, pb::CallAcceptResponse),
        "CallService" "RejectCall" => unary(pb::CallRejectRequest, pb::Empty),
        "CallService" "EndCall" => unary(pb::CallEndRequest, pb::Empty),
        "CallService" "SendIceCandidate" => unary(pb::IceCandidateMsg, pb::Empty),
        "CallService" "StreamCallEvents" => streaming(pb::Empty, pb::CallEvent),
        "TelemetryService" "StreamTelemetry" => streaming(pb::Empty, pb::TelemetryEventMsg),
        "TelemetryService" "GetSnapshot" => unary(pb::Empty, pb::TelemetrySnapshot),
        "UpdateService" "CheckForUpdates" => unary(pb::Empty, pb::UpdateReply),
        "UpdateService" "ApplyUpdate" => unary(pb::Empty, pb::Empty),
    )
}

/// `send_file` convenience: fill in the name, size and MIME type from the file itself.
pub fn complete_send_file(mut args: Value) -> Result<Value, CallError> {
    let path = args.get("file_path").and_then(Value::as_str).unwrap_or_default().to_string();
    if path.is_empty() {
        return Err(CallError::BadArgs("file_path is required".into()));
    }
    let meta = std::fs::metadata(&path).map_err(|e| CallError::BadArgs(format!("{path}: {e}")))?;
    if !meta.is_file() {
        return Err(CallError::BadArgs(format!("{path} is not a file")));
    }
    let p = std::path::Path::new(&path);
    let name = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let ext = p.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default();
    let mime = match ext.as_str() {
        "png" => "image/png", "jpg" | "jpeg" => "image/jpeg", "gif" => "image/gif", "webp" => "image/webp",
        "mp4" => "video/mp4", "webm" => "video/webm", "mkv" => "video/x-matroska", "mov" => "video/quicktime",
        "mp3" => "audio/mpeg", "ogg" | "opus" => "audio/ogg", "wav" => "audio/wav", "m4a" => "audio/mp4",
        "pdf" => "application/pdf", "zip" => "application/zip", "txt" | "log" | "md" => "text/plain",
        "json" => "application/json", "html" => "text/html", "csv" => "text/csv",
        _ => "application/octet-stream",
    };
    if let Some(o) = args.as_object_mut() {
        let absolute = std::fs::canonicalize(p).map(|c| c.to_string_lossy().trim_start_matches(r"\\?\").to_string()).unwrap_or(path);
        o.insert("file_path".into(), json!(absolute));
        if o.get("file_name").and_then(Value::as_str).unwrap_or_default().is_empty() {
            o.insert("file_name".into(), json!(name));
        }
        if o.get("file_size").and_then(Value::as_u64).unwrap_or(0) == 0 {
            o.insert("file_size".into(), json!(meta.len()));
        }
        if o.get("mime_type").and_then(Value::as_str).unwrap_or_default().is_empty() {
            o.insert("mime_type".into(), json!(mime));
        }
    }
    Ok(args)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_covers_every_rpc_in_the_proto() {
        let p = proto();
        let mut in_proto: Vec<(String, String)> = p.rpcs.iter().map(|r| (r.service.clone(), r.name.clone())).collect();
        let mut in_table: Vec<(String, String)> = RPCS.iter().map(|(s, r, _)| (s.to_string(), r.to_string())).collect();
        in_proto.sort();
        in_table.sort();
        assert_eq!(in_proto, in_table, "RPCS (and the dispatch table) must list exactly the proto's rpcs");
    }

    #[test]
    fn ids_are_unique_and_classified() {
        let ops = all();
        let mut ids: Vec<&str> = ops.iter().map(|o| o.id.as_str()).collect();
        ids.dedup();
        assert_eq!(ids.len(), ops.len());
        let get = |id: &str| ops.iter().find(|o| o.id == id).cloned().expect(id);
        assert!(!get("messages.get_messages").mutating);
        assert!(get("messages.send_text").mutating);
        assert!(get("contacts.remove_contact").destructive);
        assert!(get("telemetry.stream_telemetry").streaming);
        assert!(get("telemetry.stream_telemetry").input["properties"]["seconds"].is_object());
        assert_eq!(get("account.get_public_key_hex").group, "account");
        assert_eq!(get("gui.click").kind, "control");
    }

    #[test]
    fn enum_names_become_numbers() {
        let v = enums_by_name("SetMemberRoleRequest", json!({"group_id": "g", "member_id": "m", "role": "admin"}));
        assert_eq!(v["role"], 2);
        let v = enums_by_name("SetMemberRoleRequest", json!({"role": "GROUP_ROLE_OWNER"}));
        assert_eq!(v["role"], 1);
    }

    #[test]
    fn send_file_is_completed_from_the_file() {
        let dir = std::env::temp_dir().join(format!("tdc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).ok();
        let f = dir.join("photo.png");
        std::fs::write(&f, [0u8; 10]).ok();
        let v = complete_send_file(json!({"contact_id": "c", "file_path": f.to_string_lossy()})).expect("completed");
        assert_eq!(v["file_name"], "photo.png");
        assert_eq!(v["file_size"], 10);
        assert_eq!(v["mime_type"], "image/png");
        assert!(complete_send_file(json!({"file_path": dir.join("nope").to_string_lossy()})).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }
}
