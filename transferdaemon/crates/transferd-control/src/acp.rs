//! The Agent Client Protocol server: TransferDaemon as an agent an editor starts and talks to.
//!
//! Transport-free, like [`crate::mcp`]. [`serve`] runs the protocol over a [`Wire`], which is the
//! editor's side of standard input and output, and runs operations through a [`Host`], which is the
//! hub. `transferd-cli acp` supplies both.
//!
//! A prompt is a command:
//! * `help`: the commands.
//! * `ops [WORDS]`: the operations whose id or summary contains the words.
//! * `OPERATION key=value ...` or `OPERATION {json}`: runs the operation. A value is read as JSON
//!   when it is valid JSON, and as text otherwise. Quote a value that contains a space.
//!
//! An operation that changes something asks the editor for permission first. A `session/cancel`
//! that arrives while that question is open stops the prompt. Between prompts a cancel has nothing to
//! stop. Operations that only read run without asking.

use std::collections::HashSet;
use std::future::Future;

use serde_json::{Map, Value, json};

/// The protocol version this agent speaks. ACP versions are integers.
pub const PROTOCOL_VERSION: u64 = 1;

const HELP: &str = "\
Commands:
  help                          this list
  ops [WORDS]                   operations whose id or summary contains the words
  OPERATION key=value ...       run an operation, for example: daemon.status
  OPERATION {json}              the same, with the arguments as one JSON object

Operations that change something ask first. Quote a value that has a space in it.";

const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;
const INTERNAL_ERROR: i64 = -32603;

/// The editor's side of the conversation: one message at a time, in each direction.
pub trait Wire: Send {
    /// Sends one message to the editor.
    fn send(&mut self, message: Value) -> impl Future<Output = Result<(), String>> + Send;
    /// The next message from the editor, or `None` once it has closed its output.
    fn recv(&mut self) -> impl Future<Output = Option<Value>> + Send;
}

/// What the agent runs operations through, and reads the catalog from.
pub trait Host: Send {
    /// The operations on offer, as catalog entries (`id`, `summary`, `mutating`, `destructive`).
    fn operations(&mut self) -> impl Future<Output = Vec<Value>> + Send;
    /// Runs one operation with its arguments.
    fn call(&mut self, op: &str, args: Value) -> impl Future<Output = Result<Value, String>> + Send;
}

/// Runs the protocol until the editor closes its output.
pub async fn serve<W: Wire, H: Host>(wire: &mut W, host: &mut H) -> Result<(), String> {
    let mut agent = Agent {
        sessions: HashSet::new(),
        opened: 0,
        calls: 0,
        asks: 0,
    };
    while let Some(message) = wire.recv().await {
        if let Some(reply) = agent.handle(wire, host, &message).await? {
            wire.send(reply).await?;
        }
    }
    Ok(())
}

/// Why a request could not be answered. A protocol error goes back to the editor. A failure to
/// talk to the editor ends the agent.
enum Failure {
    Rpc(i64, String),
    Io(String),
}

impl From<String> for Failure {
    fn from(text: String) -> Self {
        Self::Io(text)
    }
}

/// The editor's answer to a permission question.
enum Permission {
    Allowed,
    Rejected,
    Cancelled,
}

struct Agent {
    sessions: HashSet<String>,
    opened: u64,
    calls: u64,
    asks: u64,
}

impl Agent {
    /// Answers one message. Notifications, and responses to requests this agent did not make, get no reply.
    async fn handle<W: Wire, H: Host>(
        &mut self,
        wire: &mut W,
        host: &mut H,
        message: &Value,
    ) -> Result<Option<Value>, String> {
        let Some(method) = message.get("method").and_then(Value::as_str) else {
            return Ok(None);
        };
        // A message without an id is a notification. A cancel is acted on only while a permission
        // question is open, which is where it is read.
        let Some(id) = message.get("id").cloned() else {
            return Ok(None);
        };
        let params = message.get("params").cloned().unwrap_or(Value::Null);
        let outcome = match method {
            "initialize" => Ok(initialize()),
            "session/new" => Ok(self.new_session()),
            "session/prompt" => self.prompt(wire, host, &params).await,
            other => Err(Failure::Rpc(
                METHOD_NOT_FOUND,
                format!("method not found: {other}"),
            )),
        };
        Ok(Some(match outcome {
            Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
            Err(Failure::Rpc(code, text)) => error_reply(id, code, &text),
            Err(Failure::Io(text)) => return Err(text),
        }))
    }

    fn new_session(&mut self) -> Value {
        self.opened += 1;
        let session = format!("session-{}", self.opened);
        self.sessions.insert(session.clone());
        json!({"sessionId": session})
    }

    async fn prompt<W: Wire, H: Host>(
        &mut self,
        wire: &mut W,
        host: &mut H,
        params: &Value,
    ) -> Result<Value, Failure> {
        let session = params
            .get("sessionId")
            .and_then(Value::as_str)
            .ok_or_else(|| Failure::Rpc(INVALID_PARAMS, "session/prompt needs a sessionId".to_owned()))?
            .to_owned();
        if !self.sessions.contains(&session) {
            return Err(Failure::Rpc(
                INVALID_PARAMS,
                format!("unknown session {session}"),
            ));
        }
        let step = match parse(&prompt_text(params)) {
            Ok(step) => step,
            Err(problem) => {
                say(wire, &session, &format!("{problem}\n\n{HELP}")).await?;
                return Ok(stop("end_turn"));
            }
        };
        match step {
            Step::Help => {
                say(wire, &session, HELP).await?;
                Ok(stop("end_turn"))
            }
            Step::Ops(words) => {
                let catalog = host.operations().await;
                say(wire, &session, &listing(&catalog, words.as_deref())).await?;
                Ok(stop("end_turn"))
            }
            Step::Run { op, args } => {
                let catalog = host.operations().await;
                let Some(entry) = catalog.iter().find(|e| e["id"].as_str() == Some(op.as_str())) else {
                    let text = format!("`{op}` is not an operation here. Try `ops {op}`.");
                    say(wire, &session, &text).await?;
                    return Ok(stop("end_turn"));
                };
                let mutating = entry["mutating"].as_bool() == Some(true);
                let destructive = entry["destructive"].as_bool() == Some(true);
                self.run(wire, host, &session, &op, args, mutating, destructive).await
            }
        }
    }

    /// Runs one operation, reported as a tool call. An operation that changes something waits for permission.
    #[allow(clippy::too_many_arguments)]
    async fn run<W: Wire, H: Host>(
        &mut self,
        wire: &mut W,
        host: &mut H,
        session: &str,
        op: &str,
        args: Value,
        mutating: bool,
        destructive: bool,
    ) -> Result<Value, Failure> {
        self.calls += 1;
        let call = format!("call-{}", self.calls);
        let kind = if destructive {
            "delete"
        } else if mutating {
            "edit"
        } else {
            "read"
        };
        let guarded = mutating || destructive;
        let status = if guarded { "pending" } else { "in_progress" };
        wire.send(update(
            session,
            json!({
                "sessionUpdate": "tool_call",
                "toolCallId": call,
                "title": op,
                "kind": kind,
                "status": status,
                "rawInput": args,
            }),
        ))
        .await?;

        if guarded {
            match self.ask(wire, session, &call, op, kind).await? {
                Permission::Allowed => {
                    wire.send(update(
                        session,
                        json!({"sessionUpdate": "tool_call_update", "toolCallId": call, "status": "in_progress"}),
                    ))
                    .await?;
                }
                Permission::Rejected => {
                    finish(wire, session, &call, "failed", "Not done: permission was refused.").await?;
                    return Ok(stop("end_turn"));
                }
                Permission::Cancelled => {
                    finish(wire, session, &call, "failed", "Not done: the prompt was cancelled.").await?;
                    return Ok(stop("cancelled"));
                }
            }
        }

        match host.call(op, args).await {
            Ok(result) => finish(wire, session, &call, "completed", &pretty(&result)).await?,
            Err(problem) => finish(wire, session, &call, "failed", &problem).await?,
        }
        Ok(stop("end_turn"))
    }

    /// Asks the editor whether to go ahead. While the question is open nothing else is served: a
    /// cancel ends the wait, and any other request is refused so its sender is not left waiting.
    async fn ask<W: Wire>(
        &mut self,
        wire: &mut W,
        session: &str,
        call: &str,
        title: &str,
        kind: &str,
    ) -> Result<Permission, Failure> {
        self.asks += 1;
        let request = format!("permission-{}", self.asks);
        wire.send(json!({
            "jsonrpc": "2.0",
            "id": request,
            "method": "session/request_permission",
            "params": {
                "sessionId": session,
                "toolCall": {"toolCallId": call, "title": title, "kind": kind, "status": "pending"},
                "options": [
                    {"optionId": "allow", "name": "Allow once", "kind": "allow_once"},
                    {"optionId": "reject", "name": "Reject", "kind": "reject_once"},
                ],
            },
        }))
        .await?;

        loop {
            let Some(message) = wire.recv().await else {
                return Err(Failure::Io(
                    "the editor closed its output while a permission question was open".to_owned(),
                ));
            };
            if message.get("method").is_none() && message.get("id") == Some(&Value::String(request.clone())) {
                let outcome = &message["result"]["outcome"];
                return Ok(match (outcome["outcome"].as_str(), outcome["optionId"].as_str()) {
                    (Some("selected"), Some("allow")) => Permission::Allowed,
                    (Some("selected"), _) => Permission::Rejected,
                    _ => Permission::Cancelled,
                });
            }
            if message.get("method").and_then(Value::as_str) == Some("session/cancel") {
                return Ok(Permission::Cancelled);
            }
            if let (Some(id), true) = (message.get("id"), message.get("method").is_some()) {
                let busy = error_reply(id.clone(), INTERNAL_ERROR, "busy: a permission question is open");
                wire.send(busy).await?;
            }
        }
    }
}

fn initialize() -> Value {
    json!({
        "protocolVersion": PROTOCOL_VERSION,
        "agentCapabilities": {
            "loadSession": false,
            "promptCapabilities": {"image": false, "audio": false, "embeddedContext": false},
            "mcpCapabilities": {"http": false, "sse": false},
        },
        "authMethods": [],
        "agentInfo": {"name": "transferd", "title": "TransferDaemon", "version": env!("CARGO_PKG_VERSION")},
    })
}

fn error_reply(id: Value, code: i64, text: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": text}})
}

fn stop(reason: &str) -> Value {
    json!({"stopReason": reason})
}

fn update(session: &str, update: Value) -> Value {
    json!({"jsonrpc": "2.0", "method": "session/update", "params": {"sessionId": session, "update": update}})
}

fn text_block(text: &str) -> Value {
    json!({"type": "text", "text": text})
}

async fn say<W: Wire>(wire: &mut W, session: &str, text: &str) -> Result<(), String> {
    wire.send(update(
        session,
        json!({"sessionUpdate": "agent_message_chunk", "content": text_block(text)}),
    ))
    .await
}

async fn finish<W: Wire>(
    wire: &mut W,
    session: &str,
    call: &str,
    status: &str,
    text: &str,
) -> Result<(), String> {
    wire.send(update(
        session,
        json!({
            "sessionUpdate": "tool_call_update",
            "toolCallId": call,
            "status": status,
            "content": [{"type": "content", "content": text_block(text)}],
        }),
    ))
    .await
}

fn pretty(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
}

/// The operations whose id or summary contains the words, one per line. Every operation when there are no words.
pub fn listing(catalog: &[Value], words: Option<&str>) -> String {
    let needle = words.unwrap_or("").to_lowercase();
    let lines: Vec<String> = catalog
        .iter()
        .filter(|e| {
            let id = e["id"].as_str().unwrap_or_default();
            let summary = e["summary"].as_str().unwrap_or_default();
            needle.is_empty() || id.to_lowercase().contains(&needle) || summary.to_lowercase().contains(&needle)
        })
        .map(|e| {
            let mark = if e["destructive"].as_bool() == Some(true) {
                " (cannot be undone)"
            } else if e["mutating"].as_bool() == Some(true) {
                " (asks first)"
            } else {
                ""
            };
            format!("{}  {}{}", e["id"].as_str().unwrap_or_default(), e["summary"].as_str().unwrap_or_default(), mark)
        })
        .collect();
    if lines.is_empty() {
        "No operation matches.".to_owned()
    } else {
        lines.join("\n")
    }
}

/// The text of a prompt: its text blocks, in order. Other kinds of block are not commands.
fn prompt_text(params: &Value) -> String {
    params
        .get("prompt")
        .and_then(Value::as_array)
        .map(|blocks| {
            blocks
                .iter()
                .filter(|block| block.get("type").and_then(Value::as_str) == Some("text"))
                .filter_map(|block| block.get("text").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default()
}

/// What a prompt asks for.
#[derive(Debug, PartialEq)]
enum Step {
    Help,
    Ops(Option<String>),
    Run { op: String, args: Value },
}

/// Reads a command: `help`, `ops [WORDS]`, or an operation with its arguments.
fn parse(text: &str) -> Result<Step, String> {
    let words = split_words(text)?;
    let Some((first, rest)) = words.split_first() else {
        return Ok(Step::Help);
    };
    match first.as_str() {
        "help" if rest.is_empty() => Ok(Step::Help),
        "ops" => Ok(Step::Ops(if rest.is_empty() { None } else { Some(rest.join(" ")) })),
        op => Ok(Step::Run {
            op: op.to_owned(),
            args: arguments(rest)?,
        }),
    }
}

/// Arguments as one JSON object: either a single `{...}` word, or `key=value` words.
fn arguments(words: &[String]) -> Result<Value, String> {
    if let [only] = words {
        if only.trim_start().starts_with('{') {
            return match serde_json::from_str::<Value>(only) {
                Ok(value) if value.is_object() => Ok(value),
                _ => Err("the arguments are a JSON object, which did not parse".to_owned()),
            };
        }
    }
    let mut object = Map::new();
    for word in words {
        let Some((key, value)) = word.split_once('=') else {
            return Err(format!("`{word}` is not key=value"));
        };
        let value = serde_json::from_str::<Value>(value).unwrap_or_else(|_| Value::String(value.to_owned()));
        object.insert(key.to_owned(), value);
    }
    Ok(Value::Object(object))
}

/// Splits a command into words. Double quotes keep spaces inside a word, and are not part of it.
fn split_words(text: &str) -> Result<Vec<String>, String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut quoted = false;
    for ch in text.chars() {
        if ch == '"' {
            quoted = !quoted;
            in_word = true;
        } else if ch.is_whitespace() && !quoted {
            if in_word {
                words.push(std::mem::take(&mut word));
                in_word = false;
            }
        } else {
            word.push(ch);
            in_word = true;
        }
    }
    if quoted {
        return Err("a double quote is never closed".to_owned());
    }
    if in_word {
        words.push(word);
    }
    Ok(words)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, VecDeque};

    /// Scripted editor: `incoming` is read in order, and everything the agent sends is kept.
    struct ScriptedWire {
        incoming: VecDeque<Value>,
        outgoing: Vec<Value>,
    }

    impl Wire for ScriptedWire {
        async fn send(&mut self, message: Value) -> Result<(), String> {
            self.outgoing.push(message);
            Ok(())
        }
        async fn recv(&mut self) -> Option<Value> {
            self.incoming.pop_front()
        }
    }

    struct FakeHost {
        catalog: Vec<Value>,
        results: HashMap<String, Result<Value, String>>,
        calls: Vec<(String, Value)>,
    }

    impl Host for FakeHost {
        async fn operations(&mut self) -> Vec<Value> {
            self.catalog.clone()
        }
        async fn call(&mut self, op: &str, args: Value) -> Result<Value, String> {
            self.calls.push((op.to_owned(), args));
            self.results.get(op).cloned().unwrap_or_else(|| Ok(json!({"ok": true})))
        }
    }

    fn host() -> FakeHost {
        FakeHost {
            catalog: vec![
                json!({"id": "daemon.status", "summary": "The daemon's status", "mutating": false, "destructive": false}),
                json!({"id": "relay.stop", "summary": "Stop a local relay", "mutating": true, "destructive": false}),
                json!({"id": "daemon.stop", "summary": "Stop the daemon", "mutating": true, "destructive": true}),
            ],
            results: HashMap::from([("daemon.status".to_owned(), Ok(json!({"version": "2.3.0"})))]),
            calls: Vec::new(),
        }
    }

    fn request(id: u64, method: &str, params: Value) -> Value {
        json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
    }

    fn prompt(id: u64, session: &str, text: &str) -> Value {
        request(
            id,
            "session/prompt",
            json!({"sessionId": session, "prompt": [{"type": "text", "text": text}]}),
        )
    }

    /// Runs the protocol over a script, and returns everything the agent sent plus the host it used.
    async fn run(incoming: Vec<Value>, mut host: FakeHost) -> (Vec<Value>, FakeHost) {
        let mut wire = ScriptedWire {
            incoming: incoming.into(),
            outgoing: Vec::new(),
        };
        serve(&mut wire, &mut host).await.expect("serves");
        (wire.outgoing, host)
    }

    fn reply_to(sent: &[Value], id: u64) -> Value {
        sent.iter()
            .find(|m| m.get("id") == Some(&json!(id)))
            .cloned()
            .unwrap_or_else(|| panic!("no reply to {id} in {sent:?}"))
    }

    /// What the agent said, one entry per message chunk.
    fn chunks(sent: &[Value]) -> Vec<String> {
        sent.iter()
            .filter(|m| m["params"]["update"]["sessionUpdate"] == "agent_message_chunk")
            .filter_map(|m| m["params"]["update"]["content"]["text"].as_str().map(str::to_owned))
            .collect()
    }

    #[tokio::test]
    async fn a_read_operation_runs_without_asking_and_reports_its_result() {
        let (sent, host) = run(
            vec![
                request(0, "initialize", json!({"protocolVersion": 1})),
                request(1, "session/new", json!({"cwd": "X:/", "mcpServers": []})),
                prompt(2, "session-1", "daemon.status"),
            ],
            host(),
        )
        .await;

        assert_eq!(reply_to(&sent, 0)["result"]["protocolVersion"], 1);
        assert_eq!(reply_to(&sent, 2)["result"]["stopReason"], "end_turn");
        assert!(sent.iter().all(|m| m["method"] != "session/request_permission"), "no question for a read");
        assert_eq!(host.calls, vec![("daemon.status".to_owned(), json!({}))]);
        let done = sent.iter().rev().find(|m| m["method"] == "session/update").expect("an update");
        assert_eq!(done["params"]["update"]["status"], "completed");
        assert!(done["params"]["update"]["content"][0]["content"]["text"].as_str().unwrap().contains("2.3.0"));
    }

    #[tokio::test]
    async fn a_change_asks_first_and_runs_when_the_editor_allows() {
        let (sent, host) = run(
            vec![
                request(1, "session/new", json!({})),
                prompt(2, "session-1", "relay.stop kind=relayd"),
                json!({"jsonrpc": "2.0", "id": "permission-1", "result": {"outcome": {"outcome": "selected", "optionId": "allow"}}}),
            ],
            host(),
        )
        .await;

        assert!(sent.iter().any(|m| m["method"] == "session/request_permission"), "asked");
        assert_eq!(host.calls, vec![("relay.stop".to_owned(), json!({"kind": "relayd"}))]);
        assert_eq!(reply_to(&sent, 2)["result"]["stopReason"], "end_turn");
    }

    #[tokio::test]
    async fn a_refused_change_does_not_run() {
        let (sent, host) = run(
            vec![
                request(1, "session/new", json!({})),
                prompt(2, "session-1", "daemon.stop"),
                json!({"jsonrpc": "2.0", "id": "permission-1", "result": {"outcome": {"outcome": "selected", "optionId": "reject"}}}),
            ],
            host(),
        )
        .await;

        assert!(host.calls.is_empty(), "nothing ran");
        let failed = sent.iter().rev().find(|m| m["method"] == "session/update").expect("an update");
        assert_eq!(failed["params"]["update"]["status"], "failed");
        assert_eq!(reply_to(&sent, 2)["result"]["stopReason"], "end_turn");
    }

    #[tokio::test]
    async fn a_cancel_while_the_question_is_open_stops_the_prompt() {
        let (sent, host) = run(
            vec![
                request(1, "session/new", json!({})),
                prompt(2, "session-1", "relay.stop kind=relayd"),
                json!({"jsonrpc": "2.0", "method": "session/cancel", "params": {"sessionId": "session-1"}}),
            ],
            host(),
        )
        .await;

        assert!(host.calls.is_empty());
        assert_eq!(reply_to(&sent, 2)["result"]["stopReason"], "cancelled");
    }

    #[tokio::test]
    async fn help_and_ops_are_answered_without_running_anything() {
        let (sent, host) = run(
            vec![
                request(1, "session/new", json!({})),
                prompt(2, "session-1", "help"),
                prompt(3, "session-1", "ops relay"),
            ],
            host(),
        )
        .await;

        assert!(host.calls.is_empty());
        let replies = chunks(&sent);
        assert!(replies[0].contains("Commands:"), "got {}", replies[0]);
        assert!(replies[1].contains("relay.stop  Stop a local relay (asks first)"), "got {}", replies[1]);
        assert!(!replies[1].contains("daemon.status"), "the filter applies: {}", replies[1]);
    }

    #[tokio::test]
    async fn an_unknown_operation_and_a_bad_argument_are_explained() {
        let (sent, host) = run(
            vec![
                request(1, "session/new", json!({})),
                prompt(2, "session-1", "no.such.op"),
                prompt(3, "session-1", "daemon.status stray"),
            ],
            host(),
        )
        .await;

        assert!(host.calls.is_empty());
        let text = chunks(&sent).join("\n");
        assert!(text.contains("`no.such.op` is not an operation here"), "got {text}");
        assert!(text.contains("is not key=value"), "got {text}");
    }

    #[tokio::test]
    async fn a_prompt_in_an_unknown_session_is_refused() {
        let (sent, _host) = run(vec![prompt(2, "session-9", "help")], host()).await;

        assert_eq!(reply_to(&sent, 2)["error"]["code"], INVALID_PARAMS);
    }

    #[test]
    fn arguments_are_key_value_words_or_one_json_object() {
        assert_eq!(
            arguments(&["addr=udp://h:1".to_owned(), "n=3".to_owned(), "flag=true".to_owned()]).expect("kv"),
            json!({"addr": "udp://h:1", "n": 3, "flag": true})
        );
        assert_eq!(
            arguments(&[r#"{"node_id":"abc","n":2}"#.to_owned()]).expect("json"),
            json!({"node_id": "abc", "n": 2})
        );
        assert!(arguments(&["{not json".to_owned()]).is_err());
        assert_eq!(parse("").expect("empty"), Step::Help);
        assert_eq!(
            parse(r#"relay.probe addr="a b""#).expect("quotes"),
            Step::Run {
                op: "relay.probe".to_owned(),
                args: json!({"addr": "a b"}),
            }
        );
        assert_eq!(parse("ops").expect("ops"), Step::Ops(None));
        assert!(split_words(r#"x "open"#).is_err());
    }}
