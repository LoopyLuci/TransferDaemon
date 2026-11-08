//! The terminal: slash commands that drive the daemon. The GUI's terminal page, the CLI and the tests all use this one
//! parser and one runner, so a command means the same thing everywhere.
//!
//! [`parse`] turns a line into a [`Command`]; [`run`] carries it out and returns the lines to print. [`run`] blocks
//! while it talks to the daemon, so a window calls it from a background thread.

use crate::client::{Client, ClientError};
use crate::daemon_ctl;
use serde_json::{json, Value};
use std::time::Duration;
use transferd_activity::Level;

/// What the user can type. Lines that do not start with `/` are [`Command::Plain`].
#[derive(Debug, Clone, PartialEq)]
pub enum Command {
    Empty,
    Plain,
    Help(Option<String>),
    Status,
    Start,
    Stop,
    Restart,
    Version,
    Ops(Option<String>),
    Call { op: String, args: Value },
    Activity { level: Option<Level>, category: Option<String>, text: Option<String>, limit: usize },
    Config,
    Update(UpdateAction),
    Open(String),
    Clear,
    Unknown(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateAction {
    State,
    Check,
    Download,
    Install,
    Policy(String),
}

/// One line of help: the command, how to use it, and what it does.
pub struct Entry {
    pub name: &'static str,
    pub usage: &'static str,
    pub summary: &'static str,
}

/// Every slash command, in the order `/help` shows them.
pub const COMMANDS: &[Entry] = &[
    Entry { name: "help", usage: "/help [command]", summary: "List the commands, or explain one" },
    Entry { name: "status", usage: "/status", summary: "What the daemon is doing: version, uptime, addresses, counts, windows" },
    Entry { name: "start", usage: "/start", summary: "Start the daemon (it keeps running after this window closes)" },
    Entry { name: "stop", usage: "/stop", summary: "Stop the daemon" },
    Entry { name: "restart", usage: "/restart", summary: "Stop the daemon, then start it again" },
    Entry { name: "version", usage: "/version", summary: "This build's version and the running daemon's" },
    Entry { name: "activity", usage: "/activity [level] [category] [text] [limit=N]", summary: "The activity log: errors, warnings, connections, calls. Newest last" },
    Entry { name: "logs", usage: "/logs", summary: "Shortcut for /activity warn: only warnings and errors" },
    Entry { name: "ops", usage: "/ops [text]", summary: "Every operation the daemon offers (the API, MCP and CLI all use them)" },
    Entry { name: "call", usage: "/call <operation> [json]", summary: "Run one operation, e.g. /call daemon.status or /call activity.counts" },
    Entry { name: "config", usage: "/config", summary: "Show config.json, the daemon's settings file" },
    Entry { name: "update", usage: "/update [state|check|download|install|policy <manual|download|install>]", summary: "Updates: the versions and policy (default), check GitHub, download, or install" },
    Entry { name: "open", usage: "/open gui|tui", summary: "Open the window or the terminal UI" },
    Entry { name: "clear", usage: "/clear", summary: "Clear this terminal's output" },
];

/// Categories the activity log uses. `/activity` reads a bare word as a category when it is one of these.
pub const CATEGORIES: &[&str] = &["lanes", "overlay", "relay", "api", "gui", "updates", "store", "security", "panic", "system"];

/// Read one line. Errors are for the user: a command that is not what they meant.
pub fn parse(line: &str) -> Result<Command, String> {
    let line = line.trim();
    if line.is_empty() {
        return Ok(Command::Empty);
    }
    let Some(body) = line.strip_prefix('/') else {
        return Ok(Command::Plain);
    };
    let (name, rest) = match body.split_once(char::is_whitespace) {
        Some((name, rest)) => (name, rest.trim()),
        None => (body, ""),
    };
    let rest_opt = || (!rest.is_empty()).then(|| rest.to_string());
    Ok(match name.to_ascii_lowercase().as_str() {
        "help" | "?" => Command::Help(rest_opt()),
        "status" => Command::Status,
        "start" => Command::Start,
        "stop" => Command::Stop,
        "restart" => Command::Restart,
        "version" => Command::Version,
        "ops" | "operations" => Command::Ops(rest_opt()),
        "call" => {
            let (op, json_text) = match rest.split_once(char::is_whitespace) {
                Some((op, json_text)) => (op, json_text.trim()),
                None => (rest, ""),
            };
            if op.is_empty() {
                return Err("usage: /call <operation> [json], e.g. /call daemon.status".to_string());
            }
            let args = if json_text.is_empty() {
                json!({})
            } else {
                let value: Value = serde_json::from_str(json_text).map_err(|e| format!("the arguments are not JSON: {e}"))?;
                if !value.is_object() {
                    return Err("the arguments must be a JSON object, like {\"key\": value}".to_string());
                }
                value
            };
            Command::Call { op: op.to_string(), args }
        }
        "activity" | "log" => parse_activity(rest, None)?,
        "logs" => parse_activity(rest, Some(Level::Warn))?,
        "config" => Command::Config,
        "update" | "updates" => parse_update(rest)?,
        "open" => match rest.to_ascii_lowercase().as_str() {
            "gui" | "window" => Command::Open("gui".to_string()),
            "tui" | "terminal" => Command::Open("tui".to_string()),
            _ => return Err("usage: /open gui or /open tui".to_string()),
        },
        "clear" | "cls" => Command::Clear,
        other => Command::Unknown(other.to_string()),
    })
}

fn parse_activity(rest: &str, default_level: Option<Level>) -> Result<Command, String> {
    let mut level = default_level;
    let mut category = None;
    let mut limit = 200usize;
    let mut words = Vec::new();
    for token in rest.split_whitespace() {
        let lower = token.to_ascii_lowercase();
        if let Some(n) = lower.strip_prefix("limit=") {
            limit = n.parse().map_err(|_| format!("limit must be a number, not {n:?}"))?;
        } else if let Some(parsed) = Level::parse(&lower).filter(|_| level == default_level) {
            level = Some(parsed);
        } else if CATEGORIES.contains(&lower.as_str()) {
            category = Some(lower);
        } else {
            words.push(token.to_string());
        }
    }
    let text = (!words.is_empty()).then(|| words.join(" "));
    Ok(Command::Activity { level, category, text, limit: limit.clamp(1, 5000) })
}

fn parse_update(rest: &str) -> Result<Command, String> {
    let mut parts = rest.split_whitespace();
    let action = match parts.next().map(str::to_ascii_lowercase).as_deref() {
        None | Some("state") => UpdateAction::State,
        Some("check") => UpdateAction::Check,
        Some("download") => UpdateAction::Download,
        Some("install") => UpdateAction::Install,
        Some("policy") => {
            let policy = parts.next().ok_or("usage: /update policy <manual|download|install>")?;
            UpdateAction::Policy(policy.to_ascii_lowercase())
        }
        Some(other) => return Err(format!("unknown update action {other:?}; try /update state, check, download, install or policy")),
    };
    Ok(Command::Update(action))
}

/// The help text: the list of commands, or one command's usage.
pub fn help(topic: Option<&str>) -> Vec<String> {
    match topic.map(|t| t.trim_start_matches('/').to_ascii_lowercase()) {
        None => {
            let mut lines = vec!["Commands (each starts with /):".to_string()];
            for entry in COMMANDS {
                lines.push(format!("  {:<12} {}", entry.name, entry.summary));
            }
            lines.push(String::new());
            lines.push("/help <command> shows its usage. Anything without a / is a note, and is not sent anywhere.".into());
            lines
        }
        Some(name) => match COMMANDS.iter().find(|e| e.name == name) {
            Some(entry) => vec![format!("usage: {}", entry.usage), format!("  {}", entry.summary)],
            None => vec![format!("no command /{name}; /help lists them")],
        },
    }
}

/// Carry out one command. Returns the lines to print (never empty for a command that has something to say).
pub fn run(command: Command) -> Vec<String> {
    match command {
        Command::Empty | Command::Clear => Vec::new(),
        Command::Plain => vec!["Commands start with /. Type /help to see them.".to_string()],
        Command::Unknown(name) => vec![format!("no command /{name}; /help lists them")],
        Command::Help(topic) => help(topic.as_deref()),
        Command::Status => lines_or_error(status_lines()),
        Command::Start => match daemon_ctl::start() {
            Ok(pid) => vec![format!("started the daemon (pid {pid})")],
            Err(e) => vec![format!("could not start: {e}")],
        },
        Command::Stop => match daemon_ctl::stop() {
            Ok(()) => vec!["stopped the daemon".to_string()],
            Err(e) => vec![format!("could not stop: {e}")],
        },
        Command::Restart => match daemon_ctl::restart() {
            Ok(pid) => vec![format!("restarted the daemon (pid {pid})")],
            Err(e) => vec![format!("could not restart: {e}")],
        },
        Command::Version => version_lines(),
        Command::Ops(filter) => lines_or_error(ops_lines(filter.as_deref())),
        Command::Call { op, args } => lines_or_error(call_lines(&op, args)),
        Command::Activity { level, category, text, limit } => {
            lines_or_error(activity_lines(level, category, text, limit))
        }
        Command::Config => match daemon_ctl::read_config() {
            Ok(text) => {
                let mut lines = vec![daemon_ctl::config_path().display().to_string()];
                lines.extend(text.lines().map(str::to_string));
                lines
            }
            Err(e) => vec![e],
        },
        Command::Update(action) => lines_or_error(update_lines(action)),
        Command::Open(kind) => {
            let op = if kind == "gui" { "gui.launch" } else { "tui.launch" };
            lines_or_error(client().and_then(|c| c.call(op, json!({}))).map(|v| vec![format!("{kind} opened: {}", compact(&v))]).map_err(|e| e.to_string()))
        }
    }
}

fn lines_or_error(result: Result<Vec<String>, String>) -> Vec<String> {
    match result {
        Ok(lines) => lines,
        Err(e) => vec![e],
    }
}

fn client() -> Result<Client, ClientError> {
    Ok(Client::connect()?.with_timeout(Duration::from_secs(60)))
}

fn call(op: &str, args: Value) -> Result<Value, String> {
    client().and_then(|c| c.call(op, args)).map_err(|e| e.to_string())
}

fn status_lines() -> Result<Vec<String>, String> {
    let s = daemon_ctl::status().map_err(|e| e.to_string())?;
    let mut lines = vec![
        format!("daemon {} (pid {}), up {}", text(&s, "version"), s["pid"], duration(s["uptime_s"].as_u64().unwrap_or(0))),
        format!("  gRPC {}   control {}", text(&s, "grpc"), text(&s, "control")),
        format!("  reachable: {}   contacts {}   transfers {}   groups {}", s["daemon_reachable"], s["contacts"], s["transfers"], s["groups"]),
        format!("  window: {}   terminal UI: {}", if s["gui"].is_null() { "closed" } else { "open" }, if s["tui"].is_null() { "closed" } else { "open" }),
    ];
    if let Some(relays) = s["relays"].as_array().filter(|r| !r.is_empty()) {
        lines.push(format!("  relays running here: {}", relays.len()));
    }
    Ok(lines)
}

fn version_lines() -> Vec<String> {
    let ours = env!("CARGO_PKG_VERSION");
    match daemon_ctl::running() {
        Some(health) => vec![format!("this tool {ours}; the running daemon {}", text(&health, "version"))],
        None => vec![format!("this tool {ours}; the daemon is not running")],
    }
}

fn ops_lines(filter: Option<&str>) -> Result<Vec<String>, String> {
    let client = client().map_err(|e| e.to_string())?;
    let ops = client.operations().map_err(|e| e.to_string())?;
    let needle = filter.map(str::to_lowercase);
    let mut lines = Vec::new();
    for op in ops {
        let id = text(&op, "id");
        let summary = text(&op, "summary");
        if let Some(n) = &needle {
            if !id.to_lowercase().contains(n) && !summary.to_lowercase().contains(n) {
                continue;
            }
        }
        let mark = if op["mutating"].as_bool().unwrap_or(false) { "change" } else { "read  " };
        lines.push(format!("  {id:<34} {mark}  {}", truncate(&summary, 80)));
    }
    if lines.is_empty() {
        lines.push("no operation matches".to_string());
    }
    Ok(lines)
}

fn call_lines(op: &str, args: Value) -> Result<Vec<String>, String> {
    let reply = call(op, args)?;
    let pretty = serde_json::to_string_pretty(&reply).unwrap_or_else(|_| reply.to_string());
    Ok(pretty.lines().map(str::to_string).collect())
}

fn activity_lines(level: Option<Level>, category: Option<String>, text_filter: Option<String>, limit: usize) -> Result<Vec<String>, String> {
    let mut args = json!({"limit": limit});
    if let Some(level) = level {
        args["level"] = json!(level.as_str());
    }
    if let Some(category) = category {
        args["category"] = json!(category);
    }
    if let Some(text_filter) = text_filter {
        args["text"] = json!(text_filter);
    }
    let reply = call("activity.list", args)?;
    let events = reply["events"].as_array().cloned().unwrap_or_default();
    if events.is_empty() {
        return Ok(vec!["no matching activity".to_string()]);
    }
    Ok(events.iter().map(format_event).collect())
}

fn update_lines(action: UpdateAction) -> Result<Vec<String>, String> {
    let (op, args) = match action {
        UpdateAction::State => ("updates.get_update_state", json!({})),
        UpdateAction::Check => ("updates.check_for_updates", json!({})),
        UpdateAction::Download => ("updates.download_update", json!({})),
        UpdateAction::Install => ("updates.apply_update", json!({})),
        UpdateAction::Policy(policy) => ("updates.set_update_policy", json!({"policy": policy})),
    };
    let reply = call(op, args)?;
    if op == "updates.apply_update" {
        return Ok(vec!["installed the latest release; restart the daemon to run it".to_string()]);
    }
    Ok(update_state_lines(&reply))
}

/// The update state in words: the two versions side by side, the policy, and anything waiting.
pub fn update_state_lines(reply: &Value) -> Vec<String> {
    let mut lines = vec![format!(
        "installed {}   latest release {}",
        text(reply, "current_version"),
        if text(reply, "latest_version").is_empty() { "not checked yet".to_string() } else { text(reply, "latest_version") }
    )];
    lines.push(format!("policy: {}", text(reply, "policy")));
    if reply["restart_required"].as_bool().unwrap_or(false) {
        lines.push("installed; restart the daemon to run the new version".to_string());
    } else if !text(reply, "staged_version").is_empty() {
        lines.push(format!("downloaded and verified: {} (ready to install)", text(reply, "staged_version")));
    }
    let error = text(reply, "error");
    if !error.is_empty() {
        lines.push(format!("error: {error}"));
    }
    lines
}

/// One activity event as a line: `2026-11-08 10:02:11 warn  lanes    transferd::transport: message  k=v`.
pub fn format_event(event: &Value) -> String {
    let fields = event["fields"]
        .as_object()
        .map(|f| f.iter().map(|(k, v)| format!("  {k}={}", v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string()))).collect::<String>())
        .unwrap_or_default();
    format!(
        "{} {:<5} {:<9} {}: {}{}",
        format_utc(event["ts_ms"].as_u64().unwrap_or(0)),
        text(event, "level"),
        text(event, "category"),
        text(event, "source"),
        text(event, "message"),
        fields
    )
}

/// A time in milliseconds since the Unix epoch, as `YYYY-MM-DD HH:MM:SS` in UTC.
pub fn format_utc(ms: u64) -> String {
    let secs = ms / 1000;
    let (y, m, d) = civil_from_days((secs / 86_400) as i64);
    let rem = secs % 86_400;
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}", rem / 3600, rem % 3600 / 60, rem % 60)
}

/// Year, month and day for a count of days since 1970-01-01 (proleptic Gregorian calendar).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn text(v: &Value, key: &str) -> String {
    v[key].as_str().map(str::to_string).unwrap_or_default()
}

fn compact(v: &Value) -> String {
    serde_json::to_string(v).unwrap_or_default()
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let head: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{head}…")
    }
}

fn duration(secs: u64) -> String {
    let (d, h, m) = (secs / 86_400, secs % 86_400 / 3600, secs % 3600 / 60);
    if d > 0 {
        format!("{d}d {h}h {m}m")
    } else if h > 0 {
        format!("{h}h {m}m")
    } else {
        format!("{m}m {}s", secs % 60)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn plain_lines_and_blanks_are_not_commands() {
        assert_eq!(parse("   ").unwrap(), Command::Empty);
        assert_eq!(parse("hello there").unwrap(), Command::Plain);
    }

    #[test]
    fn slash_commands_parse_with_their_arguments() {
        assert_eq!(parse("/STATUS").unwrap(), Command::Status);
        assert_eq!(parse("/help call").unwrap(), Command::Help(Some("call".into())));
        assert_eq!(parse("/ops daemon").unwrap(), Command::Ops(Some("daemon".into())));
        assert_eq!(parse("/clear").unwrap(), Command::Clear);
        assert_eq!(parse("/open gui").unwrap(), Command::Open("gui".into()));
        assert!(parse("/open cloud").is_err());
        assert_eq!(parse("/bogus").unwrap(), Command::Unknown("bogus".into()));
    }

    #[test]
    fn call_takes_an_operation_and_a_json_object() {
        assert_eq!(
            parse("/call activity.record {\"message\": \"hi\"}").unwrap(),
            Command::Call { op: "activity.record".into(), args: json!({"message": "hi"}) }
        );
        assert_eq!(parse("/call daemon.status").unwrap(), Command::Call { op: "daemon.status".into(), args: json!({}) });
        assert!(parse("/call").is_err());
        assert!(parse("/call daemon.status [1]").is_err(), "arguments must be an object");
        assert!(parse("/call daemon.status {oops").is_err());
    }

    #[test]
    fn activity_reads_levels_categories_text_and_limits() {
        assert_eq!(
            parse("/activity warn lanes limit=50").unwrap(),
            Command::Activity { level: Some(Level::Warn), category: Some("lanes".into()), text: None, limit: 50 }
        );
        assert_eq!(
            parse("/activity relay refused").unwrap(),
            Command::Activity { level: None, category: Some("relay".into()), text: Some("refused".into()), limit: 200 }
        );
        assert_eq!(
            parse("/logs").unwrap(),
            Command::Activity { level: Some(Level::Warn), category: None, text: None, limit: 200 }
        );
        assert!(parse("/activity limit=lots").is_err());
    }

    #[test]
    fn update_actions_parse() {
        assert_eq!(parse("/update").unwrap(), Command::Update(UpdateAction::State));
        assert_eq!(parse("/update policy Download").unwrap(), Command::Update(UpdateAction::Policy("download".into())));
        assert!(parse("/update policy").is_err());
        assert!(parse("/update fly").is_err());
    }

    #[test]
    fn help_lists_every_command_and_explains_one() {
        let all = help(None);
        for entry in COMMANDS {
            assert!(all.iter().any(|l| l.contains(entry.name)), "{} is listed", entry.name);
        }
        assert_eq!(help(Some("/restart")), vec!["usage: /restart".to_string(), "  Stop the daemon, then start it again".to_string()]);
        assert!(help(Some("nope"))[0].contains("no command"));
    }

    #[test]
    fn times_are_utc_calendar_dates() {
        assert_eq!(format_utc(0), "1970-01-01 00:00:00");
        assert_eq!(format_utc(1_700_000_000_000), "2023-11-14 22:13:20");
        assert_eq!(format_utc(951_782_400_000), "2000-02-29 00:00:00", "leap years are counted");
    }

    #[test]
    fn an_event_reads_as_one_line() {
        let event = json!({"ts_ms": 0, "level": "warn", "category": "lanes", "source": "transferd::transport",
                           "message": "lane stalled", "fields": {"peer": "bob"}});
        assert_eq!(format_event(&event), "1970-01-01 00:00:00 warn  lanes     transferd::transport: lane stalled  peer=bob");
    }

    #[test]
    fn the_update_state_says_both_versions() {
        let reply = json!({"current_version": "2.4.0-dev", "latest_version": "2.3.0", "policy": "manual",
                           "staged_version": "", "restart_required": false, "error": ""});
        let lines = update_state_lines(&reply);
        assert_eq!(lines[0], "installed 2.4.0-dev   latest release 2.3.0");
        assert_eq!(lines[1], "policy: manual");
    }
}
