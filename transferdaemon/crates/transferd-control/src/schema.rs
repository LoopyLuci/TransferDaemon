//! JSON Schemas for the gRPC messages, read from `transferd.proto` itself.
//!
//! The catalog describes every operation's arguments and result with a JSON Schema. Writing those by hand would drift
//! from the proto, so this reads the proto (compiled in with `include_str!`) and builds them: messages, their fields,
//! `repeated` fields, nested messages, enums and the comments beside fields. Only the proto3 subset the file uses is
//! understood (no maps, imports or options), which is checked by a test.

use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

/// The proto source the gRPC code was generated from.
pub const PROTO: &str = include_str!("../../transferd-api/proto/transferd.proto");

#[derive(Debug, Clone)]
pub struct Field {
    pub name: String,
    pub ty: String,
    pub repeated: bool,
    pub oneof: Option<String>,
    pub doc: String,
}

#[derive(Debug, Clone)]
pub struct Rpc {
    pub service: String,
    pub name: String,
    pub input: String,
    pub output: String,
    pub server_streaming: bool,
    pub doc: String,
}

#[derive(Debug, Default, Clone)]
pub struct Proto {
    pub messages: BTreeMap<String, Vec<Field>>,
    pub enums: BTreeMap<String, Vec<String>>,
    pub rpcs: Vec<Rpc>,
}

fn strip_comment(line: &str) -> (&str, &str) {
    match line.find("//") {
        Some(i) => (&line[..i], line[i + 2..].trim()),
        None => (line, ""),
    }
}

/// Parse the proto3 subset `transferd.proto` uses.
pub fn parse(src: &str) -> Proto {
    let mut p = Proto::default();
    // A flat token walk over lines is enough: every declaration in the file sits on its own line or on one line.
    let mut stack: Vec<(String, String)> = vec![]; // (kind, name)
    let mut pending_doc: Vec<String> = vec![];
    for raw in src.lines() {
        let (code, comment) = strip_comment(raw);
        let code = code.trim();
        if code.is_empty() {
            if !comment.is_empty() && !comment.starts_with("---") {
                pending_doc.push(comment.to_string());
            } else if comment.is_empty() {
                pending_doc.clear();
            }
            continue;
        }
        // One-line messages: `message X { string a = 1; }`
        let mut rest = code.to_string();
        while !rest.is_empty() {
            let trimmed = rest.trim_start().to_string();
            if trimmed.is_empty() {
                break;
            }
            if let Some(after) = trimmed.strip_prefix('}') {
                stack.pop();
                rest = after.to_string();
                continue;
            }
            let (stmt, tail) = match (trimmed.find(';'), trimmed.find('{')) {
                (Some(s), Some(b)) if b < s => (trimmed[..=b].to_string(), trimmed[b + 1..].to_string()),
                (Some(s), _) => (trimmed[..=s].to_string(), trimmed[s + 1..].to_string()),
                (None, Some(b)) => (trimmed[..=b].to_string(), trimmed[b + 1..].to_string()),
                (None, None) => (trimmed.clone(), String::new()),
            };
            rest = tail;
            let words: Vec<&str> = stmt
                .split(|c: char| c.is_whitespace() || c == '(' || c == ')' || c == '{' || c == ';' || c == '=')
                .filter(|w| !w.is_empty())
                .collect();
            if words.is_empty() {
                continue;
            }
            let doc = {
                let mut d = pending_doc.join(" ");
                if !comment.is_empty() {
                    if !d.is_empty() {
                        d.push(' ');
                    }
                    d.push_str(comment);
                }
                d
            };
            match words[0] {
                "syntax" | "package" | "option" | "import" => {}
                "service" | "message" | "enum" | "oneof" if stmt.ends_with('{') => {
                    let kind = words[0].to_string();
                    let name = words.get(1).copied().unwrap_or_default().to_string();
                    if kind == "message" {
                        p.messages.entry(name.clone()).or_default();
                    } else if kind == "enum" {
                        p.enums.entry(name.clone()).or_default();
                    }
                    stack.push((kind, name));
                }
                "rpc" => {
                    // rpc Name (Input) returns (stream Output);
                    let service = stack.iter().rev().find(|(k, _)| k == "service").map(|(_, n)| n.clone()).unwrap_or_default();
                    let returns = words.iter().position(|w| *w == "returns").unwrap_or(0);
                    let streaming = words.get(returns + 1) == Some(&"stream");
                    let output = words.get(returns + if streaming { 2 } else { 1 }).copied().unwrap_or_default();
                    p.rpcs.push(Rpc {
                        service,
                        name: words.get(1).copied().unwrap_or_default().to_string(),
                        input: words.get(2).copied().unwrap_or_default().to_string(),
                        output: output.to_string(),
                        server_streaming: streaming,
                        doc,
                    });
                }
                _ => {
                    let Some((kind, name)) = stack.last().cloned() else { continue };
                    if kind == "enum" {
                        p.enums.entry(name).or_default().push(words[0].to_string());
                    } else if kind == "message" || kind == "oneof" {
                        let message = stack.iter().rev().find(|(k, _)| k == "message").map(|(_, n)| n.clone()).unwrap_or_default();
                        let repeated = words[0] == "repeated";
                        let (ty, fname) = if repeated { (words.get(1), words.get(2)) } else { (words.first(), words.get(1)) };
                        if let (Some(ty), Some(fname)) = (ty, fname) {
                            p.messages.entry(message).or_default().push(Field {
                                name: fname.to_string(),
                                ty: ty.to_string(),
                                repeated,
                                oneof: (kind == "oneof").then(|| name.clone()),
                                doc,
                            });
                        }
                    }
                }
            }
            pending_doc.clear();
        }
    }
    p
}

impl Proto {
    /// The JSON Schema of a message (nested messages inlined, to a depth limit).
    pub fn schema(&self, message: &str) -> Value {
        self.schema_depth(message, 0)
    }

    fn schema_depth(&self, message: &str, depth: usize) -> Value {
        let Some(fields) = self.messages.get(message) else {
            return json!({"type": "object"});
        };
        let mut props = Map::new();
        for f in fields {
            let mut s = self.type_schema(&f.ty, depth);
            if !f.doc.is_empty() {
                if let Some(o) = s.as_object_mut() {
                    o.insert("description".into(), Value::String(f.doc.clone()));
                }
            }
            if let Some(group) = &f.oneof {
                if let Some(o) = s.as_object_mut() {
                    let note = format!("one of the `{group}` fields");
                    let d = o.get("description").and_then(Value::as_str).map(|d| format!("{d} ({note})")).unwrap_or(note);
                    o.insert("description".into(), Value::String(d));
                }
            }
            if f.repeated {
                s = json!({"type": "array", "items": s});
            }
            props.insert(f.name.clone(), s);
        }
        json!({"type": "object", "properties": props, "additionalProperties": false})
    }

    fn type_schema(&self, ty: &str, depth: usize) -> Value {
        match ty {
            "string" => json!({"type": "string"}),
            "bool" => json!({"type": "boolean"}),
            "int32" | "sint32" | "sfixed32" | "int64" | "sint64" | "sfixed64" => json!({"type": "integer"}),
            "uint32" | "fixed32" | "uint64" | "fixed64" => json!({"type": "integer", "minimum": 0}),
            "float" | "double" => json!({"type": "number"}),
            "bytes" => json!({"type": "array", "items": {"type": "integer", "minimum": 0, "maximum": 255}}),
            other => {
                if let Some(values) = self.enums.get(other) {
                    let described: Vec<String> = values.iter().enumerate().map(|(i, v)| format!("{i} = {v}")).collect();
                    json!({"type": "integer", "enum": (0..values.len()).collect::<Vec<_>>(),
                           "description": described.join(", ")})
                } else if depth < 4 {
                    self.schema_depth(other, depth + 1)
                } else {
                    json!({"type": "object"})
                }
            }
        }
    }

    /// The `(field, enum values)` pairs of a message, so callers can pass enum names instead of numbers.
    pub fn enum_fields(&self, message: &str) -> Vec<(String, Vec<String>)> {
        self.messages
            .get(message)
            .map(|fs| {
                fs.iter()
                    .filter_map(|f| self.enums.get(&f.ty).map(|v| (f.name.clone(), v.clone())))
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Parsed once.
pub fn proto() -> &'static Proto {
    static P: std::sync::OnceLock<Proto> = std::sync::OnceLock::new();
    P.get_or_init(|| parse(PROTO))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_rpc_and_message_is_understood() {
        let p = proto();
        assert!(p.rpcs.len() >= 45, "only {} rpcs parsed", p.rpcs.len());
        for r in &p.rpcs {
            assert!(p.messages.contains_key(&r.input), "{}: no message {}", r.name, r.input);
            assert!(p.messages.contains_key(&r.output), "{}: no message {}", r.name, r.output);
        }
        let send = p.schema("SendTextRequest");
        assert_eq!(send["properties"]["contact_id"]["type"], "string");
        assert!(send["properties"]["reply_to"]["description"].as_str().unwrap_or("").contains("replied"));
        let group = p.schema("GroupReply");
        assert_eq!(group["properties"]["members"]["type"], "array");
        assert_eq!(group["properties"]["members"]["items"]["properties"]["role"]["type"], "integer");
        assert!(p.rpcs.iter().any(|r| r.name == "StreamTelemetry" && r.server_streaming));
        assert!(p.rpcs.iter().any(|r| r.name == "StreamTelemetry" && r.doc.contains("Live event stream")));
        let ev = p.schema("TelemetryEventMsg");
        assert!(ev["properties"]["system_health"]["description"].as_str().unwrap_or("").contains("event"));
        assert_eq!(p.enum_fields("SetMemberRoleRequest"), vec![("role".to_string(), p.enums["GroupRole"].clone())]);
    }
}
