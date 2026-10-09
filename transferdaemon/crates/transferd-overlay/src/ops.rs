//! The `overlay.*` operations, as JSON in and JSON out.
//!
//! These names and shapes are the contract the control hub, the CLI, the MCP tools and ABP all
//! build against; keeping the implementation here means the hub only has to forward, and the
//! operations can be tested without an HTTP server in the way.
//!
//! | Operation | Arguments | Returns |
//! |---|---|---|
//! | `overlay.status` | — | `{node_id, name, version, protocol_versions, lanes, relays, nat}` |
//! | `overlay.peers` | — | `[{node_id, name, state, routes, services}]` |
//! | `overlay.invite_create` | `{ttl_s}` | `{invite}` |
//! | `overlay.invite_accept` | `{invite, name?}` | `{node_id, name}` |
//! | `overlay.expose` | `{service, local_addr, allow}` | — |
//! | `overlay.unexpose` | `{service}` | — |
//! | `overlay.connect` | `{node_id\|group, service}` | `{local_addr, route}` |
//! | `overlay.disconnect` | `{local_addr}` | — |
//! | `overlay.services` | — | — |
//! | `overlay.proxy_status` | — | `{socks5_addr, http_proxy_addr}` |
//! | `overlay.events` | `{seconds?, max?}` | a stream of events |
//! | `overlay.audit` | `{limit?}` | the audit trail |
//! | `overlay.proxies_start` | — | `{socks5_addr, http_proxy_addr}` |
//! | `overlay.group_set` | `{name, members}` | — |
//! | `overlay.probe` | `{node_id}` | what one node can reach |
//! | `overlay.dns_set` | `{upstreams, listen?, service?, timeout_ms?}` | mesh DNS on (empty `upstreams`: off) |
//! | `overlay.dns_status` | — | the forwarder, its counters per upstream, and what this node shares |

use std::sync::Arc;

use serde_json::{json, Value};

use crate::error::OverlayError;
use crate::node::OverlayNode;
use crate::protocol::VERSION_CURRENT;

/// Run one operation by id.
pub async fn call(node: &Arc<OverlayNode>, op: &str, args: Value) -> Result<Value, OverlayError> {
    match op {
        "overlay.status" => Ok(node.status()),
        "overlay.peers" => Ok(json!(node.peer_list())),
        "overlay.invite_create" => {
            let ttl = args.get("ttl_s").and_then(Value::as_u64).unwrap_or(900);
            Ok(json!({"invite": node.invite_create(ttl)}))
        }
        "overlay.invite_accept" => {
            let invite = str_arg(&args, "invite")?;
            let name = args.get("name").and_then(Value::as_str).map(str::to_string);
            let record = node.invite_accept(&invite, name)?;
            Ok(json!({"node_id": record.node_id, "name": record.name}))
        }
        "overlay.expose" => {
            let service = str_arg(&args, "service")?;
            let local = str_arg(&args, "local_addr")?;
            let addr: std::net::SocketAddr = local
                .parse()
                .map_err(|_| OverlayError::protocol(format!("{local} is not host:port")))?;
            let allow = args
                .get("allow")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            let description = args
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or_default();
            node.expose(&service, addr, allow, description)?;
            Ok(json!({}))
        }
        "overlay.unexpose" => {
            let service = str_arg(&args, "service")?;
            node.unexpose(&service)?;
            Ok(json!({}))
        }
        "overlay.connect" => {
            let service = str_arg(&args, "service")?;
            let target = args
                .get("node_id")
                .and_then(Value::as_str)
                .or_else(|| args.get("group").and_then(Value::as_str))
                .ok_or_else(|| OverlayError::protocol("connect needs node_id or group"))?
                .to_string();
            let (local, route) = node.connect(&target, &service).await?;
            Ok(
                json!({"local_addr": local.to_string(), "route": route.as_str(), "service": service}),
            )
        }
        "overlay.disconnect" => {
            let local = str_arg(&args, "local_addr")?;
            let addr: std::net::SocketAddr = local
                .parse()
                .map_err(|_| OverlayError::protocol(format!("{local} is not host:port")))?;
            node.disconnect(addr)?;
            Ok(json!({}))
        }
        "overlay.services" => Ok(json!({
            "exposed": node.service_details(),
            "connected": node.connect_details(),
            "groups": node.groups(),
        })),
        "overlay.proxy_status" => {
            let proxies = node.proxy_status();
            Ok(json!({
                "socks5_addr": proxies.socks5.map(|a| a.to_string()),
                "http_proxy_addr": proxies.http.map(|a| a.to_string()),
            }))
        }
        "overlay.proxies_start" => {
            let (socks, http) = node.start_proxies().await?;
            Ok(json!({"socks5_addr": socks.to_string(), "http_proxy_addr": http.to_string()}))
        }
        "overlay.events" => {
            let seconds = args
                .get("seconds")
                .and_then(Value::as_f64)
                .unwrap_or(5.0)
                .clamp(0.2, 120.0);
            let max = args
                .get("max")
                .and_then(Value::as_u64)
                .unwrap_or(200)
                .max(1) as usize;
            Ok(json!(collect_events(node, seconds, max).await))
        }
        "overlay.audit" => {
            let limit = args
                .get("limit")
                .and_then(Value::as_u64)
                .unwrap_or(100)
                .min(2000) as usize;
            let records: Vec<Value> = node
                .audit_trail()
                .recent(limit)
                .iter()
                .map(|r| serde_json::to_value(r).unwrap_or(Value::Null))
                .collect();
            Ok(json!(records))
        }
        "overlay.group_set" => {
            let name = str_arg(&args, "name")?;
            let members = args
                .get("members")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            node.set_group(&name, members);
            Ok(json!({}))
        }
        "overlay.probe" => {
            let target = str_arg(&args, "node_id")?;
            let session = node.ensure_session(&target).await?;
            Ok(json!({
                "node_id": target,
                "routes": session.routes(),
                "protocol_version": session.version(),
                "services": session.services.read().clone(),
            }))
        }
        "overlay.dns_set" => {
            let upstreams: Vec<String> = args
                .get("upstreams")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::trim).map(str::to_string))
                        .filter(|s| !s.is_empty())
                        .collect()
                })
                .unwrap_or_default();
            if upstreams.is_empty() {
                return node.set_mesh_dns(None).await;
            }
            let mut config = crate::dns::MeshDnsConfig::new(upstreams);
            if let Some(listen) = args.get("listen").and_then(Value::as_str) {
                config.listen = listen.to_string();
            }
            if let Some(service) = args
                .get("service")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
            {
                config.service = service.to_string();
            }
            if let Some(ms) = args.get("timeout_ms").and_then(Value::as_u64) {
                config.timeout_ms = ms;
            }
            node.set_mesh_dns(Some(config)).await
        }
        "overlay.dns_status" => Ok(node.mesh_dns_status()),
        other => Err(OverlayError::protocol(format!(
            "no overlay operation {other:?}"
        ))),
    }
}

/// The operation ids this dispatcher answers, with their schemas. The control hub publishes
/// these through `GET /v1/operations`, so a client can discover them at runtime.
pub fn operations() -> Vec<(&'static str, &'static str, bool, Value, Value)> {
    let obj = |props: Value, required: &[&str]| json!({"type": "object", "properties": props, "required": required});
    vec![
        ("overlay.status", "This node: id, name, version, protocol versions, its routes to every peer, its relays, and its NAT view", false, obj(json!({}), &[]), obj(json!({
            "node_id": {"type": "string"}, "name": {"type": "string"}, "version": {"type": "string"},
            "protocol_versions": {"type": "object"}, "lanes": {"type": "array"},
            "relays": {"type": "array"}, "nat": {"type": "object"}}), &[])),
        ("overlay.peers", "Every paired node: its state, the measured quality of each route to it, and the services it offers", false, obj(json!({}), &[]), obj(json!({"type": "array"}), &[])),
        ("overlay.invite_create", "Create a pairing invite: this node's identity and how to reach it, signed, valid for ttl_s", false,
            obj(json!({"ttl_s": {"type": "integer", "description": "how long the invite is valid (default 900)"}}), &[]),
            obj(json!({"invite": {"type": "string"}}), &[])),
        ("overlay.invite_accept", "Pair with a node from its invite (trust on first use: a changed identity is refused)", true,
            obj(json!({"invite": {"type": "string"}, "name": {"type": "string"}}), &["invite"]),
            obj(json!({"node_id": {"type": "string"}, "name": {"type": "string"}}), &[])),
        ("overlay.expose", "Publish a local service to chosen paired nodes; nothing is exposed by default", true,
            obj(json!({"service": {"type": "string"}, "local_addr": {"type": "string", "description": "host:port to forward to"},
                       "allow": {"type": "array", "items": {"type": "string"}, "description": "node ids, and/or \"*paired\""},
                       "description": {"type": "string"}}), &["service", "local_addr"]),
            obj(json!({}), &[])),
        ("overlay.unexpose", "Withdraw a published service", true, obj(json!({"service": {"type": "string"}}), &["service"]), obj(json!({}), &[])),
        ("overlay.connect", "Reach a node's service (by node id or by group) and get a stable local endpoint", true,
            obj(json!({"node_id": {"type": "string"}, "group": {"type": "string"}, "service": {"type": "string"}}), &["service"]),
            obj(json!({"local_addr": {"type": "string"}, "route": {"type": "string"}, "service": {"type": "string"}}), &[])),
        ("overlay.disconnect", "Close a forwarded endpoint", true, obj(json!({"local_addr": {"type": "string"}}), &["local_addr"]), obj(json!({}), &[])),
        ("overlay.services", "What this node exposes, what it has connected, and its service groups", false, obj(json!({}), &[]),
            obj(json!({"exposed": {"type": "array"}, "connected": {"type": "array"}, "groups": {"type": "array"}}), &[])),
        ("overlay.proxy_status", "Where the local SOCKS5 and HTTP-CONNECT proxies are listening", false, obj(json!({}), &[]),
            obj(json!({"socks5_addr": {"type": ["string", "null"]}, "http_proxy_addr": {"type": ["string", "null"]}}), &[])),
        ("overlay.proxies_start", "Start the local SOCKS5 and HTTP-CONNECT proxies, so any app can use <service>.<node>.td", true,
            obj(json!({}), &[]), obj(json!({"socks5_addr": {"type": "string"}, "http_proxy_addr": {"type": "string"}}), &[])),
        ("overlay.events", "Live events (peer up/down, route change, service exposed) for a few seconds", false,
            obj(json!({"seconds": {"type": "number"}, "max": {"type": "integer"}}), &[]), obj(json!({"type": "array"}), &[])),
        ("overlay.audit", "The audit trail of exposes, connects and refusals", false,
            obj(json!({"limit": {"type": "integer"}}), &[]), obj(json!({"type": "array"}), &[])),
        ("overlay.group_set", "Define a service group: any node in it may serve the service", true,
            obj(json!({"name": {"type": "string"}, "members": {"type": "array", "items": {"type": "string"}}}), &["name"]),
            obj(json!({}), &[])),
        ("overlay.probe", "What one node can reach right now: its routes, protocol version and services", false,
            obj(json!({"node_id": {"type": "string"}}), &["node_id"]),
            obj(json!({"node_id": {"type": "string"}, "routes": {"type": "array"}}), &[])),
        ("overlay.dns_set", "Mesh DNS: answer DNS on a local address (default 127.0.0.1:53053) through paired nodes' resolvers (their \"dns\" service), tried in order; no upstreams turns it off", true,
            obj(json!({"upstreams": {"type": "array", "items": {"type": "string"}, "description": "node ids or group names, in order"},
                       "listen": {"type": "string", "description": "host:port for UDP and TCP"},
                       "service": {"type": "string", "description": "the service name the resolvers are shared under (default dns)"},
                       "timeout_ms": {"type": "integer"}}), &["upstreams"]),
            obj(json!({"enabled": {"type": "boolean"}, "listen": {"type": "string"}}), &[])),
        ("overlay.dns_status", "Mesh DNS: where it answers, each upstream's health and counters (queries, answered, blocked, NXDOMAIN, timeouts, average ms), and the resolver this node shares", false,
            obj(json!({}), &[]),
            obj(json!({"enabled": {"type": "boolean"}, "upstreams": {"type": "array"}, "totals": {"type": "object"}, "serving": {}}), &[])),
    ]
}

/// The version this build speaks, for a client that wants to check before calling anything.
pub fn version_info() -> Value {
    json!({"min": crate::protocol::VERSION_MIN, "current": VERSION_CURRENT})
}

async fn collect_events(node: &Arc<OverlayNode>, seconds: f64, max: usize) -> Vec<Value> {
    let mut out: Vec<Value> = node
        .events()
        .recent(max)
        .iter()
        .map(|e| serde_json::to_value(e).unwrap_or(Value::Null))
        .collect();
    let mut rx = node.events().subscribe();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs_f64(seconds);
    while out.len() < max {
        let Ok(received) = tokio::time::timeout_at(deadline, rx.recv()).await else {
            break;
        };
        match received {
            Ok(event) => out.push(serde_json::to_value(&event).unwrap_or(Value::Null)),
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
            Err(_) => break,
        }
    }
    out
}

fn str_arg(args: &Value, key: &str) -> Result<String, OverlayError> {
    args.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .ok_or_else(|| OverlayError::protocol(format!("{key} is required")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn an_unknown_operation_is_refused_rather_than_guessed() {
        let node = OverlayNode::start(crate::node::OverlayConfig::local(
            crate::NodeIdentity::generate("t"),
        ))
        .await
        .expect("a node");
        let err = call(&node, "overlay.nonsense", json!({}))
            .await
            .expect_err("refused");
        assert_eq!(err.code(), "protocol");
    }

    #[tokio::test]
    async fn status_reports_the_node_itself() {
        let identity = crate::NodeIdentity::generate("test-node");
        let node = OverlayNode::start(crate::OverlayConfig::local(identity.clone()))
            .await
            .expect("a node");
        let status = call(&node, "overlay.status", json!({}))
            .await
            .expect("status");
        assert_eq!(status["node_id"], identity.node_id());
        assert_eq!(status["name"], "test-node");
        assert_eq!(status["protocol_versions"]["current"], VERSION_CURRENT);
        assert_eq!(
            status["nat"]["type"], "unknown",
            "no relay, so no reachability view"
        );
        assert!(
            status["proxies"]["socks5_addr"].is_null(),
            "proxies are opt-in"
        );
    }

    #[tokio::test]
    async fn nothing_is_exposed_or_connected_by_default() {
        let node = OverlayNode::start(crate::OverlayConfig::local(crate::NodeIdentity::generate(
            "t",
        )))
        .await
        .expect("a node");
        assert!(node.service_details().is_empty());
        assert!(node.connect_details().is_empty());
        let services = call(&node, "overlay.services", json!({}))
            .await
            .expect("services");
        assert!(services["exposed"].as_array().expect("an array").is_empty());
        let proxies = call(&node, "overlay.proxy_status", json!({}))
            .await
            .expect("proxies");
        assert!(proxies["socks5_addr"].is_null());
        assert!(proxies["http_proxy_addr"].is_null());
    }

    #[tokio::test]
    async fn exposing_requires_a_service_and_an_address() {
        let node = OverlayNode::start(crate::OverlayConfig::local(crate::NodeIdentity::generate(
            "t",
        )))
        .await
        .expect("a node");
        assert!(call(&node, "overlay.expose", json!({"service": "http"}))
            .await
            .is_err());
        assert!(call(
            &node,
            "overlay.expose",
            json!({"service": "http", "local_addr": "not-an-addr"})
        )
        .await
        .is_err());
        call(
            &node,
            "overlay.expose",
            json!({"service": "http", "local_addr": "127.0.0.1:8000", "allow": ["*paired"]}),
        )
        .await
        .expect("expose");
        let services = call(&node, "overlay.services", json!({}))
            .await
            .expect("services");
        assert_eq!(services["exposed"][0]["service"], "http");
        call(&node, "overlay.unexpose", json!({"service": "http"}))
            .await
            .expect("unexpose");
        assert!(node.service_details().is_empty());
    }

    #[tokio::test]
    async fn an_invite_round_trips_between_two_nodes() {
        let a = OverlayNode::start(crate::OverlayConfig::local(crate::NodeIdentity::generate(
            "a",
        )))
        .await
        .expect("a node");
        let b = OverlayNode::start(crate::OverlayConfig::local(crate::NodeIdentity::generate(
            "b",
        )))
        .await
        .expect("a node");
        let invite = call(&a, "overlay.invite_create", json!({"ttl_s": 600}))
            .await
            .expect("invite")["invite"]
            .as_str()
            .expect("a string")
            .to_string();
        let paired = call(
            &b,
            "overlay.invite_accept",
            json!({"invite": invite, "name": "laptop"}),
        )
        .await
        .expect("pair");
        assert_eq!(paired["node_id"], a.node_id());
        assert_eq!(paired["name"], "laptop");
        // And it is in the peer list, so `overlay.peers` shows it.
        let peers = call(&b, "overlay.peers", json!({})).await.expect("peers");
        let list = peers.as_array().expect("an array");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0]["node_id"], a.node_id());
    }

    #[tokio::test]
    async fn every_published_operation_is_runnable_or_explicitly_about_the_network() {
        // The catalog must not drift from the dispatcher: anything published has to exist.
        let node = OverlayNode::start(crate::OverlayConfig::local(crate::NodeIdentity::generate(
            "t",
        )))
        .await
        .expect("a node");
        for (id, _, _, _, _) in operations() {
            let args = match id {
                "overlay.invite_accept" => json!({"invite": "nonsense"}),
                "overlay.expose" => {
                    json!({"service": "http", "local_addr": "127.0.0.1:1", "allow": []})
                }
                "overlay.unexpose" => json!({"service": "http"}),
                "overlay.connect" | "overlay.probe" => {
                    json!({"node_id": &"a".repeat(64), "service": "http"})
                }
                "overlay.disconnect" => json!({"local_addr": "127.0.0.1:1"}),
                "overlay.group_set" => json!({"name": "g", "members": []}),
                _ => json!({}),
            };
            let result = call(&node, id, args).await;
            // These reach outside the node by design (a peer, or an invite from someone else);
            // everything else must answer with nothing but this node.
            if matches!(
                id,
                "overlay.connect" | "overlay.probe" | "overlay.invite_accept"
            ) {
                assert!(
                    result.is_err(),
                    "{id} needs a reachable node or a real invite"
                );
            } else {
                assert!(result.is_ok(), "{id} answered: {:?}", result.err());
            }
        }
    }
}
