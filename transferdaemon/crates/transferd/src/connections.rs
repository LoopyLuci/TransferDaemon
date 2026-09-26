//! ConnectionService — the transport control center.
//!
//! Enumerates the machine's network interfaces (Wi-Fi / Ethernet / USB /
//! Bluetooth / VPN) plus virtual transports (relay, direct TCP), exposes the
//! global lane policy, and streams live per-lane health for the UI.

use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use transferd_api::{
    ConnectionService, Connection, ConnectionList, ConnectionStatusMsg,
    SetConnectionPolicyRequest, Empty,
};

use crate::state::DaemonState;

type State = Arc<Mutex<DaemonState>>;
type BoxStream<T> = Pin<Box<dyn futures::Stream<Item = Result<T, Status>> + Send>>;

/// Policy key in daemon settings.
pub const POLICY_SETTING: &str = "conn.policy";

pub struct ConnectionServiceImpl(pub State);

impl ConnectionServiceImpl {
    /// Enumerate physical interfaces via `netdev`.
    fn physical_interfaces(&self) -> Vec<Connection> {
        let mut out = Vec::new();
        for iface in netdev::get_interfaces() {
                let name = iface.name.clone();
                let up = iface.is_up();
                let has_addr = !iface.ipv4.is_empty() || !iface.ipv6.is_empty();
                out.push(Connection {
                    id: format!("if:{name}"),
                    name: name.clone(),
                    kind: classify_interface(&name).into(),
                    enabled: up,
                    online: up && has_addr,
                    link_speed_bps: iface.transmit_speed.unwrap_or(0),
                    rtt_ms: 0.0,
                    bandwidth_bps: 0,
                    policy: String::new(),
                });
        }
        out
    }

    /// Virtual transports (relay when running, direct TCP always).
    fn virtual_connections(&self) -> Vec<Connection> {
        let s = self.0.lock();
        let relay = s.relay_hub.is_some();
        let policy = s.settings.get(POLICY_SETTING).cloned().unwrap_or_else(|| "auto".into());
        let mut out = vec![Connection {
            id: "direct".into(),
            name: "Direct TCP".into(),
            kind: "direct".into(),
            enabled: policy != "relay",
            online: true,
            link_speed_bps: 0,
            rtt_ms: 0.0,
            bandwidth_bps: 0,
            policy: String::new(),
        }];
        out.push(Connection {
            id: "relay".into(),
            name: "Relay network".into(),
            kind: "relay".into(),
            enabled: relay && policy != "direct",
            online: relay,
            link_speed_bps: 0,
            rtt_ms: 0.0,
            bandwidth_bps: 0,
            policy: String::new(),
        });
        out
    }
}

#[tonic::async_trait]
impl ConnectionService for ConnectionServiceImpl {
    async fn list_connections(&self, _: Request<Empty>) -> Result<Response<ConnectionList>, Status> {
        let mut connections = self.physical_interfaces();
        connections.extend(self.virtual_connections());
        Ok(Response::new(ConnectionList { connections }))
    }

    async fn set_connection_policy(
        &self, req: Request<SetConnectionPolicyRequest>,
    ) -> Result<Response<Empty>, Status> {
        let r = req.into_inner();
        let policy = r.policy;
        if !matches!(policy.as_str(), "auto" | "direct" | "relay" | "stripe") {
            return Err(Status::invalid_argument("policy must be auto|direct|relay|stripe"));
        }
        let mut s = self.0.lock();
        s.settings.insert(POLICY_SETTING.to_string(), policy);
        s.try_save();
        Ok(Response::new(Empty {}))
    }

    type StreamConnectionStatusStream = BoxStream<ConnectionStatusMsg>;

    async fn stream_connection_status(
        &self, _: Request<Empty>,
    ) -> Result<Response<Self::StreamConnectionStatusStream>, Status> {
        let (tx, rx) = mpsc::channel::<Result<ConnectionStatusMsg, Status>>(16);
        let state = self.0.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            loop {
                interval.tick().await;
                let transport = state.lock().transport.clone();
                let msgs = {
                    let pm = transport.lock().await;
                    let mut items = Vec::new();
                    for (contact_id, session) in pm.sessions() {
                        for lane in session.lanes() {
                            let m = lane.metrics();
                            items.push(ConnectionStatusMsg {
                                connection_id: format!("lane:{}:{}", contact_id, lane.id()),
                                rtt_ms: m.rtt_ms.load(Ordering::Relaxed) as f64 / 1000.0,
                                bandwidth_bps: m.bandwidth_bps.load(Ordering::Relaxed),
                                active_chunks: m.active_chunks.load(Ordering::Relaxed),
                                online: m.is_healthy(),
                            });
                        }
                    }
                    items
                };
                for msg in msgs {
                    if tx.send(Ok(msg)).await.is_err() {
                        return;
                    }
                }
            }
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }
}

/// Guess an interface kind from its name.
fn classify_interface(name: &str) -> &'static str {
    let lower = name.to_lowercase();
    if lower.contains("wlan") || lower.contains("wifi") || lower.contains("wireless") {
        "wifi"
    } else if lower.contains("usb") {
        "usb"
    } else if lower.contains("bt") || lower.contains("bluetooth") {
        "bluetooth"
    } else if lower.contains("tun") || lower.contains("tap")
        || lower.contains("wg") || lower.contains("ppp")
        || lower.contains("utun") {
        "vpn"
    } else if lower.contains("lo") {
        "loopback"
    } else {
        "ethernet"
    }
}