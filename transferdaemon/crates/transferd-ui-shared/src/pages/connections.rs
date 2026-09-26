//! Connections — the transport control center.
//!
//! Lists every interface + virtual transport with live health, lets the user
//! pick the transfer policy, and shows real per-lane RTT/bandwidth numbers.

use crate::app::AppState;
use crate::design::{self, DesignTokens};
use crate::types::Connection;
use egui::{RichText, ScrollArea};
use std::collections::HashMap;
use std::time::Instant;

pub struct ConnectionsPage {
    connections: Vec<Connection>,
    policy: String,
    last_refresh: Instant,
    /// Live lane health: connection_id → (rtt_ms, bandwidth_bps, active, online).
    live: HashMap<String, (f64, u64, u64, bool)>,
    stream_rx: Option<tokio::sync::mpsc::UnboundedReceiver<transferd_api::ConnectionStatusMsg>>,
    stream_started: bool,
}

impl Default for ConnectionsPage {
    fn default() -> Self {
        Self {
            connections: Vec::new(),
            policy: "auto".into(),
            last_refresh: Instant::now()
                .checked_sub(std::time::Duration::from_secs(5))
                .unwrap_or_else(Instant::now),
            live: HashMap::new(),
            stream_rx: None,
            stream_started: false,
        }
    }
}

impl ConnectionsPage {
    fn ensure_stream(&mut self, state: &AppState) {
        if self.stream_started {
            return;
        }
        let Some(addr) = state.daemon_addr.clone() else { return };
        self.stream_started = true;

        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            let endpoint = match tonic::transport::Channel::from_shared(addr.clone()) {
                Ok(ep) => ep,
                Err(_) => return,
            };
            let channel = match endpoint.connect().await {
                Ok(ch) => ch,
                Err(_) => return,
            };
            let token = transferd_api::auth::resolve_token().unwrap_or_default();
            let mut client = transferd_api::ConnectionServiceClient::new(
                transferd_api::auth::AuthChannel::new(channel, &token),
            );
            let mut stream = match client.stream_connection_status(transferd_api::Empty {}).await {
                Ok(r) => r.into_inner(),
                Err(_) => return,
            };
            while let Ok(Some(msg)) = stream.message().await {
                if tx.send(msg).is_err() {
                    return;
                }
            }
        });
        self.stream_rx = Some(rx);
    }

    pub fn show(&mut self, ui: &mut egui::Ui, state: &mut AppState) {
        let tokens = DesignTokens::current();
        self.ensure_stream(state);

        // Drain live status.
        if let Some(rx) = &mut self.stream_rx {
            while let Ok(msg) = rx.try_recv() {
                self.live.insert(msg.connection_id, (msg.rtt_ms, msg.bandwidth_bps, msg.active_chunks, msg.online));
            }
        }

        // Refresh the connection list + policy periodically.
        if self.last_refresh.elapsed() >= std::time::Duration::from_secs(3) {
            self.last_refresh = Instant::now();
            let rt = tokio::runtime::Handle::current();
            let connections = rt.block_on(state.daemon.get_connections());
            self.policy = connections
                .iter()
                .find(|c| c.kind == "direct")
                .map(|c| c.policy.clone())
                .unwrap_or_else(|| self.policy.clone());
            self.connections = connections;
        }

        ui.add_space(tokens.spacing.sm);

        // ── Policy selector ───────────────────────────────────────────────────
        design::card_frame(&tokens).show(ui, |ui| {
            ui.label(RichText::new("Transfer policy").size(14.0).strong().color(tokens.palette.text_primary));
            ui.add_space(tokens.spacing.xs);
            ui.horizontal(|ui| {
                for (key, label) in [
                    ("auto", "Auto"),
                    ("direct", "Direct only"),
                    ("relay", "Relay only"),
                    ("stripe", "Stripe all"),
                ] {
                    let selected = self.policy == key;
                    let bg = if selected { tokens.palette.accent } else { tokens.palette.surface };
                    let fg = if selected { tokens.palette.text_inverse } else { tokens.palette.text_primary };
                    if ui
                        .add_sized(
                            [ui.available_width() / 4.2, 30.0],
                            egui::Button::new(RichText::new(label).size(11.0).color(fg)).fill(bg),
                        )
                        .clicked()
                    {
                        let rt = tokio::runtime::Handle::current();
                        let _ = rt.block_on(state.daemon.set_connection_policy("global", key));
                        self.policy = key.to_string();
                    }
                }
            });
            ui.add_space(tokens.spacing.xs);
            ui.label(
                RichText::new(
                    "Direct only = skip relay; Relay only = skip direct; Stripe = use every available lane.",
                )
                .size(11.0)
                .color(tokens.palette.text_disabled),
            );
        });

        ui.add_space(tokens.spacing.md);

        // ── Connection list ───────────────────────────────────────────────────
        if self.connections.is_empty() {
            ui.vertical_centered(|ui| {
                ui.add_space(ui.available_height() / 4.0);
                ui.label(RichText::new("🌐").size(48.0).color(tokens.palette.text_disabled));
                ui.add_space(tokens.spacing.sm);
                ui.label(
                    RichText::new("No connections reported")
                        .size(14.0)
                        .color(tokens.palette.text_secondary),
                );
            });
            return;
        }

        ScrollArea::vertical().show(ui, |ui| {
            let connections = self.connections.clone();
            for c in &connections {
                self.connection_row(ui, c, &tokens);
                ui.add_space(tokens.spacing.xs);
            }
        });
    }

    fn connection_row(&self, ui: &mut egui::Ui, c: &Connection, tokens: &DesignTokens) {
        let live = self.live.get(&c.id);
        let online = c.online || live.map(|l| l.3).unwrap_or(false);
        let dot = if online { tokens.palette.success } else { tokens.palette.text_disabled };

        design::card_frame(tokens).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new(kind_icon(&c.kind)).size(20.0));
                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(&c.name).size(14.0).color(tokens.palette.text_primary));
                        ui.label(
                            RichText::new(c.kind_label())
                                .size(11.0)
                                .color(tokens.palette.text_secondary),
                        );
                        ui.label(RichText::new(if online { "● online" } else { "○ offline" }).size(11.0).color(dot));
                    });
                    // Stats line.
                    let speed = format_speed(c.link_speed_bps);
                    let mut stats = format!("link {speed}");
                    if let Some((rtt, bw, active, _)) = live {
                        stats.push_str(&format!("   ·   {:.1} ms   ·   {}   ·   {} in flight", rtt, format_speed(*bw), active));
                    } else if c.rtt_ms > 0.0 {
                        stats.push_str(&format!("   ·   {:.1} ms   ·   {}", c.rtt_ms, format_speed(c.bandwidth_bps)));
                    }
                    ui.label(RichText::new(stats).size(11.0).color(tokens.palette.text_disabled));
                });
            });
        });
    }
}

fn kind_icon(kind: &str) -> &'static str {
    match kind {
        "wifi" => "📶",
        "ethernet" | "loopback" => "🔌",
        "usb" => "🔗",
        "bluetooth" => "🛜",
        "vpn" => "🛡️",
        "proxy" => "🧭",
        "relay" => "☁️",
        "direct" => "⚡",
        _ => "🌐",
    }
}

fn format_speed(bps: u64) -> String {
    if bps == 0 {
        return "–".into();
    }
    if bps >= 1_000_000_000 {
        format!("{:.1} Gbps", bps as f64 / 1e9)
    } else if bps >= 1_000_000 {
        format!("{:.0} Mbps", bps as f64 / 1e6)
    } else {
        format!("{:.0} Kbps", bps as f64 / 1e3)
    }
}