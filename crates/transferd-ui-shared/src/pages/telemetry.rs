//! Telemetry page — live system health and ATE lane activity.
//!
//! Redesigned with the new design system for a modern, accessible experience.

use std::collections::VecDeque;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::design::{self, DesignTokens};
use egui::{Color32, RichText, ScrollArea, Ui, Vec2};
use tokio::sync::mpsc;
use transferd_api::{Empty, TelemetryEventMsg, TelemetryServiceClient};
use tonic::transport::Channel;

const MAX_EVENTS: usize = 200;
const SPARKLINE_SECS: usize = 60;
const MAX_ATE_TS: usize = 3_000;

struct LogEntry {
    ts: u64,
    kind: EventKind,
    summary: String,
}

#[derive(Clone, Copy)]
enum EventKind {
    System,
    Ate,
}

pub struct TelemetryPage {
    cpu_pct: f32,
    mem_rss_kb: u64,
    uptime_secs: u64,
    active_sessions: u32,
    events: VecDeque<LogEntry>,
    ate_timestamps: VecDeque<u64>,
    stream_rx: Option<mpsc::UnboundedReceiver<TelemetryEventMsg>>,
}

impl Default for TelemetryPage {
    fn default() -> Self {
        Self {
            cpu_pct: 0.0,
            mem_rss_kb: 0,
            uptime_secs: 0,
            active_sessions: 0,
            events: VecDeque::with_capacity(MAX_EVENTS),
            ate_timestamps: VecDeque::with_capacity(MAX_ATE_TS),
            stream_rx: None,
        }
    }
}

impl TelemetryPage {
    fn start_stream(&mut self, addr: String, ctx: egui::Context) {
        let (tx, rx) = mpsc::unbounded_channel::<TelemetryEventMsg>();
        self.stream_rx = Some(rx);

        tokio::spawn(async move {
            let endpoint = match Channel::from_shared(addr) {
                Ok(ep) => ep,
                Err(e) => {
                    tracing::error!("[telemetry] invalid addr: {e}");
                    return;
                }
            };
            let channel = match endpoint.connect().await {
                Ok(ch) => ch,
                Err(e) => {
                    tracing::error!("[telemetry] connect failed: {e}");
                    return;
                }
            };
            let token = transferd_api::auth::resolve_token().unwrap_or_default();
            let mut client =
                TelemetryServiceClient::new(transferd_api::auth::AuthChannel::new(channel, &token));
            let mut stream = match client.stream_telemetry(Empty {}).await {
                Ok(r) => r.into_inner(),
                Err(e) => {
                    tracing::error!("[telemetry] stream_telemetry: {e}");
                    return;
                }
            };
            while let Ok(Some(msg)) = stream.message().await {
                if tx.send(msg).is_err() {
                    break;
                }
                ctx.request_repaint();
            }
        });
    }

    fn drain_events(&mut self) {
        // Collect into a vec first to release the mutable borrow on stream_rx
        // before calling push_log (which also borrows self mutably).
        let mut collected = vec![];
        if let Some(rx) = &mut self.stream_rx {
            while let Ok(msg) = rx.try_recv() {
                collected.push(msg);
            }
        }
        for msg in collected {
            use transferd_api::proto::telemetry_event_msg::Event;
            let Some(ev) = msg.event else {
                continue;
            };
            match ev {
                Event::SystemHealth(h) => {
                    self.cpu_pct = h.cpu_pct;
                    self.mem_rss_kb = h.mem_rss_kb;
                    self.uptime_secs = h.uptime_secs;
                    self.active_sessions = h.active_sessions;
                    let summary = format!(
                        "CPU {:.1}%  RSS {}  up {}  sessions {}",
                        h.cpu_pct,
                        fmt_kib(h.mem_rss_kb),
                        fmt_duration(h.uptime_secs),
                        h.active_sessions,
                    );
                    self.push_log(h.ts, EventKind::System, summary);
                }
                Event::AteLane(a) => {
                    while self.ate_timestamps.len() >= MAX_ATE_TS {
                        self.ate_timestamps.pop_front();
                    }
                    self.ate_timestamps.push_back(a.ts);
                    let summary = format!(
                        "lane {}  gsn {}  rtt {:.2}ms  bw {}",
                        a.selected_lane, a.gsn, a.rtt_ms, fmt_bps(a.bandwidth_bps),
                    );
                    self.push_log(a.ts, EventKind::Ate, summary);
                }
            }
        }
    }

    fn push_log(&mut self, ts: u64, kind: EventKind, summary: String) {
        if self.events.len() >= MAX_EVENTS {
            self.events.pop_front();
        }
        self.events.push_back(LogEntry {
            ts,
            kind,
            summary,
        });
    }

    pub fn show(&mut self, ui: &mut Ui, daemon_addr: Option<&str>, ctx: &egui::Context) {
        let tokens = DesignTokens::current();
        let now = current_ts();

        if self.stream_rx.is_none() {
            if let Some(addr) = daemon_addr {
                self.start_stream(addr.to_owned(), ctx.clone());
            }
        }

        self.drain_events();

        if self.stream_rx.is_none() {
            ui.vertical_centered(|ui| {
                ui.add_space(ui.available_height() / 3.0);
                ui.label(
                    RichText::new("📊")
                        .size(48.0)
                        .color(tokens.palette.text_disabled),
                );
                ui.add_space(tokens.spacing.sm);
                ui.label(
                    RichText::new("Telemetry unavailable")
                        .size(16.0)
                        .color(tokens.palette.text_secondary),
                );
                ui.add_space(tokens.spacing.xs);
                ui.label(
                    RichText::new("Daemon not connected")
                        .size(13.0)
                        .color(tokens.palette.text_disabled),
                );
            });
            return;
        }

        // Use scroll area to prevent content from being cut off
        ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.add_space(tokens.spacing.md);

                // ── Header cards ─────────────────────────────────────────────────────
                let card_w = (ui.available_width() - tokens.spacing.sm * 3.0) / 4.0;
                ui.horizontal(|ui| {
                    for (label, value, bar_pct, icon) in [
                        (
                            "CPU",
                            format!("{:.1}%", self.cpu_pct),
                            self.cpu_pct / 100.0,
                            "⚡",
                        ),
                        (
                            "Memory",
                            fmt_kib(self.mem_rss_kb),
                            -1.0_f32,
                            "💾",
                        ),
                        (
                            "Sessions",
                            self.active_sessions.to_string(),
                            -1.0_f32,
                            "🔗",
                        ),
                        (
                            "Uptime",
                            fmt_duration(self.uptime_secs),
                            -1.0_f32,
                            "⏱",
                        ),
                    ] {
                        design::card_frame(&tokens).show(ui, |ui| {
                            ui.set_width(card_w);
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(icon).size(14.0));
                                ui.label(
                                    RichText::new(label)
                                        .color(tokens.palette.text_disabled)
                                        .size(11.0),
                                );
                            });
                            ui.label(
                                RichText::new(&value)
                                    .color(tokens.palette.text_primary)
                                    .size(18.0)
                                    .strong(),
                            );
                            if bar_pct >= 0.0 {
                                let bar = egui::ProgressBar::new(bar_pct.clamp(0.0, 1.0))
                                    .fill(cpu_bar_color(bar_pct, &tokens));
                                ui.add(bar);
                            }
                        });
                        ui.add_space(tokens.spacing.xs);
                    }
                });

                ui.add_space(tokens.spacing.sm);

                // ── ATE sparkline ────────────────────────────────────────────
                design::card_frame(&tokens).show(ui, |ui| {
                    ui.label(
                        RichText::new("ATE Lane Activity (last 60s)")
                            .color(tokens.palette.text_disabled)
                            .size(12.0),
                    );
                    ui.add_space(tokens.spacing.xs);

                    let mut per_sec = [0u32; SPARKLINE_SECS];
                    for &ts in &self.ate_timestamps {
                        let age = now.saturating_sub(ts) as usize;
                        if age < SPARKLINE_SECS {
                            per_sec[SPARKLINE_SECS - 1 - age] += 1;
                        }
                    }
                    let max_val = (*per_sec.iter().max().unwrap_or(&1)).max(1) as f32;
                    let (_, rect) = ui.allocate_space(Vec2::new(ui.available_width(), 40.0));
                    if ui.is_rect_visible(rect) {
                        let bar_w = rect.width() / SPARKLINE_SECS as f32;
                        for (i, &count) in per_sec.iter().enumerate() {
                            let t = count as f32 / max_val;
                            let bar_h = t * rect.height();
                            let bar_rect = egui::Rect::from_min_size(
                                egui::pos2(
                                    rect.left() + i as f32 * bar_w,
                                    rect.bottom() - bar_h,
                                ),
                                Vec2::new((bar_w - 1.0).max(0.5), bar_h.max(0.5)),
                            );
                            let color = Color32::from_rgb(
                                0,
                                (t * 180.0) as u8,
                                255,
                            );
                            ui.painter()
                                .rect_filled(bar_rect, 0.0, color);
                        }
                    }
                });

                ui.add_space(tokens.spacing.sm);
                ui.separator();
                ui.add_space(tokens.spacing.xs);

                // ── Event log ────────────────────────────────────────────────
                ui.label(
                    RichText::new("Live Event Log")
                        .color(tokens.palette.text_disabled)
                        .size(12.0),
                );
                for entry in self.events.iter().rev().take(100) {
                    let (tag, tag_color) = match entry.kind {
                        EventKind::System => ("SYS", tokens.palette.info),
                        EventKind::Ate => ("ATE", tokens.palette.success),
                    };
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(fmt_age(entry.ts, now))
                                .color(tokens.palette.text_disabled)
                                .size(11.0)
                                .monospace(),
                        );
                        ui.add_space(tokens.spacing.xxs);
                        ui.label(
                            RichText::new(tag)
                                .color(tag_color)
                                .size(11.0)
                                .monospace(),
                        );
                        ui.add_space(tokens.spacing.xxs);
                        ui.label(
                            RichText::new(&entry.summary)
                                .color(tokens.palette.text_primary)
                                .size(12.0),
                        );
                    });
                }
            });
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn current_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn fmt_kib(kib: u64) -> String {
    let bytes = kib.saturating_mul(1024);
    if bytes < 1024 * 1024 {
        format!("{:.0} KiB", bytes as f32 / 1024.0)
    } else {
        format!("{:.1} MiB", bytes as f32 / 1024.0 / 1024.0)
    }
}

fn fmt_bps(bps: u64) -> String {
    if bps < 1_000 {
        format!("{bps} bps")
    } else if bps < 1_000_000 {
        format!("{:.1} Kbps", bps as f32 / 1_000.0)
    } else {
        format!("{:.1} Mbps", bps as f32 / 1_000_000.0)
    }
}

fn fmt_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    }
}

fn fmt_age(ts: u64, now: u64) -> String {
    let delta = now.saturating_sub(ts);
    if delta == 0 {
        " now     ".to_owned()
    } else if delta < 60 {
        format!("-{delta:3}s   ")
    } else {
        format!("-{:3}m   ", delta / 60)
    }
}

fn cpu_bar_color(pct: f32, tokens: &DesignTokens) -> Color32 {
    if pct < 0.6 {
        tokens.palette.success
    } else if pct < 0.85 {
        tokens.palette.warning
    } else {
        tokens.palette.error
    }
}
