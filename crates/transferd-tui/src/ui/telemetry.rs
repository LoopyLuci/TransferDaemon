use crate::app::App;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    symbols,
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, List, ListItem, Paragraph, Sparkline},
    Frame,
};
use transferd_api::{Empty, TelemetryServiceClient};
use tonic::transport::Channel;

/// Lazily start the telemetry stream when the Telemetry tab is first shown.
pub fn ensure_stream(app: &mut App) {
    if app.telemetry.stream_rx.is_some() {
        return;
    }
    let Some(addr) = app.daemon_addr.clone() else { return };

    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    app.telemetry.stream_rx = Some(rx);

    tokio::spawn(async move {
        let endpoint = match Channel::from_shared(addr) {
            Ok(ep) => ep,
            Err(e) => { tracing::error!("[telemetry] invalid addr: {e}"); return; }
        };
        let channel = match endpoint.connect().await {
            Ok(ch) => ch,
            Err(e) => { tracing::error!("[telemetry] connect: {e}"); return; }
        };
        let token = transferd_api::auth::resolve_token().unwrap_or_default();
        let mut client =
            TelemetryServiceClient::new(transferd_api::auth::AuthChannel::new(channel, &token));
        let mut stream = match client.stream_telemetry(Empty {}).await {
            Ok(r) => r.into_inner(),
            Err(e) => { tracing::error!("[telemetry] stream_telemetry: {e}"); return; }
        };
        while let Ok(Some(msg)) = stream.message().await {
            if tx.send(msg).is_err() { break; }
        }
    });
}

pub fn render(f: &mut Frame, app: &mut App, area: Rect) {
    ensure_stream(app);

    let not_connected = app.telemetry.stream_rx.is_none();
    if not_connected {
        let msg = Paragraph::new("Telemetry unavailable — daemon not connected.")
            .style(Style::default().fg(Color::DarkGray))
            .block(Block::default().borders(Borders::ALL).title(" Telemetry "));
        f.render_widget(msg, area);
        return;
    }

    // Layout: top row (metrics), middle (sparkline), bottom (log)
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // metric gauges row
            Constraint::Length(5),  // sparkline
            Constraint::Min(0),     // event log
        ])
        .split(area);

    // ── Metric gauges row ─────────────────────────────────────────────────────
    let gauge_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(chunks[0]);

    let cpu = app.telemetry.cpu_pct;
    let cpu_color = if cpu < 60.0 { Color::Green } else if cpu < 85.0 { Color::Yellow } else { Color::Red };
    f.render_widget(
        Gauge::default()
            .block(Block::default().borders(Borders::ALL).title(" CPU "))
            .gauge_style(Style::default().fg(cpu_color))
            .ratio((cpu as f64 / 100.0).clamp(0.0, 1.0))
            .label(format!("{cpu:.1}%")),
        gauge_chunks[0],
    );

    let mem_mib = app.telemetry.mem_rss_kb / 1024;
    f.render_widget(
        Paragraph::new(format!("{mem_mib} MiB"))
            .style(Style::default().fg(Color::Cyan))
            .block(Block::default().borders(Borders::ALL).title(" Memory ")),
        gauge_chunks[1],
    );

    f.render_widget(
        Paragraph::new(format!("{}", app.telemetry.active_sessions))
            .style(Style::default().fg(Color::Green))
            .block(Block::default().borders(Borders::ALL).title(" Sessions ")),
        gauge_chunks[2],
    );

    let uptime = app.telemetry.uptime_secs;
    let uptime_str = if uptime < 60 {
        format!("{uptime}s")
    } else if uptime < 3600 {
        format!("{}m{}s", uptime / 60, uptime % 60)
    } else {
        format!("{}h{}m", uptime / 3600, (uptime % 3600) / 60)
    };
    f.render_widget(
        Paragraph::new(uptime_str)
            .style(Style::default().fg(Color::White))
            .block(Block::default().borders(Borders::ALL).title(" Uptime ")),
        gauge_chunks[3],
    );

    // ── ATE sparkline ─────────────────────────────────────────────────────────
    let spark_data: Vec<u64> = app.telemetry.sparkline(60)
        .into_iter()
        .map(|v| v as u64)
        .collect();
    let sparkline = Sparkline::default()
        .block(Block::default().borders(Borders::ALL).title(" ATE Lane Activity (last 60s) "))
        .data(&spark_data)
        .style(Style::default().fg(Color::Blue))
        .bar_set(symbols::bar::NINE_LEVELS);
    f.render_widget(sparkline, chunks[1]);

    // ── Event log ─────────────────────────────────────────────────────────────
    let items: Vec<ListItem> = app.telemetry.log
        .iter()
        .rev()
        .take(chunks[2].height.saturating_sub(2) as usize)
        .map(|(_, tag, summary)| {
            let tag_color = match *tag {
                "SYS" => Color::Cyan,
                "ATE" => Color::Green,
                _     => Color::DarkGray,
            };
            ListItem::new(Line::from(vec![
                Span::styled(format!("[{tag}] "), Style::default().fg(tag_color).add_modifier(Modifier::BOLD)),
                Span::styled(summary.clone(), Style::default().fg(Color::White)),
            ]))
        })
        .collect();

    let log = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(" Live Event Log "));
    f.render_widget(log, chunks[2]);
}
