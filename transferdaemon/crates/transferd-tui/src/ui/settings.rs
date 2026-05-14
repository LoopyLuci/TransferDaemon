use crate::app::App;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default().borders(Borders::ALL).title(" Settings ");
    let inner = block.inner(area);
    f.render_widget(block, area);

    let mut lines: Vec<Line> = Vec::new();

    lines.push(Line::from(Span::styled("IDENTITY",
        Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD))));
    lines.push(Line::from(""));

    if let Some(id) = &app.identity {
        lines.push(Line::from(vec![
            Span::styled("  Display name:  ", Style::default().fg(Color::Gray)),
            Span::styled(&id.display_name, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        ]));

        let key_short: String = if id.public_key.len() >= 20 {
            format!("{}…{}", &id.public_key[..16], &id.public_key[id.public_key.len()-8..])
        } else {
            id.public_key.clone()
        };
        lines.push(Line::from(vec![
            Span::styled("  Public key:    ", Style::default().fg(Color::Gray)),
            Span::styled(key_short.clone(), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        ]));
        lines.push(Line::from(vec![
            Span::styled("                 ", Style::default()),
            Span::styled(format!("({} hex chars)", id.public_key.len()),
                Style::default().fg(Color::DarkGray)),
        ]));
    } else {
        lines.push(Line::from(Span::styled("  No identity set up.",
            Style::default().fg(Color::Gray))));
    }

    lines.push(Line::from(""));
    if app.recovery_phrase.is_some() {
        lines.push(Line::from(vec![
            Span::styled("  [R]  ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled("Reveal Recovery Phrase", Style::default().fg(Color::Yellow)),
        ]));
    } else {
        lines.push(Line::from(Span::styled(
            "  Recovery phrase only available in creation session.",
            Style::default().fg(Color::DarkGray))));
    }

    lines.push(Line::from(""));
    lines.push(Line::from("─".repeat(inner.width.saturating_sub(2) as usize)));
    lines.push(Line::from(""));

    lines.push(Line::from(Span::styled("NETWORK",
        Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD))));
    lines.push(Line::from(""));

    let daemon_status = if app.daemon_live {
        Span::styled("gRPC (live)", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))
    } else {
        Span::styled("Mock (offline)", Style::default().fg(Color::Yellow))
    };
    lines.push(Line::from(vec![
        Span::styled("  Daemon:        ", Style::default().fg(Color::Gray)),
        daemon_status,
    ]));
    lines.push(Line::from(vec![
        Span::styled("  Active transfers:  ", Style::default().fg(Color::Gray)),
        Span::styled(format!("{}", app.transfers.len()),
            Style::default().fg(Color::White)),
    ]));

    lines.push(Line::from(""));
    lines.push(Line::from("─".repeat(inner.width.saturating_sub(2) as usize)));
    lines.push(Line::from(""));

    lines.push(Line::from(Span::styled("ABOUT",
        Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD))));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("  TransferDaemon TUI  v1.0.0",
        Style::default().fg(Color::White).add_modifier(Modifier::BOLD))));
    lines.push(Line::from(Span::styled(
        "  Sovereign, zero-knowledge, universal data transfer.",
        Style::default().fg(Color::Gray))));
    lines.push(Line::from(Span::styled(
        "  No third-party services. No telemetry. No compromise.",
        Style::default().fg(Color::DarkGray))));

    f.render_widget(Paragraph::new(lines), inner);
}
