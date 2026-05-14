use crate::app::App;
use crate::types::fmt_bytes;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, List, ListItem, ListState, Paragraph},
    Frame,
};

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    if app.transfers.is_empty() {
        let p = Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled("  No active transfers.", Style::default().fg(Color::Gray))),
        ])
        .block(Block::default().borders(Borders::ALL).title(" Transfers "));
        f.render_widget(p, area);
        return;
    }

    // Each transfer takes ~4 rows: name+direction, progress bar, stats, blank.
    let item_height = 4u16;
    let visible = ((area.height.saturating_sub(2)) / item_height) as usize;
    let scroll = app.transfers_selected.saturating_sub(visible.saturating_sub(1));

    let outer = Block::default().borders(Borders::ALL).title(" Transfers  [C] cancel  [↑↓] select ");
    let inner = outer.inner(area);
    f.render_widget(outer, area);

    let rows: Vec<Constraint> = app.transfers.iter().skip(scroll)
        .map(|_| Constraint::Length(item_height)).collect();
    if rows.is_empty() { return; }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(rows)
        .split(inner);

    for (i, (t, chunk)) in app.transfers.iter().skip(scroll).zip(chunks.iter()).enumerate() {
        let real_idx = i + scroll;
        let selected = real_idx == app.transfers_selected;
        let sel_style = if selected {
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::White)
        };

        let dir = if t.outbound { "↑ To" } else { "↓ From" };
        let header = format!("{} {}: {}", dir, t.contact_name, t.file_name);
        let prefix = if selected { "▶ " } else { "  " };

        // Row 0: header
        let sub = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Length(1),
            ])
            .split(*chunk);

        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(prefix, Style::default().fg(Color::Cyan)),
                Span::styled(header, sel_style),
            ])),
            sub[0],
        );

        // Row 1: gauge
        let progress = t.progress();
        let pct = (progress * 100.0) as u16;
        let label = if pct >= 100 {
            "Complete".into()
        } else {
            format!("{} %", pct)
        };
        let gauge_color = if pct >= 100 { Color::Green } else { Color::Cyan };
        let gauge = Gauge::default()
            .ratio(progress)
            .label(label)
            .gauge_style(Style::default().fg(gauge_color).bg(Color::DarkGray));
        f.render_widget(gauge, sub[1]);

        // Row 2: stats
        let eta = t.eta_secs().map(|s| format!("  ETA {}s", s)).unwrap_or_default();
        let bps_label = if t.bps > 0 { format!("  {}/s", fmt_bytes(t.bps)) } else { String::new() };
        let stats = format!("  {} / {}{}{}",
            fmt_bytes(t.transferred_bytes), fmt_bytes(t.size_bytes), bps_label, eta);
        f.render_widget(
            Paragraph::new(Span::styled(stats, Style::default().fg(Color::Gray))),
            sub[2],
        );
        // Row 3: blank separator
    }
}
