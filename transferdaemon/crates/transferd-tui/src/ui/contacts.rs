use crate::app::App;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Frame,
};
use std::time::{SystemTime, UNIX_EPOCH};

fn now_ts() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(3)])
        .split(area);

    let items: Vec<ListItem> = app.contacts.iter().map(|c| {
        let dot = if c.online {
            Span::styled("● ", Style::default().fg(Color::Green))
        } else {
            Span::styled("○ ", Style::default().fg(Color::DarkGray))
        };
        let last_seen = match c.last_seen_ts {
            Some(ts) if c.online => Span::styled(" (online)", Style::default().fg(Color::Green)),
            Some(ts) => {
                let secs = now_ts().saturating_sub(ts);
                let ago = if secs < 60 { format!("{}s ago", secs) }
                    else if secs < 3600 { format!("{}m ago", secs / 60) }
                    else if secs < 86400 { format!("{}h ago", secs / 3600) }
                    else { format!("{}d ago", secs / 86400) };
                Span::styled(format!(" ({})", ago), Style::default().fg(Color::DarkGray))
            }
            None => Span::styled(" (never seen)", Style::default().fg(Color::DarkGray)),
        };
        let key_short = if c.id.len() >= 16 {
            format!("  {}…{}", &c.id[..8], &c.id[c.id.len()-4..])
        } else {
            format!("  {}", c.id)
        };
        ListItem::new(vec![
            Line::from(vec![dot, Span::styled(&c.name, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)), last_seen]),
            Line::from(Span::styled(key_short, Style::default().fg(Color::DarkGray))),
        ])
    }).collect();

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(" Contacts "))
        .highlight_style(Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD))
        .highlight_symbol("▶ ");

    let mut state = ListState::default();
    if !app.contacts.is_empty() {
        state.select(Some(app.contacts_selected));
    }
    f.render_stateful_widget(list, chunks[0], &mut state);

    let help = Paragraph::new(Line::from(vec![
        Span::styled(" [A] Add  ", Style::default().fg(Color::Cyan)),
        Span::styled("[D] Delete  ", Style::default().fg(Color::Red)),
        Span::styled("[Q] Show QR  ", Style::default().fg(Color::Yellow)),
        Span::styled("[Enter] Open chat  ", Style::default().fg(Color::Green)),
    ])).block(Block::default().borders(Borders::ALL));
    f.render_widget(help, chunks[1]);
}
