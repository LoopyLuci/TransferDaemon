use crate::app::CallState;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
    Frame,
};

pub fn render(f: &mut Frame, cs: &CallState) {
    let area = call_rect(f.size());
    f.render_widget(Clear, area);

    let elapsed = cs.started_at.elapsed().as_secs();
    let h = elapsed / 3600;
    let m = (elapsed % 3600) / 60;
    let s = elapsed % 60;
    let duration = if h > 0 {
        format!("{:02}:{:02}:{:02}", h, m, s)
    } else {
        format!("{:02}:{:02}", m, s)
    };

    let mute_label = if cs.muted { "Muted  [M] unmute" } else { "[M] Mute" };

    let lines = vec![
        Line::from(Span::styled(
            format!("📞 {}", cs.contact_name),
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(duration, Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))),
        Line::from(""),
        Line::from(Span::styled(mute_label, Style::default().fg(Color::Yellow))),
        Line::from(Span::styled("[H] Hang Up", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))),
    ];

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Green))
        .title(Span::styled(" Call ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)));

    f.render_widget(Paragraph::new(lines).block(block), area);
}

fn call_rect(r: Rect) -> Rect {
    Rect {
        x: r.width.saturating_sub(24),
        y: r.height.saturating_sub(9),
        width: 24,
        height: 7,
    }
}
