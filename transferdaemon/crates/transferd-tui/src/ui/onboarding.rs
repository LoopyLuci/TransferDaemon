use crate::app::{App, OnboardingStep};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
    Frame,
};

pub fn render(f: &mut Frame, app: &App, step: &OnboardingStep) {
    let area = centered_rect(60, 70, f.size());
    f.render_widget(Clear, area);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(" TransferDaemon Setup ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)));
    let inner = block.inner(area);
    f.render_widget(block, area);

    match step {
        OnboardingStep::Welcome => render_welcome(f, inner),
        OnboardingStep::EnterName => render_enter_name(f, app, inner),
        OnboardingStep::ShowPhrase { phrase } => render_show_phrase(f, phrase, inner),
        OnboardingStep::ConfirmPhrase { phrase } => render_confirm_phrase(f, app, phrase, inner),
        OnboardingStep::EnterPhrase => render_enter_phrase(f, app, inner),
    }
}

fn render_welcome(f: &mut Frame, area: Rect) {
    let lines = vec![
        Line::from(""),
        Line::from(Span::styled("TransferDaemon",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))),
        Line::from(Span::styled("Sovereign. Zero-knowledge. Universal transfer.",
            Style::default().fg(Color::Gray))),
        Line::from(""),
        Line::from(""),
        Line::from(Span::styled("  [1]  Create new account",
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD))),
        Line::from(""),
        Line::from(Span::styled("  [2]  Restore from recovery phrase",
            Style::default().fg(Color::White))),
        Line::from(""),
        Line::from(""),
        Line::from(Span::styled("Press 1 or 2 to continue.",
            Style::default().fg(Color::DarkGray))),
    ];
    f.render_widget(Paragraph::new(lines).alignment(Alignment::Center), area);
}

fn render_enter_name(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(4), Constraint::Length(3), Constraint::Min(0)])
        .split(area);

    f.render_widget(Paragraph::new(vec![
        Line::from(""),
        Line::from(Span::styled("Choose a display name", Style::default().fg(Color::White).add_modifier(Modifier::BOLD))),
        Line::from(Span::styled("This is shown only to people you choose to share it with.",
            Style::default().fg(Color::Gray))),
    ]), chunks[0]);

    let input_block = Block::default().borders(Borders::ALL).title(" Display name ");
    let input_para = Paragraph::new(app.input.as_str())
        .block(input_block)
        .style(Style::default().fg(Color::White));
    f.render_widget(input_para, chunks[1]);
    // Show cursor
    f.set_cursor(chunks[1].x + 1 + app.input.len() as u16, chunks[1].y + 1);

    f.render_widget(Paragraph::new(vec![
        Line::from(""),
        Line::from(Span::styled("Enter  continue    Esc  back", Style::default().fg(Color::DarkGray))),
    ]), chunks[2]);
}

fn render_show_phrase(f: &mut Frame, phrase: &str, area: Rect) {
    let words: Vec<&str> = phrase.split_whitespace().collect();

    let mut lines = vec![
        Line::from(Span::styled("Your Recovery Phrase",
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))),
        Line::from(""),
        Line::from(Span::styled(
            "Write these 12 words down. Anyone with this phrase can restore your identity.",
            Style::default().fg(Color::Red))),
        Line::from(""),
    ];

    for row in 0..4 {
        let start = row * 3;
        let mut spans = Vec::new();
        for col in 0..3 {
            let i = start + col;
            if i < words.len() {
                spans.push(Span::styled(
                    format!("{:2}. {:<12}  ", i + 1, words[i]),
                    Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
                ));
            }
        }
        lines.push(Line::from(spans));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Enter  I've written it down    Esc  cancel",
        Style::default().fg(Color::DarkGray),
    )));

    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
}

fn render_confirm_phrase(f: &mut Frame, app: &App, phrase: &str, area: Rect) {
    let _ = phrase;
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Length(3), Constraint::Min(0)])
        .split(area);

    f.render_widget(Paragraph::new(vec![
        Line::from(Span::styled("Confirm your recovery phrase",
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))),
        Line::from(Span::styled("Re-type all 12 words to confirm you've saved them.",
            Style::default().fg(Color::Gray))),
    ]), chunks[0]);

    let b = Block::default().borders(Borders::ALL).title(" Type phrase to confirm ");
    let p = Paragraph::new(app.input.as_str()).block(b);
    f.render_widget(p, chunks[1]);
    f.set_cursor(chunks[1].x + 1 + app.input.len() as u16, chunks[1].y + 1);

    f.render_widget(Paragraph::new(
        Line::from(Span::styled("Enter  confirm    Esc  back", Style::default().fg(Color::DarkGray)))
    ), chunks[2]);
}

fn render_enter_phrase(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Length(5), Constraint::Min(0)])
        .split(area);

    f.render_widget(Paragraph::new(vec![
        Line::from(Span::styled("Restore Identity",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))),
        Line::from(Span::styled("Enter your 12-word recovery phrase, separated by spaces.",
            Style::default().fg(Color::Gray))),
    ]), chunks[0]);

    let b = Block::default().borders(Borders::ALL).title(" Recovery phrase ");
    let p = Paragraph::new(app.input.as_str()).block(b).wrap(Wrap { trim: true });
    f.render_widget(p, chunks[1]);
    let word_count = app.input.split_whitespace().count();
    let cursor_x = (chunks[1].x + 1 + (app.input.len() as u16)).min(chunks[1].x + chunks[1].width - 2);
    let cursor_y = chunks[1].y + 1 + (app.input.len() as u16 / (chunks[1].width.saturating_sub(2)).max(1));
    let cursor_y = cursor_y.min(chunks[1].y + chunks[1].height - 2);
    f.set_cursor(cursor_x, cursor_y);

    f.render_widget(Paragraph::new(vec![
        Line::from(Span::styled(
            format!("{}/12 words  — Enter to restore  Esc to cancel", word_count),
            if word_count >= 12 { Style::default().fg(Color::Green) } else { Style::default().fg(Color::DarkGray) },
        )),
    ]), chunks[2]);
}

pub fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
