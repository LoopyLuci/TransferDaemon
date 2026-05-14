mod call_overlay;
mod chats;
mod contacts;
mod onboarding;
mod popups;
mod settings;
mod transfers;

use crate::app::{App, Modal, Screen, Tab};
use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Tabs},
    Frame,
};

/// Main render entry — called inside `terminal.draw()`.
///
/// The call overlay needs `&mut App` because it drains the video frame channel.
/// The rest of the render functions take `&App` (read-only).
pub fn render(f: &mut Frame, app: &mut App) {
    match &app.screen.clone() {
        Screen::Onboarding(step) => {
            onboarding::render(f, app, step);
            return;
        }
        Screen::Main => {}
    }

    let area = f.size();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // tab bar
            Constraint::Min(0),    // content
            Constraint::Length(1), // status bar
        ])
        .split(area);

    // ── Tab bar ──────────────────────────────────────────────────────────────
    let tab_titles: Vec<Line> = vec![
        Line::from(vec![Span::raw(" Chats "), Span::styled("F1", Style::default().fg(Color::DarkGray))]),
        Line::from(vec![Span::raw(" Contacts "), Span::styled("F2", Style::default().fg(Color::DarkGray))]),
        Line::from(vec![Span::raw(" Transfers "), Span::styled("F3", Style::default().fg(Color::DarkGray))]),
        Line::from(vec![Span::raw(" Settings "), Span::styled("F4", Style::default().fg(Color::DarkGray))]),
    ];
    let tabs = Tabs::new(tab_titles)
        .block(Block::default().borders(Borders::ALL).title(" TransferDaemon "))
        .select(app.tab.index())
        .style(Style::default().fg(Color::White))
        .highlight_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD));
    f.render_widget(tabs, chunks[0]);

    // ── Content ──────────────────────────────────────────────────────────────
    match app.tab {
        Tab::Chats     => chats::render(f, app, chunks[1]),
        Tab::Contacts  => contacts::render(f, app, chunks[1]),
        Tab::Transfers => transfers::render(f, app, chunks[1]),
        Tab::Settings  => settings::render(f, app, chunks[1]),
    }

    // ── Status bar ───────────────────────────────────────────────────────────
    let daemon_label = if app.daemon_live { "gRPC" } else { "Mock" };
    let daemon_color = if app.daemon_live { Color::Green } else { Color::Yellow };
    let call_label = app.call_state.as_ref()
        .map(|cs| {
            let elapsed = cs.started_at.elapsed().as_secs();
            let icon = if cs.video_enabled { "📹" } else { "📞" };
            format!("  {} {} {:02}:{:02}", icon, cs.contact_name, elapsed / 60, elapsed % 60)
        })
        .unwrap_or_default();
    let status_line = Line::from(vec![
        Span::styled(format!(" {} ", daemon_label), Style::default().fg(daemon_color)),
        Span::raw("│"),
        Span::styled(format!(" {} ", &app.status), Style::default().fg(Color::Gray)),
        Span::raw(&call_label),
        Span::styled("  Ctrl+Q quit", Style::default().fg(Color::DarkGray)),
    ]);
    f.render_widget(Paragraph::new(status_line), chunks[2]);

    // ── Modals ───────────────────────────────────────────────────────────────
    if let Some(modal) = &app.modal.clone() {
        match modal {
            Modal::AddContact { key_input, name_input, field } =>
                popups::render_add_contact(f, key_input, name_input, *field),
            Modal::SendFile { path_input } =>
                popups::render_send_file(f, path_input),
            Modal::ConfirmDelete { label, .. } =>
                popups::render_confirm(f, &format!("Delete {}?", label)),
            Modal::ShowQr { hex } =>
                popups::render_qr(f, hex),
            Modal::RevealPhrase { phrase } =>
                popups::render_phrase(f, phrase),
        }
    }

    // ── Call overlay ─────────────────────────────────────────────────────────
    if app.call_state.is_some() {
        // call_overlay::render needs &mut CallState for the video overlay.
        call_overlay::render(f, app.call_state.as_mut().unwrap());
    }
}
