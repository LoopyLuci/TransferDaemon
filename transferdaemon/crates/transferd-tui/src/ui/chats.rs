use crate::app::{App, ChatFocus};
use crate::types::MessageContent;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Frame,
};

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(22), Constraint::Min(0)])
        .split(area);

    render_contact_list(f, app, chunks[0]);
    render_chat_panel(f, app, chunks[1]);
}

fn render_contact_list(f: &mut Frame, app: &App, area: Rect) {
    let focused = app.modal.is_none() && app.chat_focus == ChatFocus::ContactList;
    let border_style = if focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let items: Vec<ListItem> = app.contacts.iter().map(|c| {
        let dot = if c.online { Span::styled("● ", Style::default().fg(Color::Green)) }
                  else       { Span::styled("○ ", Style::default().fg(Color::DarkGray)) };
        ListItem::new(Line::from(vec![dot, Span::raw(&c.name)]))
    }).collect();

    let list = List::new(items)
        .block(Block::default()
            .borders(Borders::ALL)
            .title(" Chats ")
            .border_style(border_style))
        .highlight_style(Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD))
        .highlight_symbol("▶ ");

    let mut state = ListState::default();
    if !app.contacts.is_empty() {
        state.select(Some(app.selected_contact));
    }
    f.render_stateful_widget(list, area, &mut state);
}

fn render_chat_panel(f: &mut Frame, app: &App, area: Rect) {
    let contact_name = app.open_contact_name().unwrap_or("— select a contact —");

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(3)])
        .split(area);

    // ── Message thread ───────────────────────────────────────────────────────
    let msg_focused = app.modal.is_none() && app.chat_focus == ChatFocus::Messages;
    let msgs = app.open_messages();
    let visible_height = chunks[0].height.saturating_sub(2) as usize;
    let total = msgs.len();
    let scroll_offset = if total > visible_height {
        let max_scroll = total - visible_height;
        app.msg_scroll.min(max_scroll)
    } else {
        0
    };

    let items: Vec<ListItem> = msgs.iter().skip(scroll_offset).map(|m| {
        let (prefix, color) = if m.outbound {
            ("You: ", Color::Cyan)
        } else {
            ("    ", Color::White)
        };
        let text = match &m.content {
            MessageContent::Text(t) => t.clone(),
            MessageContent::File { name, size_bytes, .. } =>
                format!("📎 {} ({})", name, crate::types::fmt_bytes(*size_bytes)),
        };
        let status = m.status.label();
        ListItem::new(Line::from(vec![
            Span::styled(prefix, Style::default().fg(color).add_modifier(Modifier::BOLD)),
            Span::styled(text, Style::default().fg(color)),
            Span::styled(format!(" {}", status), Style::default().fg(Color::DarkGray)),
        ]))
    }).collect();

    let msg_block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" {} ", contact_name))
        .border_style(if msg_focused {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default().fg(Color::DarkGray)
        });

    // scroll hint
    let scroll_hint = if total > visible_height {
        format!(" ↑↓ ({}/{})", scroll_offset + visible_height.min(total), total)
    } else {
        String::new()
    };
    let msg_block = msg_block.title_bottom(
        Line::from(Span::styled(scroll_hint, Style::default().fg(Color::DarkGray)))
    );

    let list = List::new(items).block(msg_block);
    f.render_widget(list, chunks[0]);

    // ── Input bar ────────────────────────────────────────────────────────────
    let input_focused = app.modal.is_none() && app.chat_focus == ChatFocus::Input;
    let input_block = Block::default()
        .borders(Borders::ALL)
        .title(" Message (Enter send  Ctrl+F file  Ctrl+C call) ")
        .border_style(if input_focused {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default().fg(Color::DarkGray)
        });
    let input_para = Paragraph::new(app.input.as_str())
        .block(input_block)
        .style(Style::default().fg(Color::White))
        .wrap(Wrap { trim: true });
    f.render_widget(input_para, chunks[1]);

    if input_focused {
        let cursor_x = (chunks[1].x + 1 + app.input.len() as u16)
            .min(chunks[1].x + chunks[1].width - 2);
        f.set_cursor(cursor_x, chunks[1].y + 1);
    }
}
