use super::onboarding::centered_rect;
use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
    Frame,
};

pub fn render_add_contact(f: &mut Frame, key_input: &str, name_input: &str, field: usize) {
    let area = centered_rect(60, 40, f.size());
    f.render_widget(Clear, area);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Add Contact ")
        .border_style(Style::default().fg(Color::Cyan));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Min(0),
        ])
        .split(inner);

    f.render_widget(
        Paragraph::new(Span::styled("Public Key (64 hex chars):", Style::default().fg(Color::Gray))),
        chunks[0],
    );
    let key_block = Block::default().borders(Borders::ALL)
        .border_style(if field == 0 { Style::default().fg(Color::Cyan) } else { Style::default() });
    f.render_widget(
        Paragraph::new(key_input).block(key_block).wrap(Wrap { trim: true }),
        chunks[1],
    );
    if field == 0 {
        let cx = (chunks[1].x + 1 + key_input.len() as u16).min(chunks[1].x + chunks[1].width - 2);
        f.set_cursor(cx, chunks[1].y + 1);
    }

    f.render_widget(
        Paragraph::new(Span::styled("Display name:", Style::default().fg(Color::Gray))),
        chunks[2],
    );
    let name_block = Block::default().borders(Borders::ALL)
        .border_style(if field == 1 { Style::default().fg(Color::Cyan) } else { Style::default() });
    f.render_widget(
        Paragraph::new(name_input).block(name_block),
        chunks[3],
    );
    if field == 1 {
        let cx = (chunks[3].x + 1 + name_input.len() as u16).min(chunks[3].x + chunks[3].width - 2);
        f.set_cursor(cx, chunks[3].y + 1);
    }

    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("Tab", Style::default().fg(Color::Yellow)),
            Span::styled(" switch field  ", Style::default().fg(Color::DarkGray)),
            Span::styled("Enter", Style::default().fg(Color::Green)),
            Span::styled(" confirm  ", Style::default().fg(Color::DarkGray)),
            Span::styled("Esc", Style::default().fg(Color::Red)),
            Span::styled(" cancel", Style::default().fg(Color::DarkGray)),
        ])),
        chunks[4],
    );
}

pub fn render_send_file(f: &mut Frame, path_input: &str) {
    let area = centered_rect(60, 30, f.size());
    f.render_widget(Clear, area);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Send File ")
        .border_style(Style::default().fg(Color::Cyan));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Length(3), Constraint::Min(0)])
        .split(inner);

    f.render_widget(
        Paragraph::new(Span::styled("File path:", Style::default().fg(Color::Gray))),
        chunks[0],
    );
    let b = Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::Cyan));
    f.render_widget(Paragraph::new(path_input).block(b), chunks[1]);
    let cx = (chunks[1].x + 1 + path_input.len() as u16).min(chunks[1].x + chunks[1].width - 2);
    f.set_cursor(cx, chunks[1].y + 1);

    f.render_widget(
        Paragraph::new(Span::styled("Enter send  Esc cancel", Style::default().fg(Color::DarkGray))),
        chunks[2],
    );
}

pub fn render_confirm(f: &mut Frame, message: &str) {
    let area = centered_rect(50, 25, f.size());
    f.render_widget(Clear, area);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Confirm ")
        .border_style(Style::default().fg(Color::Red));
    let inner = block.inner(area);
    f.render_widget(block, area);

    f.render_widget(
        Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled(message, Style::default().fg(Color::White).add_modifier(Modifier::BOLD))),
            Line::from(""),
            Line::from(vec![
                Span::styled("Y", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
                Span::styled(" confirm  ", Style::default().fg(Color::DarkGray)),
                Span::styled("Esc", Style::default().fg(Color::Green)),
                Span::styled(" cancel", Style::default().fg(Color::DarkGray)),
            ]),
        ]),
        inner,
    );
}

pub fn render_phrase(f: &mut Frame, phrase: &str) {
    let area = centered_rect(70, 60, f.size());
    f.render_widget(Clear, area);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(" ⚠ Recovery Phrase — keep secret ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)))
        .border_style(Style::default().fg(Color::Yellow));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let words: Vec<&str> = phrase.split_whitespace().collect();
    let mut lines = vec![
        Line::from(Span::styled(
            "Anyone with this phrase can access your identity. Never share it.",
            Style::default().fg(Color::Red),
        )),
        Line::from(""),
    ];
    for row in 0..4 {
        let start = row * 3;
        let mut spans = Vec::new();
        for col in 0..3 {
            let i = start + col;
            if i < words.len() {
                spans.push(Span::styled(
                    format!("{:2}. {:<14}", i + 1, words[i]),
                    Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
                ));
            }
        }
        lines.push(Line::from(spans));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("Esc  close", Style::default().fg(Color::DarkGray))));

    f.render_widget(Paragraph::new(lines), inner);
}

pub fn render_qr(f: &mut Frame, hex: &str) {
    let area = centered_rect(50, 70, f.size());
    f.render_widget(Clear, area);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Public Key QR ")
        .border_style(Style::default().fg(Color::Cyan));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let mut lines = Vec::new();

    // Render QR using the qrcode crate.
    match qrcode::QrCode::new(hex.as_bytes()) {
        Ok(code) => {
            let matrix = code.to_colors();
            let width = code.width();
            // Use half-block rendering: two rows of QR per terminal row.
            let height = matrix.len() / width;
            for y in (0..height).step_by(2) {
                let mut spans = Vec::new();
                for x in 0..width {
                    let top = matrix[y * width + x] == qrcode::Color::Dark;
                    let bot = if y + 1 < height {
                        matrix[(y + 1) * width + x] == qrcode::Color::Dark
                    } else {
                        false
                    };
                    let ch = match (top, bot) {
                        (true, true)  => "█",
                        (true, false) => "▀",
                        (false, true) => "▄",
                        (false,false) => " ",
                    };
                    spans.push(Span::raw(ch));
                }
                lines.push(Line::from(spans));
            }
        }
        Err(_) => {
            lines.push(Line::from(Span::styled("QR generation failed", Style::default().fg(Color::Red))));
        }
    }

    lines.push(Line::from(""));
    // Truncated key for display.
    let key_display = if hex.len() > 24 {
        format!("{}…{}", &hex[..12], &hex[hex.len()-12..])
    } else {
        hex.to_owned()
    };
    lines.push(Line::from(Span::styled(key_display, Style::default().fg(Color::Cyan))));
    lines.push(Line::from(Span::styled("Esc close", Style::default().fg(Color::DarkGray))));

    f.render_widget(Paragraph::new(lines), inner);
}
