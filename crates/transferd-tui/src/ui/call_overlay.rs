use crate::app::CallState;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
    Frame,
};

/// Render the call overlay.  For audio-only calls this is the small corner
/// widget.  For video calls the video frame occupies a larger area and the
/// controls sit below it.
pub fn render(f: &mut Frame, cs: &mut CallState) {
    if cs.video.is_some() {
        render_video_call(f, cs);
    } else {
        render_audio_call(f, cs);
    }
}

fn render_audio_call(f: &mut Frame, cs: &CallState) {
    let area = audio_rect(f.size());
    f.render_widget(Clear, area);

    let elapsed = cs.started_at.elapsed().as_secs();
    let h = elapsed / 3600;
    let m = (elapsed % 3600) / 60;
    let s = elapsed % 60;
    let duration = if h > 0 { format!("{h:02}:{m:02}:{s:02}") } else { format!("{m:02}:{s:02}") };
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
        Line::from(Span::styled("[Ctrl+V] Video", Style::default().fg(Color::Cyan))),
    ];

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Green))
        .title(Span::styled(" Call ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)));
    f.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_video_call(f: &mut Frame, cs: &mut CallState) {
    let area = video_rect(f.size());
    f.render_widget(Clear, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(3)])
        .split(area);

    // Video frame in the top region.
    if let Some(ref mut overlay) = cs.video {
        let buf = f.buffer_mut();
        overlay.render_to_buffer(chunks[0], buf);
    }

    // Controls in the bottom strip.
    let mute_label = if cs.muted { "Muted" } else { "Live" };
    let elapsed = cs.started_at.elapsed().as_secs();
    let controls = Line::from(vec![
        Span::styled(format!(" {:02}:{:02} ", elapsed / 60, elapsed % 60),
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        Span::styled(format!("  {mute_label}  "), Style::default().fg(Color::Yellow)),
        Span::styled("[M] mute  ", Style::default().fg(Color::DarkGray)),
        Span::styled("[V] hide video  ", Style::default().fg(Color::DarkGray)),
        Span::styled("[H] hang up", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
    ]);
    let ctrl_block = Block::default()
        .borders(Borders::TOP)
        .border_style(Style::default().fg(Color::Green));
    f.render_widget(Paragraph::new(controls).block(ctrl_block), chunks[1]);
}

fn audio_rect(r: Rect) -> Rect {
    Rect {
        x: r.width.saturating_sub(26),
        y: r.height.saturating_sub(10),
        width: 26,
        height: 8,
    }
}

fn video_rect(r: Rect) -> Rect {
    // Video overlay: right half of the screen, top 2/3.
    let w = (r.width / 2).max(40);
    let h = (r.height * 2 / 3).max(20);
    Rect {
        x: r.width.saturating_sub(w),
        y: 0,
        width: w,
        height: h,
    }
}
