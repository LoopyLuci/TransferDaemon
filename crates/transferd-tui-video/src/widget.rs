//! `VideoCallOverlay` — integrates the terminal video renderer into ratatui.
//!
//! # Two rendering paths
//!
//! | Backend       | How it renders                                      |
//! |---------------|-----------------------------------------------------|
//! | HalfBlock     | Fills ratatui `Buffer` cells directly (via Widget)  |
//! | Ascii         | Same as HalfBlock                                   |
//! | Kitty/Sixel   | Produces an escape string; caller writes to stdout  |
//!
//! In the main event loop, after `terminal.draw()`, call
//! `overlay.take_direct_render()` and write the result (if `Some`) to stdout
//! at the cursor position for the video area.

use crate::{
    backends::{AsciiBackend, HalfBlockBackend, KittyBackend, SixelBackend},
    detection::{detect, TerminalGraphics},
};
use image::RgbaImage;
use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders},
};
use std::time::Instant;
use tokio::sync::mpsc;
use transferd_webrtc::types::VideoFrame;

// ---------------------------------------------------------------------------
// Overlay state
// ---------------------------------------------------------------------------

pub struct VideoCallOverlay {
    /// Contact name shown in the overlay title.
    pub contact_name: String,
    /// Current call duration reference.
    pub started_at: Instant,
    /// Channel for incoming remote video frames.
    frame_rx: Option<mpsc::Receiver<VideoFrame>>,
    /// Most recently received frame, converted to an RGBA image.
    last_frame: Option<RgbaImage>,
    /// The detected (or overridden) rendering backend kind.
    pub backend: TerminalGraphics,
    /// Half-block backend (used for buffer-filling and as fallback).
    halfblock: HalfBlockBackend,
    ascii: AsciiBackend,
    kitty: KittyBackend,
    sixel: SixelBackend,
    /// Pending escape sequence to write directly after ratatui draw.
    pending_direct: Option<(Rect, String)>,
}

impl VideoCallOverlay {
    pub fn new(contact_name: String) -> Self {
        Self {
            contact_name,
            started_at: Instant::now(),
            frame_rx: None,
            last_frame: None,
            backend: detect(),
            halfblock: HalfBlockBackend,
            ascii: AsciiBackend,
            kitty: KittyBackend,
            sixel: SixelBackend,
            pending_direct: None,
        }
    }

    /// Attach a video frame receiver (from `SimulatedCallSession.remote_video_rx`).
    pub fn set_frame_rx(&mut self, rx: mpsc::Receiver<VideoFrame>) {
        self.frame_rx = Some(rx);
    }

    /// Drain the latest frame from the channel (non-blocking).  Called every
    /// tick from the main event loop.
    pub fn tick(&mut self) {
        if let Some(ref mut rx) = self.frame_rx {
            // Drain and keep only the most recent frame.
            let mut latest = None;
            while let Ok(f) = rx.try_recv() {
                latest = Some(f);
            }
            if let Some(f) = latest {
                // Convert VideoFrame (raw RGBA bytes) to RgbaImage.
                if let Some(img) = RgbaImage::from_raw(f.width, f.height, f.rgba) {
                    self.last_frame = Some(img);
                }
            }
        }
    }

    /// Render the video overlay.
    ///
    /// For HalfBlock/Ascii backends this fills the buffer directly.
    /// For Kitty/Sixel backends this fills the area with a placeholder and
    /// stores the escape string for `take_direct_render()`.
    pub fn render_to_buffer(&mut self, area: Rect, buf: &mut Buffer) {
        // Always draw the surrounding box.
        let elapsed = self.started_at.elapsed().as_secs();
        let m = elapsed / 60;
        let s = elapsed % 60;
        let title = format!(" 📞 {} {:02}:{:02} ", self.contact_name, m, s);

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Green))
            .title(Span::styled(title, Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)));
        let inner = block.inner(area);
        block.render_in_buffer(area, buf);

        if inner.width < 2 || inner.height < 2 { return; }

        let Some(ref frame) = self.last_frame else {
            // No frame yet — show a "waiting" message.
            let msg = Line::from(Span::styled(
                "  waiting for video…",
                Style::default().fg(Color::DarkGray),
            ));
            let x = inner.x;
            let y = inner.y + inner.height / 2;
            for (i, ch) in "  waiting for video…".chars().enumerate() {
                let cx = x + i as u16;
                if cx >= inner.x + inner.width { break; }
                buf.get_mut(cx, y).set_char(ch)
                    .set_fg(Color::DarkGray);
            }
            let _ = msg;
            return;
        };

        match self.backend {
            TerminalGraphics::HalfBlock => {
                self.halfblock.render_to_buffer(frame, inner, buf);
            }
            TerminalGraphics::Ascii => {
                self.ascii.render_to_buffer(frame, inner, buf);
            }
            TerminalGraphics::Kitty => {
                // Fill area with a colored placeholder so ratatui doesn't overdraw.
                fill_placeholder(inner, buf, Color::DarkGray, '▓');
                let seq = self.kitty.render_to_string(frame, inner.width, inner.height);
                self.pending_direct = Some((inner, seq));
            }
            TerminalGraphics::Sixel => {
                fill_placeholder(inner, buf, Color::DarkGray, '▒');
                let seq = self.sixel.render_to_string(frame, inner.width, inner.height);
                self.pending_direct = Some((inner, seq));
            }
        }
    }

    /// For Kitty/Sixel backends: take the pending escape sequence and the
    /// target rect.  The caller must move the cursor to `(rect.x, rect.y)`
    /// and then write the string directly to stdout.
    pub fn take_direct_render(&mut self) -> Option<(Rect, String)> {
        self.pending_direct.take()
    }

    /// Return a test-pattern `RgbaImage` for preview / development.
    pub fn test_pattern(width: u32, height: u32, frame_idx: u32) -> RgbaImage {
        RgbaImage::from_fn(width, height, |x, y| {
            // Color bars: 8 vertical stripes, cycling hue with a scrolling
            // horizontal wave for frame_idx animation.
            let stripe = (x * 8 / width) as u8;
            let wave   = (((x + frame_idx * 2) % width) as f32 / width as f32
                * std::f32::consts::TAU).sin();
            let bright = ((y as f32 / height as f32 + wave * 0.1) * 255.0) as u8;
            let (r, g, b) = match stripe {
                0 => (bright, 0,      0),
                1 => (bright, bright, 0),
                2 => (0,      bright, 0),
                3 => (0,      bright, bright),
                4 => (0,      0,      bright),
                5 => (bright, 0,      bright),
                6 => (bright, bright, bright),
                _ => (bright / 2, bright / 2, bright / 2),
            };
            image::Rgba([r, g, b, 255])
        })
    }
}

// ---------------------------------------------------------------------------
// ratatui Block helper
// ---------------------------------------------------------------------------

trait RenderInBuffer {
    fn render_in_buffer(self, area: Rect, buf: &mut Buffer);
}

impl RenderInBuffer for Block<'_> {
    fn render_in_buffer(self, area: Rect, buf: &mut Buffer) {
        use ratatui::widgets::Widget;
        Widget::render(self, area, buf);
    }
}

fn fill_placeholder(area: Rect, buf: &mut Buffer, color: Color, ch: char) {
    for y in area.y..area.y + area.height {
        for x in area.x..area.x + area.width {
            if x < buf.area.x + buf.area.width && y < buf.area.y + buf.area.height {
                buf.get_mut(x, y).set_char(ch).set_fg(color);
            }
        }
    }
}
