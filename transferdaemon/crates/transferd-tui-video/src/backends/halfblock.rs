//! Half-block Unicode backend.
//!
//! Uses the ▀ (U+2580 UPPER HALF BLOCK) character with ANSI 24-bit color to
//! display two pixels per terminal cell — the top pixel as foreground and the
//! bottom pixel as background.
//!
//! This backend fills a ratatui Buffer directly, so it integrates cleanly with
//! the rest of the TUI without any direct terminal writes.

use crate::detection::TerminalGraphics;
use image::{imageops::FilterType, RgbaImage};
use ratatui::{buffer::Buffer, layout::Rect, style::Color};

pub struct HalfBlockBackend;

impl HalfBlockBackend {
    pub fn kind(&self) -> TerminalGraphics { TerminalGraphics::HalfBlock }

    /// Scale `frame` to fit `area` (two pixels per row) and write colored half-block
    /// characters into the ratatui buffer.
    pub fn render_to_buffer(&self, frame: &RgbaImage, area: Rect, buf: &mut Buffer) {
        if area.width == 0 || area.height == 0 { return; }

        let target_w = area.width as u32;
        let target_h = (area.height as u32) * 2; // 2 vertical pixels per cell row

        let scaled = image::imageops::resize(frame, target_w, target_h, FilterType::Triangle);

        for row in 0..area.height {
            for col in 0..area.width {
                let px  = col as u32;
                let py0 = (row as u32) * 2;
                let py1 = py0 + 1;

                let top = scaled.get_pixel(px, py0);
                let bot = if py1 < scaled.height() {
                    *scaled.get_pixel(px, py1)
                } else {
                    *top
                };

                let x = area.x + col;
                let y = area.y + row;
                if x >= buf.area.x + buf.area.width || y >= buf.area.y + buf.area.height {
                    continue;
                }
                let cell = buf.get_mut(x, y);
                cell.set_char('▀');
                cell.set_fg(Color::Rgb(top[0], top[1], top[2]));
                cell.set_bg(Color::Rgb(bot[0], bot[1], bot[2]));
            }
        }
    }

    /// Alternative: return a `String` of ANSI escape codes for direct-write callers.
    pub fn render_to_string(&self, frame: &RgbaImage, cols: u16, rows: u16) -> String {
        if cols == 0 || rows == 0 { return String::new(); }
        let scaled = image::imageops::resize(
            frame, cols as u32, rows as u32 * 2, FilterType::Triangle,
        );
        let mut out = String::with_capacity((cols as usize * rows as usize) * 30);
        for row in 0..rows {
            for col in 0..cols as u32 {
                let py0 = (row as u32) * 2;
                let py1 = py0 + 1;
                let top = scaled.get_pixel(col, py0);
                let bot = if py1 < scaled.height() { *scaled.get_pixel(col, py1) } else { *top };
                out.push_str(&format!(
                    "\x1b[38;2;{};{};{}m\x1b[48;2;{};{};{}m▀",
                    top[0], top[1], top[2], bot[0], bot[1], bot[2],
                ));
            }
            out.push_str("\x1b[0m\r\n");
        }
        out
    }
}
