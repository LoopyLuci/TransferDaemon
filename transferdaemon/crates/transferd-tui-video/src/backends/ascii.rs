//! ASCII art backend.
//!
//! Maps pixel luminance to a gradient of characters sorted by visual density.
//! Fills a ratatui Buffer directly, like HalfBlockBackend.

use crate::detection::TerminalGraphics;
use image::{imageops::FilterType, RgbaImage};
use ratatui::{buffer::Buffer, layout::Rect, style::Color};

/// Characters ordered from dark (space) to bright (@).
const GRADIENT: &[char] = &[' ', '.', ':', '-', '=', '+', '*', '#', '%', '@'];

pub struct AsciiBackend;

impl AsciiBackend {
    pub fn kind(&self) -> TerminalGraphics { TerminalGraphics::Ascii }

    pub fn render_to_buffer(&self, frame: &RgbaImage, area: Rect, buf: &mut Buffer) {
        if area.width == 0 || area.height == 0 { return; }

        let scaled = image::imageops::resize(
            frame, area.width as u32, area.height as u32, FilterType::Nearest,
        );

        for row in 0..area.height {
            for col in 0..area.width {
                let p = scaled.get_pixel(col as u32, row as u32);
                let luma = (0.299 * p[0] as f32 + 0.587 * p[1] as f32 + 0.114 * p[2] as f32)
                    as usize;
                let idx  = (luma * (GRADIENT.len() - 1)) / 255;
                let ch   = GRADIENT[idx];
                let x = area.x + col;
                let y = area.y + row;
                if x >= buf.area.x + buf.area.width || y >= buf.area.y + buf.area.height {
                    continue;
                }
                let cell = buf.get_mut(x, y);
                cell.set_char(ch);
                cell.set_fg(Color::Rgb(p[0], p[1], p[2]));
            }
        }
    }

    pub fn render_to_string(&self, frame: &RgbaImage, cols: u16, rows: u16) -> String {
        if cols == 0 || rows == 0 { return String::new(); }
        let scaled = image::imageops::resize(
            frame, cols as u32, rows as u32, FilterType::Nearest,
        );
        let mut out = String::with_capacity(cols as usize * rows as usize * 15);
        for row in 0..rows as u32 {
            for col in 0..cols as u32 {
                let p    = scaled.get_pixel(col, row);
                let luma = (0.299 * p[0] as f32 + 0.587 * p[1] as f32 + 0.114 * p[2] as f32)
                    as usize;
                let idx  = (luma * (GRADIENT.len() - 1)) / 255;
                out.push_str(&format!(
                    "\x1b[38;2;{};{};{}m{}", p[0], p[1], p[2], GRADIENT[idx],
                ));
            }
            out.push_str("\x1b[0m\r\n");
        }
        out
    }
}
