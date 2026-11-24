//! Kitty graphics protocol backend.
//!
//! Encodes frames as raw RGBA and transmits them using the Kitty terminal
//! graphics protocol (APC escape sequences).  Supports chunked transmission
//! for frames larger than 4 KiB of base64 payload.
//!
//! The caller must write the returned escape string directly to the terminal
//! after moving the cursor to the target (col, row) position.  This backend
//! does NOT write to stdout itself.
//!
//! Reference: <https://sw.kovidgoyal.net/kitty/graphics-protocol/>

use crate::detection::TerminalGraphics;
use base64::Engine as _;
use image::{imageops::FilterType, RgbaImage};

/// Stable image ID used for all video frames.  Kitty caches images by ID,
/// so reusing the same ID causes the terminal to replace the previous frame
/// efficiently.
const VIDEO_IMAGE_ID: u32 = 42;

/// Maximum raw bytes per base64 chunk (4096 base64 chars ≈ 3072 raw bytes).
const CHUNK_BYTES: usize = 3072;

pub struct KittyBackend;

impl KittyBackend {
    pub fn kind(&self) -> TerminalGraphics { TerminalGraphics::Kitty }

    /// Scale `frame` to fit within `cols`×`rows` cells and return the escape
    /// sequence string.  Callers should move the cursor to the target position
    /// then `print!("{}", sequence)`.
    pub fn render_to_string(&self, frame: &RgbaImage, cols: u16, rows: u16) -> String {
        if cols == 0 || rows == 0 { return String::new(); }

        // Each terminal cell is typically ~2× taller in pixels than it is wide
        // (e.g. 8×16 px).  We use 2:1 for safe sizing.
        let target_w = cols as u32;
        let target_h = rows as u32 * 2;
        let scaled = image::imageops::resize(frame, target_w, target_h, FilterType::Triangle);
        let rgba_bytes = scaled.as_raw();

        let payload = base64::engine::general_purpose::STANDARD.encode(rgba_bytes);
        let chunks: Vec<&str> = payload
            .as_bytes()
            .chunks(CHUNK_BYTES * 4 / 3) // base64 is 4/3 the raw size
            .map(|c| std::str::from_utf8(c).unwrap_or(""))
            .collect();

        let mut out = String::with_capacity(payload.len() + 256);

        // Delete any previous placement for this image ID.
        out.push_str(&format!("\x1b_Ga=d,d=i,i={VIDEO_IMAGE_ID}\x1b\\"));

        for (i, chunk) in chunks.iter().enumerate() {
            let more = if i + 1 < chunks.len() { 1 } else { 0 };
            let params = if i == 0 {
                format!(
                    "a=T,f=32,s={},v={},c={},r={},m={},q=2,i={}",
                    target_w, target_h, cols, rows, more, VIDEO_IMAGE_ID,
                )
            } else {
                format!("m={more},q=2,i={VIDEO_IMAGE_ID}")
            };
            out.push_str(&format!("\x1b_G{params};{chunk}\x1b\\"));
        }

        out
    }

    /// Return an escape sequence that clears (deletes) the video image.
    pub fn clear(&self) -> String {
        format!("\x1b_Ga=d,d=i,i={VIDEO_IMAGE_ID}\x1b\\")
    }
}
