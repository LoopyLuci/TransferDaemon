//! Sixel graphics backend.
//!
//! Implements a minimal but correct Sixel encoder using a fixed 216-color
//! web-safe palette (6×6×6 RGB cube, identical to xterm's default).
//!
//! The returned escape string must be written directly to the terminal after
//! positioning the cursor.
//!
//! Reference: <https://en.wikipedia.org/wiki/Sixel>

use crate::detection::TerminalGraphics;
use image::{imageops::FilterType, RgbaImage};

pub struct SixelBackend;

impl SixelBackend {
    pub fn kind(&self) -> TerminalGraphics { TerminalGraphics::Sixel }

    pub fn render_to_string(&self, frame: &RgbaImage, cols: u16, rows: u16) -> String {
        if cols == 0 || rows == 0 { return String::new(); }

        // Target pixel size: cols × rows*2 (sixel uses 6 pixel rows per band,
        // so round up to multiple of 6).
        let pw = cols as u32;
        let ph_raw = rows as u32 * 2;
        let ph = ph_raw.div_ceil(6) * 6;

        let scaled = image::imageops::resize(frame, pw, ph, FilterType::Triangle);

        encode_sixel(&scaled, pw, ph)
    }
}

/// Encode an RGBA image as a Sixel escape sequence using a 216-color cube.
fn encode_sixel(img: &RgbaImage, w: u32, h: u32) -> String {
    let mut out = String::with_capacity((w * h) as usize * 3);

    // DCS introducer: pixel aspect ratio 1:1 (Pn=0 for default, Pu=1 for pixel).
    out.push_str("\x1bPq");

    // Emit palette definitions.  Colors are R,G,B in 0-100 scale.
    for idx in 0u16..216 {
        let r100 = (idx / 36)       * 20;
        let g100 = ((idx / 6) % 6)  * 20;
        let b100 = (idx % 6)        * 20;
        out.push_str(&format!("#{idx};2;{r100};{g100};{b100}"));
    }

    // Process each band of 6 rows.
    let bands = h / 6;
    for band in 0..bands {
        let band_y0 = band * 6;

        // For each color, build a sixel bitmask row (indexed by column).
        // palette_rows[color_idx][col] = sixel bitmask byte
        let mut palette_rows: Vec<Vec<u8>> = vec![vec![0u8; w as usize]; 216];
        let mut used = vec![false; 216];

        for row_in_band in 0..6u32 {
            let y = band_y0 + row_in_band;
            if y >= h { break; }
            let bit = 1u8 << row_in_band;
            for x in 0..w {
                let p = img.get_pixel(x, y);
                let ci = quantize_to_216(p[0], p[1], p[2]);
                palette_rows[ci][x as usize] |= bit;
                used[ci] = true;
            }
        }

        // Emit the sixel data for each used color.
        for ci in 0..216usize {
            if !used[ci] { continue; }

            // Select color.
            out.push_str(&format!("#{ci}"));

            // Emit sixel characters: each char = bitmask + 0x3F.
            // Apply RLE: sequences of identical characters are compressed as
            // `!<count><char>`.
            let row = &palette_rows[ci];
            let mut i = 0;
            while i < w as usize {
                let ch  = row[i];
                let mut run = 1;
                while i + run < w as usize && row[i + run] == ch { run += 1; }
                let sixel = (ch + 0x3F) as char;
                if run >= 3 {
                    out.push('!');
                    out.push_str(&run.to_string());
                    out.push(sixel);
                } else {
                    for _ in 0..run { out.push(sixel); }
                }
                i += run;
            }

            // `$` returns to the beginning of the band for the next color.
            out.push('$');
        }

        // `-` advances to the next sixel band.
        out.push('-');
    }

    // ST: string terminator.
    out.push_str("\x1b\\");
    out
}

/// Map an RGB pixel to the nearest index in the 6×6×6 web-safe cube.
#[inline]
fn quantize_to_216(r: u8, g: u8, b: u8) -> usize {
    let ri = (r as usize * 5 / 255).min(5);
    let gi = (g as usize * 5 / 255).min(5);
    let bi = (b as usize * 5 / 255).min(5);
    ri * 36 + gi * 6 + bi
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantize_corners() {
        assert_eq!(quantize_to_216(0,   0,   0),   0);   // black
        assert_eq!(quantize_to_216(255, 0,   0),   180); // red
        assert_eq!(quantize_to_216(0,   255, 0),   30);  // green
        assert_eq!(quantize_to_216(0,   0,   255), 5);   // blue
        assert_eq!(quantize_to_216(255, 255, 255), 215); // white
    }

    #[test]
    fn sixel_roundtrip_smoke() {
        let img = RgbaImage::from_fn(4, 6, |x, y| {
            image::Rgba([((x * 50) as u8), ((y * 40) as u8), 128, 255])
        });
        let out = encode_sixel(&img, 4, 6);
        assert!(out.starts_with("\x1bPq"));
        assert!(out.ends_with("\x1b\\"));
    }
}
