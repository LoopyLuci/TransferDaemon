//! QR code widget — renders a contact public key as a scannable QR code.
//!
//! Redesigned with the new design system for a modern, accessible experience.

use crate::design::DesignTokens;
use egui::{Color32, ColorImage, Context, Pos2, TextureHandle, TextureOptions, Ui, Vec2};
use qrcode::QrCode;

pub struct QrWidget {
    data: String,
    texture: Option<TextureHandle>,
}

impl QrWidget {
    pub fn new() -> Self {
        Self {
            data: String::new(),
            texture: None,
        }
    }

    pub fn show(&mut self, ui: &mut Ui, ctx: &Context, data: &str, size: f32) {
        let tokens = DesignTokens::current();

        if self.data != data || self.texture.is_none() {
            self.data = data.to_owned();
            self.texture = build_texture(ctx, data, &tokens);
        }
        match &self.texture {
            Some(tex) => {
                // Draw QR code with a white background and rounded corners
                let (rect, _) = ui.allocate_exact_size(Vec2::splat(size + 16.0), egui::Sense::hover());
                let qr_rect = egui::Rect::from_center_size(
                    rect.center(),
                    Vec2::splat(size),
                );

                // White background for QR code
                ui.painter().rect_filled(
                    qr_rect,
                    8.0,
                    Color32::WHITE,
                );

                // QR code image
                ui.painter().image(
                    tex.id(),
                    qr_rect,
                    egui::Rect::from_min_size(Pos2::ZERO, Vec2::splat(1.0)),
                    Color32::WHITE,
                );
            }
            None => {
                ui.label(
                    egui::RichText::new("⚠ QR unavailable")
                        .color(tokens.palette.error),
                );
            }
        }
    }
}

impl Default for QrWidget {
    fn default() -> Self {
        Self::new()
    }
}

fn build_texture(ctx: &Context, data: &str, _tokens: &DesignTokens) -> Option<TextureHandle> {
    let code = QrCode::new(data.as_bytes()).ok()?;
    let quiet = 2usize;
    let modules = code.width();
    let side = modules + quiet * 2;
    let mut pixels = vec![Color32::WHITE; side * side];
    for y in 0..modules {
        for x in 0..modules {
            if code[(y, x)] == qrcode::Color::Dark {
                pixels[(y + quiet) * side + (x + quiet)] = Color32::BLACK;
            }
        }
    }
    let img = ColorImage {
        size: [side, side],
        pixels,
    };
    Some(ctx.load_texture(
        "qr-code",
        img,
        TextureOptions::NEAREST,
    ))
}
