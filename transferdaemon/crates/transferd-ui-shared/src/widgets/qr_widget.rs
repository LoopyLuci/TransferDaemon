//! QR code widget — renders a contact public key as a scannable QR code.

use egui::{ColorImage, Context, TextureHandle, TextureOptions, Ui, Vec2};
use qrcode::QrCode;

pub struct QrWidget {
    data: String,
    texture: Option<TextureHandle>,
}

impl QrWidget {
    pub fn new() -> Self {
        Self { data: String::new(), texture: None }
    }

    pub fn show(&mut self, ui: &mut Ui, ctx: &Context, data: &str, size: f32) {
        if self.data != data || self.texture.is_none() {
            self.data = data.to_owned();
            self.texture = build_texture(ctx, data);
        }
        match &self.texture {
            Some(tex) => { ui.image((tex.id(), Vec2::splat(size))); }
            None => { ui.label(egui::RichText::new("⚠ QR unavailable").color(egui::Color32::RED)); }
        }
    }
}

impl Default for QrWidget {
    fn default() -> Self { Self::new() }
}

fn build_texture(ctx: &Context, data: &str) -> Option<TextureHandle> {
    let code = QrCode::new(data.as_bytes()).ok()?;
    let quiet = 2usize;
    let modules = code.width();
    let side = modules + quiet * 2;
    let mut pixels = vec![egui::Color32::WHITE; side * side];
    for y in 0..modules {
        for x in 0..modules {
            if code[(y, x)] == qrcode::Color::Dark {
                pixels[(y + quiet) * side + (x + quiet)] = egui::Color32::BLACK;
            }
        }
    }
    let img = ColorImage { size: [side, side], pixels };
    Some(ctx.load_texture("qr-code", img, TextureOptions::NEAREST))
}
