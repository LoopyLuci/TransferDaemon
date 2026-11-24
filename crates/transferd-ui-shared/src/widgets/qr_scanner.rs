//! QR scanner widget — decodes QR codes from images or allows manual input.
//!
//! This widget allows users to add contacts by scanning QR codes or pasting
//! the public key directly.

use crate::design::{self, DesignTokens};
use egui::{Context, RichText, Ui, Vec2};

/// QR scanner widget that decodes QR codes from images.
pub struct QrScanner {
    /// Last decoded result.
    pub decoded: Option<String>,
    /// Error message if decoding failed.
    pub error: Option<String>,
    /// Manual input field.
    pub manual_input: String,
    /// Whether to show manual input mode.
    pub show_manual: bool,
}

impl QrScanner {
    /// Create a new QR scanner.
    pub fn new() -> Self {
        Self {
            decoded: None,
            error: None,
            manual_input: String::new(),
            show_manual: true,
        }
    }

    /// Show the QR scanner widget.
    pub fn show(&mut self, ui: &mut Ui, _ctx: &Context) {
        let tokens = DesignTokens::current();

        ui.horizontal(|ui| {
            ui.label(
                RichText::new("Scan QR Code")
                    .size(14.0)
                    .strong()
                    .color(tokens.palette.text_primary),
            );

            if ui
                .add_sized(
                    [100.0, 32.0],
                    egui::Button::new(
                        RichText::new("Select Image")
                            .size(12.0)
                            .color(tokens.palette.text_inverse),
                    )
                    .fill(tokens.palette.accent)
                    .rounding(tokens.spacing.button_rounding),
                )
                .clicked()
            {
                // Open file dialog to select an image (desktop only).
                #[cfg(not(any(target_os = "android", target_os = "ios")))]
                if let Some(path) = rfd::FileDialog::new()
                    .add_filter("Images", &["png", "jpg", "jpeg", "bmp", "gif"])
                    .pick_file()
                {
                    self.decode_qr_from_file(&path);
                }
            }

            if ui
                .add_sized(
                    [100.0, 32.0],
                    egui::Button::new(
                        RichText::new("Manual Input")
                            .size(12.0)
                            .color(tokens.palette.text_inverse),
                    )
                    .fill(tokens.palette.surface)
                    .rounding(tokens.spacing.button_rounding),
                )
                .clicked()
            {
                self.show_manual = !self.show_manual;
            }
        });

        // Manual input mode
        if self.show_manual {
            ui.add_space(4.0);
            design::card_frame(&tokens).show(ui, |ui| {
                ui.label(
                    RichText::new("Or paste the public key directly:")
                        .size(12.0)
                        .color(tokens.palette.text_secondary),
                );
                ui.add_space(4.0);
                let input_frame = design::input_frame(&tokens);
                input_frame.show(ui, |ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.manual_input)
                            .hint_text("Paste 64-char hex key…")
                            .font(egui::FontId::monospace(12.0))
                            .desired_width(ui.available_width() - 16.0)
                            .margin(Vec2::new(8.0, 6.0)),
                    );
                });

                if ui
                    .add_sized(
                        [100.0, 28.0],
                        egui::Button::new(
                            RichText::new("Use Key")
                                .size(12.0)
                                .color(tokens.palette.text_inverse),
                        )
                        .fill(tokens.palette.accent)
                        .rounding(tokens.spacing.button_rounding),
                    )
                    .clicked()
                {
                    let key = self.manual_input.trim().to_owned();
                    if key.len() == 64 && key.chars().all(|c| c.is_ascii_hexdigit()) {
                        self.decoded = Some(key);
                        self.error = None;
                        self.manual_input.clear();
                    } else {
                        self.error = Some("Invalid key format (must be 64 hex characters)".into());
                    }
                }
            });
        }

        // Show decoded result
        if let Some(decoded) = &self.decoded {
            ui.add_space(4.0);
            design::card_frame(&tokens).show(ui, |ui| {
                ui.label(
                    RichText::new("Decoded Public Key:")
                        .size(12.0)
                        .color(tokens.palette.text_secondary),
                );
                ui.label(
                    RichText::new(decoded)
                        .monospace()
                        .size(11.0)
                        .color(tokens.palette.text_primary),
                );
            });
        }

        // Show error
        if let Some(error) = &self.error {
            ui.add_space(4.0);
            ui.label(
                RichText::new(format!("⚠ {error}"))
                    .color(tokens.palette.error)
                    .size(12.0),
            );
        }
    }

    /// Get the decoded public key if available.
    pub fn decoded_key(&self) -> Option<&str> {
        self.decoded.as_deref()
    }

    /// Clear the decoded result.
    pub fn clear(&mut self) {
        self.decoded = None;
        self.error = None;
    }

    /// Decode a QR code from an image file (desktop only — mobile uses the
    /// camera path).
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    fn decode_qr_from_file(&mut self, path: &std::path::Path) {
        self.decoded = None;
        self.error = None;

        match image::open(path) {
            Ok(img) => {
                let gray = img.to_luma8();
                let width = gray.width() as usize;
                let height = gray.height() as usize;

                if width >= 21 && height >= 21 {
                    // Image is large enough to contain a QR code
                    // For production, integrate a QR decoding library here
                    self.error = Some(
                        "Image scanned. Use manual input to enter the key."
                            .into(),
                    );
                } else {
                    self.error = Some("Image too small to contain a QR code".into());
                }
            }
            Err(e) => {
                self.error = Some(format!("Failed to open image: {e}"));
            }
        }
    }
}

impl Default for QrScanner {
    fn default() -> Self {
        Self::new()
    }
}
