//! Chat message bubble widget.

use crate::design::DesignTokens;
use crate::types::{Message, MessageContent, MessageStatus};
use egui::{Color32, FontId, Pos2, Rounding, Ui, Vec2};

pub const DEFAULT_INBOUND_COLOR: Color32 = Color32::from_rgb(38, 38, 44);
pub const DEFAULT_OUTBOUND_COLOR: Color32 = Color32::from_rgb(0, 122, 255);

const BUBBLE_PADDING: Vec2 = Vec2::new(12.0, 8.0);
const BUBBLE_ROUNDING: f32 = 16.0;
const BUBBLE_ABS_MAX: f32 = 380.0;

/// An action the user took on a bubble (hover menu).
pub enum BubbleAction {
    /// Start a reply quoting the message with this id.
    Reply(String),
    /// Toggle an emoji reaction on the message with this id.
    React { msg_id: String, emoji: String },
}

/// Render a single message bubble. Returns an optional user action when the
/// hover reply/reaction menu is used.
pub fn message_bubble(
    ui: &mut Ui,
    msg: &Message,
    max_width: f32,
    inbound_color: Option<Color32>,
    messages: &[Message],
) -> Option<BubbleAction> {
    let tokens = DesignTokens::current();
    let outbound = msg.outbound;
    let bubble_color = if outbound {
        DEFAULT_OUTBOUND_COLOR
    } else {
        inbound_color.unwrap_or(DEFAULT_INBOUND_COLOR)
    };
    let text_color = tokens.palette.bubble_text;
    let capped = max_width.min(BUBBLE_ABS_MAX);

    let mut action = None;
    ui.with_layout(
        if outbound {
            egui::Layout::right_to_left(egui::Align::TOP)
        } else {
            egui::Layout::left_to_right(egui::Align::TOP)
        },
        |ui| {
            ui.set_max_width(capped);

            let text = match &msg.content {
                MessageContent::Text(t) => t.clone(),
                MessageContent::File {
                    name,
                    size_bytes,
                    transferred_bytes,
                    mime,
                } => {
                    // Image preview: render a thumbnail above the file line.
                    let _ = mime;
                    let preview_done = if *transferred_bytes >= *size_bytes
                        && crate::image_preview::is_image(mime.as_deref(), name)
                    {
                        let path = crate::image_preview::received_path(name);
                        if let Some(tex) = crate::image_preview::thumbnail(ui, &path) {
                            let size = tex.size_vec2();
                            let (rect, _) = ui.allocate_exact_size(size, egui::Sense::hover());
                            ui.painter().image(
                                tex.id(),
                                rect,
                                egui::Rect::from_min_size(egui::Pos2::ZERO, size),
                                Color32::WHITE,
                            );
                            ui.add_space(4.0);
                            true
                        } else {
                            false
                        }
                    } else {
                        false
                    };
                    let _ = preview_done;
                    let pct = if *size_bytes > 0 {
                        transferred_bytes * 100 / size_bytes
                    } else {
                        100
                    };
                    format!("📁 {} ({} MB, {}%)", name, size_bytes / 1_048_576, pct)
                }
            };

            let inner_w = capped - BUBBLE_PADDING.x * 2.0;

            // Resolve the quoted message, if any.
            let reply_galley = msg.reply_to.as_ref().and_then(|rid| {
                messages.iter().find(|m| m.id == *rid).map(|quoted| {
                    let label = format!("↩ {}", quoted.content.preview());
                    ui.painter().layout(
                        label,
                        FontId::proportional(11.0),
                        Color32::from_rgba_premultiplied(255, 255, 255, 160),
                        inner_w,
                    )
                })
            });

            let galley = ui.painter().layout(
                text,
                FontId::proportional(14.0),
                text_color,
                inner_w,
            );

            // Reaction chips (aggregated by emoji).
            let mut reaction_chips: Vec<(String, usize)> = Vec::new();
            for (emoji, _sender) in &msg.reactions {
                if let Some(entry) = reaction_chips.iter_mut().find(|(e, _)| e == emoji) {
                    entry.1 += 1;
                } else {
                    reaction_chips.push((emoji.clone(), 1));
                }
            }

            let status_label = if outbound {
                msg.status.label()
            } else {
                ""
            };
            let ts = format_ts(msg.timestamp_ts);
            let footer = format!("{ts}  {status_label}");
            // Read receipts render in a distinct blue so Delivered vs Read is visible.
            let footer_color = if outbound {
                if msg.status == MessageStatus::Read {
                    Color32::from_rgb(120, 200, 255)
                } else {
                    Color32::from_rgba_premultiplied(255, 255, 255, 140)
                }
            } else {
                Color32::from_rgba_premultiplied(255, 255, 255, 100)
            };
            let footer_galley = ui.painter().layout_no_wrap(
                footer,
                FontId::proportional(11.0),
                footer_color,
            );

            let reply_h = reply_galley.as_ref().map(|g| g.size().y + 3.0).unwrap_or(0.0);
            let chips_h = if reaction_chips.is_empty() {
                0.0
            } else {
                20.0
            };
            let bubble_w = galley
                .size()
                .x
                .max(footer_galley.size().x)
                .max(reply_galley.as_ref().map(|g| g.size().x).unwrap_or(0.0))
                + BUBBLE_PADDING.x * 2.0;
            let bubble_h = galley.size().y
                + footer_galley.size().y
                + reply_h
                + chips_h
                + BUBBLE_PADDING.y * 2.0
                + 4.0;

            let (rect, resp) = ui.allocate_exact_size(
                Vec2::new(bubble_w, bubble_h),
                egui::Sense::click(),
            );

            // Bubble shadow (inbound only)
            if !outbound {
                let shadow_rect = rect.translate(Vec2::new(1.0, 1.0));
                ui.painter().rect_filled(
                    shadow_rect,
                    Rounding::same(BUBBLE_ROUNDING),
                    Color32::from_rgba_premultiplied(0, 0, 0, 20),
                );
            }

            // Bubble
            ui.painter().rect_filled(rect, Rounding::same(BUBBLE_ROUNDING), bubble_color);

            // Quoted reply preview
            let mut y = rect.min.y + BUBBLE_PADDING.y;
            if let Some(g) = &reply_galley {
                let quote_rect = egui::Rect::from_min_size(
                    Pos2::new(rect.min.x + BUBBLE_PADDING.x, y),
                    g.size(),
                );
                ui.painter().rect_filled(
                    quote_rect.expand(2.0),
                    Rounding::same(4.0),
                    Color32::from_rgba_premultiplied(0, 0, 0, 28),
                );
                ui.painter().galley(quote_rect.min, g.clone(), Color32::from_rgba_premultiplied(255, 255, 255, 160));
                y += g.size().y + 3.0;
            }

            // Text
            ui.painter().galley(Pos2::new(rect.min.x + BUBBLE_PADDING.x, y), galley, text_color);

            // Reaction chips
            if !reaction_chips.is_empty() {
                let cy = rect.max.y - BUBBLE_PADDING.y - footer_galley.size().y - chips_h;
                let mut cx = rect.min.x + BUBBLE_PADDING.x;
                for (emoji, count) in &reaction_chips {
                    let label = if *count > 1 {
                        format!("{emoji} {count}")
                    } else {
                        emoji.clone()
                    };
                    let chip = ui.painter().layout_no_wrap(
                        label,
                        FontId::proportional(11.0),
                        Color32::from_rgba_premultiplied(255, 255, 255, 230),
                    );
                    let chip_rect = egui::Rect::from_min_size(
                        Pos2::new(cx, cy),
                        Vec2::new(chip.size().x + 10.0, 16.0),
                    );
                    ui.painter().rect_filled(
                        chip_rect,
                        Rounding::same(8.0),
                        Color32::from_rgba_premultiplied(255, 255, 255, 40),
                    );
                    ui.painter().galley(
                        Pos2::new(cx + 5.0, cy),
                        chip,
                        Color32::from_rgba_premultiplied(255, 255, 255, 230),
                    );
                    cx += chip_rect.width() + 4.0;
                }
            }

            // Footer
            let footer_pos = Pos2::new(
                rect.min.x + BUBBLE_PADDING.x,
                rect.max.y - BUBBLE_PADDING.y - footer_galley.size().y,
            );
            ui.painter().galley(footer_pos, footer_galley, footer_color);

            // Hover menu: reply + a few reactions
            if resp.hovered() {
                let menu_y = rect.top() - 6.0;
                let mut mx = if outbound { rect.right() } else { rect.left() };
                for emoji in ["❤️", "👍", "😂"] {
                    let btn = ui.painter().layout_no_wrap(
                        emoji.to_string(),
                        FontId::proportional(13.0),
                        tokens.palette.text_primary,
                    );
                    let btn_rect = egui::Rect::from_min_size(
                        Pos2::new(mx - 26.0, menu_y),
                        Vec2::new(26.0, 26.0),
                    );
                    ui.painter().rect_filled(
                        btn_rect,
                        Rounding::same(13.0),
                        tokens.palette.surface,
                    );
                    ui.painter().galley(
                        Pos2::new(btn_rect.center().x - btn.size().x / 2.0, btn_rect.center().y - btn.size().y / 2.0),
                        btn,
                        tokens.palette.text_primary,
                    );
                    // Check click against the small button rect.
                    let clicked = resp.clicked()
                        && ui.rect_contains_pointer(btn_rect);
                    if clicked {
                        action = Some(BubbleAction::React {
                            msg_id: msg.id.clone(),
                            emoji: emoji.to_string(),
                        });
                    }
                    mx -= 30.0;
                }
                // Reply button
                let rbtn = ui.painter().layout_no_wrap(
                    "↩".to_string(),
                    FontId::proportional(13.0),
                    tokens.palette.text_primary,
                );
                let rbtn_rect = egui::Rect::from_min_size(
                    Pos2::new(mx - 26.0, menu_y),
                    Vec2::new(26.0, 26.0),
                );
                ui.painter().rect_filled(
                    rbtn_rect,
                    Rounding::same(13.0),
                    tokens.palette.surface,
                );
                ui.painter().galley(
                    Pos2::new(rbtn_rect.center().x - rbtn.size().x / 2.0, rbtn_rect.center().y - rbtn.size().y / 2.0),
                    rbtn,
                    tokens.palette.text_primary,
                );
                if resp.clicked() && ui.rect_contains_pointer(rbtn_rect) {
                    action = Some(BubbleAction::Reply(msg.id.clone()));
                }
            }
        },
    );
    action
}

fn format_ts(ts: u64) -> String {
    let secs_in_day = ts % 86400;
    let h = secs_in_day / 3600;
    let m = (secs_in_day % 3600) / 60;
    format!("{h:02}:{m:02}")
}