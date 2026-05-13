//! Chat message bubble widget.

use crate::types::{Message, MessageContent, MessageStatus};
use egui::{Color32, FontId, Pos2, Rounding, Ui, Vec2};

const BUBBLE_MAX_WIDTH: f32 = 320.0;
const BUBBLE_PADDING: Vec2 = Vec2::new(12.0, 8.0);
const BUBBLE_ROUNDING: f32 = 12.0;

pub fn message_bubble(ui: &mut Ui, msg: &Message) {
    let outbound = msg.outbound;
    let bubble_color = if outbound {
        Color32::from_rgb(0, 122, 255) // iOS blue for outbound
    } else {
        Color32::from_rgb(58, 58, 60)  // dark grey for inbound
    };
    let text_color = Color32::WHITE;

    ui.with_layout(
        if outbound {
            egui::Layout::right_to_left(egui::Align::TOP)
        } else {
            egui::Layout::left_to_right(egui::Align::TOP)
        },
        |ui| {
            ui.set_max_width(BUBBLE_MAX_WIDTH);

            let text = match &msg.content {
                MessageContent::Text(t) => t.clone(),
                MessageContent::File { name, size_bytes, transferred_bytes, .. } => {
                    let pct = if *size_bytes > 0 {
                        transferred_bytes * 100 / size_bytes
                    } else { 100 };
                    format!("📁 {} ({} MB, {}%)", name, size_bytes / 1_048_576, pct)
                }
            };

            let galley = ui.painter().layout(
                text.clone(),
                FontId::proportional(14.0),
                text_color,
                BUBBLE_MAX_WIDTH - BUBBLE_PADDING.x * 2.0,
            );

            // Status + timestamp footer
            let status_label = if outbound { msg.status.label() } else { "" };
            let ts = format_ts(msg.timestamp_ts);
            let footer = format!("{ts}  {status_label}");
            let footer_galley = ui.painter().layout_no_wrap(
                footer,
                FontId::proportional(11.0),
                Color32::from_rgba_premultiplied(255, 255, 255, 160),
            );

            let content_size = Vec2::new(
                galley.size().x.max(footer_galley.size().x) + BUBBLE_PADDING.x * 2.0,
                galley.size().y + footer_galley.size().y + BUBBLE_PADDING.y * 2.0 + 4.0,
            );

            let (rect, _) = ui.allocate_exact_size(content_size, egui::Sense::hover());

            // Background bubble
            ui.painter().rect_filled(rect, Rounding::same(BUBBLE_ROUNDING), bubble_color);

            // Text
            let text_pos = rect.min + BUBBLE_PADDING;
            ui.painter().galley(text_pos, galley, text_color);

            // Footer (timestamp + status)
            let footer_pos = Pos2::new(
                rect.min.x + BUBBLE_PADDING.x,
                rect.max.y - BUBBLE_PADDING.y - footer_galley.size().y,
            );
            ui.painter().galley(footer_pos, footer_galley,
                Color32::from_rgba_premultiplied(255, 255, 255, 140));

            // Unread indicator for inbound delivered messages
            if !outbound && msg.status == MessageStatus::Delivered {
                let dot_pos = rect.right_top() + Vec2::new(-6.0, 6.0);
                ui.painter().circle_filled(dot_pos, 5.0, Color32::from_rgb(0, 122, 255));
            }
        },
    );
}

fn format_ts(ts: u64) -> String {
    // Simple HH:MM formatting; real implementation would use `chrono`.
    let secs_in_day = ts % 86400;
    let h = secs_in_day / 3600;
    let m = (secs_in_day % 3600) / 60;
    format!("{h:02}:{m:02}")
}
