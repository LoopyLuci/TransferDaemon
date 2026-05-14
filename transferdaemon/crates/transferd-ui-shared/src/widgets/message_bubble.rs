//! Chat message bubble widget.

use crate::types::{Message, MessageContent, MessageStatus};
use egui::{Color32, FontId, Pos2, Rounding, Ui, Vec2};

const BUBBLE_PADDING: Vec2 = Vec2::new(12.0, 8.0);
const BUBBLE_ROUNDING: f32 = 14.0;
// Minimum cap — prevents bubbles from being absurdly wide on large monitors.
const BUBBLE_ABS_MAX: f32 = 380.0;

/// Render a single message bubble.
///
/// `max_width` is typically `ui.available_width() * 0.75`.
pub fn message_bubble(ui: &mut Ui, msg: &Message, max_width: f32) {
    let outbound = msg.outbound;
    let bubble_color = if outbound {
        Color32::from_rgb(0, 122, 255)
    } else {
        Color32::from_rgb(44, 44, 46)
    };
    let text_color = Color32::WHITE;
    let capped = max_width.min(BUBBLE_ABS_MAX);

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
                MessageContent::File { name, size_bytes, transferred_bytes, .. } => {
                    let pct = if *size_bytes > 0 {
                        transferred_bytes * 100 / size_bytes
                    } else {
                        100
                    };
                    format!("📁 {} ({} MB, {}%)", name, size_bytes / 1_048_576, pct)
                }
            };

            let inner_w = capped - BUBBLE_PADDING.x * 2.0;

            let galley = ui.painter().layout(
                text,
                FontId::proportional(14.0),
                text_color,
                inner_w,
            );

            let status_label = if outbound { msg.status.label() } else { "" };
            let ts = format_ts(msg.timestamp_ts);
            let footer = format!("{ts}  {status_label}");
            let footer_galley = ui.painter().layout_no_wrap(
                footer,
                FontId::proportional(11.0),
                Color32::from_rgba_premultiplied(255, 255, 255, 140),
            );

            let bubble_w = galley.size().x
                .max(footer_galley.size().x)
                + BUBBLE_PADDING.x * 2.0;
            let bubble_h = galley.size().y
                + footer_galley.size().y
                + BUBBLE_PADDING.y * 2.0
                + 4.0;

            let (rect, _) = ui.allocate_exact_size(
                Vec2::new(bubble_w, bubble_h),
                egui::Sense::hover(),
            );

            // Background
            ui.painter().rect_filled(rect, Rounding::same(BUBBLE_ROUNDING), bubble_color);

            // Body text
            ui.painter().galley(rect.min + BUBBLE_PADDING, galley, text_color);

            // Footer (timestamp + status tick)
            let footer_pos = Pos2::new(
                rect.min.x + BUBBLE_PADDING.x,
                rect.max.y - BUBBLE_PADDING.y - footer_galley.size().y,
            );
            ui.painter().galley(footer_pos, footer_galley,
                Color32::from_rgba_premultiplied(255, 255, 255, 120));

            // Blue unread dot for inbound delivered messages
            if !outbound && msg.status == MessageStatus::Delivered {
                let dot = rect.right_top() + Vec2::new(-6.0, 6.0);
                ui.painter().circle_filled(dot, 5.0, Color32::from_rgb(0, 122, 255));
            }
        },
    );
}

fn format_ts(ts: u64) -> String {
    let secs_in_day = ts % 86400;
    let h = secs_in_day / 3600;
    let m = (secs_in_day % 3600) / 60;
    format!("{h:02}:{m:02}")
}
