//! File transfer progress widget.
//!
//! Redesigned with the new design system for a modern, accessible experience.

use crate::design::{self, DesignTokens};
use crate::types::TransferStatus;
use egui::{ProgressBar, Ui, Vec2};

/// Return value from transfer_bar indicating user action.
pub struct TransferAction {
    pub transfer_id: String,
    pub action: TransferActionKind,
}

#[derive(Clone, Copy, PartialEq)]
pub enum TransferActionKind {
    Cancel,
    Pause,
    Resume,
}

pub fn transfer_bar(ui: &mut Ui, t: &TransferStatus) -> Option<TransferAction> {
    let tokens = DesignTokens::current();
    let mut action: Option<TransferAction> = None;

    design::card_frame(&tokens).show(ui, |ui| {
        ui.horizontal(|ui| {
            let icon = if t.outbound { "⬆" } else { "⬇" };
            let icon_color = if t.outbound {
                tokens.palette.accent
            } else {
                tokens.palette.success
            };
            ui.label(egui::RichText::new(icon).size(18.0).color(icon_color));

            ui.vertical(|ui| {
                ui.label(
                    egui::RichText::new(&t.file_name)
                        .strong()
                        .color(tokens.palette.text_primary),
                );
                ui.label(
                    egui::RichText::new(format!(
                        "{} · {} lane{}",
                        t.contact_name,
                        t.lanes_active,
                        if t.lanes_active == 1 { "" } else { "s" }
                    ))
                    .size(12.0)
                    .color(tokens.palette.text_secondary),
                );

                let bar = ProgressBar::new(t.progress())
                    .text(format!("{:.0}%", t.progress() * 100.0))
                    .fill(tokens.palette.accent);
                ui.add(bar);

                let bps_str = format_bps(t.bps);
                let eta_str = t
                    .eta_secs()
                    .map(|s| format!("  ETA {}", format_duration(s)))
                    .unwrap_or_default();
                ui.label(
                    egui::RichText::new(format!("{bps_str}{eta_str}"))
                        .size(12.0)
                        .color(tokens.palette.text_disabled),
                );
            });

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                // Pause/Resume button
                let pause_label = if t.paused { "▶" } else { "⏸" };
                if ui
                    .add_sized(
                        Vec2::splat(28.0),
                        egui::Button::new(
                            egui::RichText::new(pause_label)
                                .color(tokens.palette.text_secondary)
                                .size(12.0),
                        )
                        .fill(tokens.palette.surface)
                        .rounding(14.0),
                    )
                    .clicked()
                {
                    let kind = if t.paused {
                        TransferActionKind::Resume
                    } else {
                        TransferActionKind::Pause
                    };
                    action = Some(TransferAction { transfer_id: t.id.clone(), action: kind });
                }

                ui.add_space(4.0);

                // Cancel button
                if ui
                    .add_sized(
                        Vec2::splat(28.0),
                        egui::Button::new(
                            egui::RichText::new("✕")
                                .color(tokens.palette.error)
                                .size(12.0),
                        )
                        .fill(tokens.palette.surface)
                        .rounding(14.0),
                    )
                    .clicked()
                {
                    action = Some(TransferAction { transfer_id: t.id.clone(), action: TransferActionKind::Cancel });
                }
            });
        });
    });

    action
}

fn format_bps(bps: u64) -> String {
    if bps >= 1_000_000_000 {
        format!("{:.1} Gbps", bps as f64 / 1e9)
    } else if bps >= 1_000_000 {
        format!("{:.1} Mbps", bps as f64 / 1e6)
    } else if bps >= 1_000 {
        format!("{:.0} Kbps", bps as f64 / 1e3)
    } else {
        format!("{bps} bps")
    }
}

fn format_duration(secs: u64) -> String {
    if secs >= 3600 {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    } else if secs >= 60 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{secs}s")
    }
}
