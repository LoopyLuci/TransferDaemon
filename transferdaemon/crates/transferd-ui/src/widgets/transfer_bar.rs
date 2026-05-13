//! File transfer progress widget.

use crate::types::TransferStatus;
use egui::{Color32, ProgressBar, Ui};

pub fn transfer_bar(ui: &mut Ui, t: &TransferStatus) -> bool {
    let mut cancelled = false;

    egui::Frame::none()
        .fill(Color32::from_rgb(28, 28, 30))
        .rounding(8.0)
        .inner_margin(10.0)
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                let icon = if t.outbound { "⬆" } else { "⬇" };
                ui.label(egui::RichText::new(icon).size(18.0));
                ui.vertical(|ui| {
                    // File name + contact
                    ui.label(
                        egui::RichText::new(&t.file_name)
                            .strong()
                            .color(Color32::WHITE),
                    );
                    ui.label(
                        egui::RichText::new(format!(
                            "{} · {} lane{}",
                            t.contact_name,
                            t.lanes_active,
                            if t.lanes_active == 1 { "" } else { "s" }
                        ))
                        .size(12.0)
                        .color(Color32::from_gray(160)),
                    );

                    // Progress bar
                    let bar = ProgressBar::new(t.progress())
                        .text(format!("{:.0}%", t.progress() * 100.0))
                        .fill(Color32::from_rgb(0, 122, 255));
                    ui.add(bar);

                    // Throughput + ETA
                    let bps_str = format_bps(t.bps);
                    let eta_str = t.eta_secs()
                        .map(|s| format!("  ETA {}", format_duration(s)))
                        .unwrap_or_default();
                    ui.label(
                        egui::RichText::new(format!("{bps_str}{eta_str}"))
                            .size(12.0)
                            .color(Color32::from_gray(160)),
                    );
                });

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("✕").clicked() {
                        cancelled = true;
                    }
                });
            });
        });

    cancelled
}

fn format_bps(bps: u64) -> String {
    if bps >= 1_000_000_000 { format!("{:.1} Gbps", bps as f64 / 1e9) }
    else if bps >= 1_000_000 { format!("{:.1} Mbps", bps as f64 / 1e6) }
    else if bps >= 1_000     { format!("{:.0} Kbps", bps as f64 / 1e3) }
    else                     { format!("{bps} bps") }
}

fn format_duration(secs: u64) -> String {
    if secs >= 3600 { format!("{}h {}m", secs / 3600, (secs % 3600) / 60) }
    else if secs >= 60 { format!("{}m {}s", secs / 60, secs % 60) }
    else { format!("{secs}s") }
}
