use std::sync::mpsc;

use transferd_ui_shared::tray_channel::{TrayCommand, TrayUpdate};
use tray_icon::{
    menu::{Menu, MenuEvent, MenuItemBuilder, PredefinedMenuItem},
    Icon, TrayIconBuilder, TrayIconEvent,
};

/// Start the system tray on a background thread.
///
/// Returns a sender for updating the tray and a receiver for tray events.
pub fn start_tray() -> (mpsc::Sender<TrayUpdate>, mpsc::Receiver<TrayCommand>) {
    let (tx_cmd, rx_cmd) = mpsc::channel::<TrayCommand>();
    let (tx_update, rx_update) = mpsc::channel::<TrayUpdate>();

    std::thread::spawn(move || {
        let icon = create_tray_icon();

        let show_item = MenuItemBuilder::new()
            .text("Show TransferDaemon")
            .id("show".into())
            .build();
        let separator = PredefinedMenuItem::separator();
        let quit_item = MenuItemBuilder::new()
            .text("Quit")
            .id("quit".into())
            .build();

        let menu = Menu::new();
        menu.append_items(&[&show_item, &separator, &quit_item])
            .expect("tray menu");

        let _tray = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_icon(icon)
            .with_tooltip("TransferDaemon")
            .build()
            .expect("tray icon");

        let event_rx = TrayIconEvent::receiver();
        let menu_rx = MenuEvent::receiver();

        loop {
            while let Ok(update) = rx_update.try_recv() {
                match update {
                    TrayUpdate::SetBadge(count) => {
                        let tip = match count {
                            Some(n) if n > 0 => format!("TransferDaemon — {n} new"),
                            _ => "TransferDaemon".into(),
                        };
                        tracing::info!("[Tray] Badge: {tip}");
                    }
                    TrayUpdate::SetTooltip(tip) => {
                        tracing::info!("[Tray] Tooltip: {tip}");
                    }
                }
            }

            while let Ok(event) = event_rx.try_recv() {
                if matches!(event, TrayIconEvent::DoubleClick { .. }) {
                    let _ = tx_cmd.send(TrayCommand::ShowWindow);
                }
            }

            while let Ok(me) = menu_rx.try_recv() {
                let id: &str = me.id().as_ref();
                match id {
                    "quit" => { let _ = tx_cmd.send(TrayCommand::Quit); }
                    "show" => { let _ = tx_cmd.send(TrayCommand::ShowWindow); }
                    _ => {}
                }
            }

            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    });

    (tx_update, rx_cmd)
}

fn create_tray_icon() -> Icon {
    let w = 64u32;
    let h = 64u32;
    let mut rgba = Vec::with_capacity((w * h * 4) as usize);
    let center = 32.0_f64;
    let r = 30.0_f64;

    for y in 0..h {
        for x in 0..w {
            let dist = ((x as f64 - center).powi(2) + (y as f64 - center).powi(2)).sqrt();
            if dist > r {
                rgba.extend_from_slice(&[0, 0, 0, 0]);
                continue;
            }
            rgba.extend_from_slice(&[30, 35, 45, 255]);
        }
    }

    // White "T"
    let t_x = 22u32;
    let t_y = 18u32;
    for py in t_y..t_y + 6 {
        for px in t_x..t_x + 20 {
            let i = ((py * w + px) * 4) as usize;
            if i + 3 < rgba.len() {
                rgba[i..i + 4].copy_from_slice(&[220, 225, 230, 255]);
            }
        }
    }
    let stem_x = t_x + (20 - 6) / 2;
    for py in t_y + 6..t_y + 6 + 22 {
        for px in stem_x..stem_x + 6 {
            let i = ((py * w + px) * 4) as usize;
            if i + 3 < rgba.len() {
                rgba[i..i + 4].copy_from_slice(&[220, 225, 230, 255]);
            }
        }
    }

    Icon::from_rgba(rgba, w, h).expect("tray icon")
}
