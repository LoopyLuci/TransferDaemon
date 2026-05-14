mod app;
mod daemon;
mod events;
mod grpc_daemon;
mod types;
mod ui;

use app::App;
use crossterm::{
    cursor::MoveTo,
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use daemon::MockDaemon;
use grpc_daemon::GrpcDaemon;
use ratatui::{backend::CrosstermBackend, Terminal};
use std::{io, io::Write, sync::Arc, time::Duration};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = std::env::var("TRANSFERD_ADDR")
        .unwrap_or_else(|_| "http://127.0.0.1:50051".into());

    let (daemon, daemon_live): (Arc<dyn daemon::DaemonApi>, bool) =
        match GrpcDaemon::try_connect(&addr).await {
            Some(g) => (Arc::new(g), true),
            None    => (Arc::new(MockDaemon::new()), false),
        };

    let mut app = App::new(daemon, daemon_live).await;

    // ── Terminal setup ───────────────────────────────────────────────────────
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // ── Event reader thread ──────────────────────────────────────────────────
    let (ev_tx, mut ev_rx) = tokio::sync::mpsc::channel::<crossterm::event::Event>(64);
    tokio::task::spawn_blocking(move || {
        loop {
            if crossterm::event::poll(Duration::from_millis(50)).unwrap_or(false) {
                if let Ok(ev) = crossterm::event::read() {
                    if ev_tx.blocking_send(ev).is_err() { break; }
                }
            }
        }
    });

    // ── Main loop ────────────────────────────────────────────────────────────
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        // Draw the main ratatui UI.
        terminal.draw(|f| ui::render(f, &mut app))?;

        // After ratatui draws, handle any pending Kitty/Sixel direct writes.
        // These overwrite the placeholder cells ratatui left for the video area.
        if let Some(cs) = &mut app.call_state {
            if let Some(ref mut overlay) = cs.video {
                if let Some((rect, seq)) = overlay.take_direct_render() {
                    let mut out = io::stdout();
                    execute!(out, MoveTo(rect.x, rect.y))?;
                    out.write_all(seq.as_bytes())?;
                    out.flush()?;
                }
            }
        }

        tokio::select! {
            biased;
            Some(ev) = ev_rx.recv() => {
                if let crossterm::event::Event::Key(key) = ev {
                    if events::handle_key(&mut app, key).await {
                        break;
                    }
                }
            }
            _ = tick.tick() => {
                app.tick().await;
            }
        }
    }

    // ── Restore terminal ─────────────────────────────────────────────────────
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}
