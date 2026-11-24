mod app;
mod automation;
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
use ratatui::{
    backend::{Backend, CrosstermBackend, TestBackend},
    Terminal,
};
use serde_json::{json, Value};
use std::{io, io::Write, sync::Arc, time::Duration};

const USAGE: &str = "transferd-tui [--headless] [--size WxH]

  --headless     draw into memory instead of a terminal; driven through the daemon's control hub (tui.* operations)
  --size WxH     the headless screen size (default 120x40)

Environment: TRANSFERD_ADDR (the daemon's gRPC address), TRANSFERD_TUI_CONTROL=off (do not attach to the hub).";

/// Only the in-memory (headless) screen can be resized from here; a real terminal is resized by its window.
trait Resize {
    fn resize_to(&mut self, w: u16, h: u16) -> Result<(), String>;
}

impl Resize for TestBackend {
    fn resize_to(&mut self, w: u16, h: u16) -> Result<(), String> {
        self.resize(w, h);
        Ok(())
    }
}

impl<W: Write> Resize for CrosstermBackend<W> {
    fn resize_to(&mut self, _w: u16, _h: u16) -> Result<(), String> {
        Err("only a headless terminal UI can be resized from here".into())
    }
}

struct Options {
    headless: bool,
    size: (u16, u16),
}

fn options() -> Result<Options, String> {
    let mut o = Options { headless: false, size: (120, 40) };
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--headless" => o.headless = true,
            "--size" => {
                let v = args.next().ok_or("--size needs WxH")?;
                let (w, h) = v.split_once(['x', 'X']).ok_or("--size is WxH, e.g. 120x40")?;
                o.size = (w.parse().map_err(|_| "bad width")?, h.parse().map_err(|_| "bad height")?);
                if o.size.0 < 40 || o.size.1 < 12 {
                    return Err("the screen must be at least 40x12".into());
                }
            }
            "-h" | "--help" => return Err(USAGE.into()),
            other => return Err(format!("unknown argument {other}\n\n{USAGE}")),
        }
    }
    Ok(o)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opts = match options() {
        Ok(o) => o,
        Err(msg) => {
            eprintln!("{msg}");
            std::process::exit(if msg == USAGE { 0 } else { 2 });
        }
    };
    let addr = std::env::var("TRANSFERD_ADDR")
        .unwrap_or_else(|_| "http://127.0.0.1:50051".into());

    let (daemon, daemon_live, live_addr): (Arc<dyn daemon::DaemonApi>, bool, Option<String>) =
        match GrpcDaemon::try_connect(&addr).await {
            Some(g) => (Arc::new(g), true, Some(addr.clone())),
            None    => (Arc::new(MockDaemon::new()), false, None),
        };

    let mut app = App::new(daemon, daemon_live, live_addr).await;

    let control = !std::env::var("TRANSFERD_TUI_CONTROL").map(|v| v == "off" || v == "0").unwrap_or(false);
    let jobs = if control || opts.headless { Some(automation::start(opts.headless)) } else { None };

    if opts.headless {
        let mut terminal = Terminal::new(TestBackend::new(opts.size.0, opts.size.1))?;
        let result = run(&mut terminal, &mut app, None, jobs, true).await;
        transferd_control::client::detach("tui");
        return result;
    }

    // ── Terminal setup ───────────────────────────────────────────────────────
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // ── Event reader thread ──────────────────────────────────────────────────
    let (ev_tx, ev_rx) = tokio::sync::mpsc::channel::<crossterm::event::Event>(64);
    tokio::task::spawn_blocking(move || {
        loop {
            if crossterm::event::poll(Duration::from_millis(50)).unwrap_or(false) {
                if let Ok(ev) = crossterm::event::read() {
                    if ev_tx.blocking_send(ev).is_err() { break; }
                }
            }
        }
    });

    let result = run(&mut terminal, &mut app, Some(ev_rx), jobs, false).await;

    // ── Restore terminal ─────────────────────────────────────────────────────
    transferd_control::client::detach("tui");
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}

async fn next_or_pending<T>(rx: &mut Option<tokio::sync::mpsc::Receiver<T>>) -> Option<T> {
    match rx.as_mut() {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

/// The main loop: draw, then wait for a key, an automation command, or the tick. Returns when the user (or a
/// `tui.quit`) quits.
async fn run<B: Backend + Resize>(
    terminal: &mut Terminal<B>,
    app: &mut App,
    mut events: Option<tokio::sync::mpsc::Receiver<crossterm::event::Event>>,
    mut jobs: Option<tokio::sync::mpsc::Receiver<automation::Job>>,
    headless: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut screen = String::new();
    let (mut ticks, mut misses) = (0u64, 0u32);

    loop {
        // Draw the main ratatui UI, keeping a text copy of what was drawn for tui.screen.
        let size = terminal.size()?;
        terminal.draw(|f| {
            ui::render(f, app);
            screen = automation::buffer_text(f.buffer_mut());
        })?;

        // After ratatui draws, handle any pending Kitty/Sixel direct writes.
        // These overwrite the placeholder cells ratatui left for the video area.
        if !headless {
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
        }

        tokio::select! {
            biased;
            Some(ev) = next_or_pending(&mut events) => {
                if let crossterm::event::Event::Key(key) = ev {
                    // Only handle Press (and Repeat for held keys like arrows).
                    // Release events must be ignored: on Windows, crossterm emits
                    // both Press and Release for every keystroke. Processing Release
                    // causes the character that opened a modal (e.g. 'A') to also
                    // be typed into the modal's first field, and causes modal-close
                    // handlers (e.g. "any key closes QR") to fire immediately.
                    use crossterm::event::KeyEventKind;
                    if matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat)
                        && events::handle_key(app, key).await {
                        break;
                    }
                }
            }
            Some(job) = next_or_pending(&mut jobs) => {
                let (reply, quit) = handle_job(terminal, app, &job, &screen, (size.width, size.height), headless).await;
                let _ = job.reply.send(reply);
                if quit {
                    break;
                }
            }
            _ = tick.tick() => {
                app.tick().await;
                // A headless TUI exists to be driven through its daemon's hub: once that daemon has been gone for
                // two minutes, stop instead of lingering.
                if headless {
                    ticks += 1;
                    if ticks % 120 == 0 {
                        // every 30 s; four misses in a row (two minutes) and it stops
                        misses = if hub_alive() { 0 } else { misses + 1 };
                        if misses >= 4 {
                            break;
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// Whether the daemon this TUI attaches to still answers (a loopback health check on its control hub).
fn hub_alive() -> bool {
    transferd_control::Client::connect()
        .map(|c| c.with_timeout(Duration::from_secs(2)).health().is_ok())
        .unwrap_or(false)
}

fn redraw<B: Backend>(terminal: &mut Terminal<B>, app: &mut App) -> String {
    let mut s = String::new();
    let _ = terminal.draw(|f| {
        ui::render(f, app);
        s = automation::buffer_text(f.buffer_mut());
    });
    s
}

/// One automation command. Returns the reply and whether to quit.
async fn handle_job<B: Backend + Resize>(
    terminal: &mut Terminal<B>,
    app: &mut App,
    job: &automation::Job,
    screen: &str,
    size: (u16, u16),
    headless: bool,
) -> (Result<Value, String>, bool) {
    let args = &job.args;
    match job.action.as_str() {
        "state" => (Ok(automation::state(app, size, headless)), false),
        "screen" => (Ok(json!({"text": screen, "size": [size.0, size.1]})), false),
        "key" | "type" => {
            let evs = if job.action == "key" {
                automation::key_events(args.get("keys").and_then(Value::as_str).unwrap_or_default())
            } else {
                Ok(automation::text_events(args.get("text").and_then(Value::as_str).unwrap_or_default()))
            };
            match evs {
                Ok(evs) => {
                    for ev in evs {
                        if events::handle_key(app, ev).await {
                            return (Ok(json!({"quit": true})), true);
                        }
                    }
                    // Let background work the keys started (sends, loads) land before answering.
                    app.tick().await;
                    let text = redraw(terminal, app);
                    (Ok(json!({"state": automation::state(app, size, headless), "screen": text})), false)
                }
                Err(e) => (Err(e), false),
            }
        }
        "navigate" => {
            let to = args.get("to").and_then(Value::as_str).unwrap_or_default().to_lowercase();
            match automation::TABS.iter().find(|(n, _)| *n == to) {
                Some((_, tab)) => {
                    app.tab = *tab;
                    app.set_status("");
                    let text = redraw(terminal, app);
                    (Ok(json!({"tab": to, "screen": text})), false)
                }
                None => (Err(format!("no tab {to:?}; one of: {}", automation::TABS.iter().map(|(n, _)| *n).collect::<Vec<_>>().join(", "))), false),
            }
        }
        "resize" => {
            let w = args.get("width").and_then(Value::as_u64).unwrap_or(120).clamp(40, 500) as u16;
            let h = args.get("height").and_then(Value::as_u64).unwrap_or(40).clamp(12, 300) as u16;
            match terminal.backend_mut().resize_to(w, h).and_then(|_| terminal.autoresize().map_err(|e| e.to_string())) {
                Ok(()) => {
                    let text = redraw(terminal, app);
                    (Ok(json!({"size": [w, h], "screen": text})), false)
                }
                Err(e) => (Err(e), false),
            }
        }
        "quit" => (Ok(json!({"quit": true})), true),
        other => (Err(format!("unknown tui action {other:?}")), false),
    }
}
