//! Driving the window from outside: the `gui.*` operations of the daemon's control hub.
//!
//! The window attaches to the hub (see `transferd_control::attach`) and answers commands forwarded to it. Everything
//! happens the way a person would do it, inside the normal frame loop:
//!
//! * **Seeing.** Every widget on screen is read from the AccessKit tree egui builds each frame (role, label, value,
//!   checked, enabled, bounds), so `inspect`, `find` and `wait` see exactly what is drawn.
//! * **Acting.** Clicks, typing, keys and scrolling are real input events injected before a frame
//!   (`raw_input_hook`): the pointer moves to the widget, presses and releases over a few frames, so hover, focus and
//!   click handling run as they do for a mouse.
//! * **Semantic shortcuts** (`navigate`, `open_chat`) set the page directly, for when a script needs to get somewhere
//!   without depending on layout.
//! * **Screenshots** use the viewport's own screenshot command.

use serde_json::{json, Value};
use std::collections::VecDeque;
use std::sync::mpsc;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use transferd_ui_shared::app::{Page, TransferDaemonApp};
use transferd_ui_shared::pages::home::Tab;

type Reply = mpsc::Sender<Result<Value, String>>;

struct Job {
    action: String,
    args: Value,
    reply: Reply,
}

/// A batch of input events to inject into one frame, and (on the last one) the job to answer after that frame.
struct Step {
    events: Vec<egui::Event>,
    done: Option<(Reply, Value)>,
}

#[derive(Clone, Debug)]
struct Widget {
    id: u64,
    role: String,
    label: String,
    value: String,
    enabled: bool,
    checked: Option<bool>,
    focused: bool,
    rect: Option<egui::Rect>,
}

impl Widget {
    fn json(&self) -> Value {
        let mut v = json!({"id": format!("{:x}", self.id), "role": self.role, "label": self.label});
        let a = alias(&self.label);
        if !a.is_empty() {
            v["means"] = json!(a);
        }
        if !self.value.is_empty() {
            v["value"] = json!(self.value);
        }
        if !self.enabled {
            v["enabled"] = json!(false);
        }
        if let Some(c) = self.checked {
            v["checked"] = json!(c);
        }
        if self.focused {
            v["focused"] = json!(true);
        }
        if let Some(r) = self.rect {
            v["rect"] = json!([r.min.x.round(), r.min.y.round(), r.width().round(), r.height().round()]);
        }
        v
    }

    fn text(&self) -> String {
        format!("{} {} {}", self.label, self.value, alias(&self.label)).to_lowercase()
    }
}

pub struct AutomatedApp {
    inner: TransferDaemonApp,
    jobs: mpsc::Receiver<Job>,
    steps: VecDeque<Step>,
    screenshots: Vec<(Reply, u32)>,
    waits: Vec<(Reply, String, bool, Instant)>,
    ctx_slot: Arc<OnceLock<egui::Context>>,
    accesskit_on: bool,
}

/// Start attaching to the hub; returns the app wrapped so it answers commands.
pub fn wrap(inner: TransferDaemonApp, ctx: &egui::Context) -> AutomatedApp {
    let (tx, rx) = mpsc::channel::<Job>();
    let ctx_slot: Arc<OnceLock<egui::Context>> = Arc::new(OnceLock::new());
    let _ = ctx_slot.set(ctx.clone());
    let slot = ctx_slot.clone();
    transferd_control::attach("gui", json!({"app": "transferd-ui", "version": env!("CARGO_PKG_VERSION")}), move |cmd| {
        let (rtx, rrx) = mpsc::channel();
        let timeout = cmd.args.get("timeout_s").and_then(Value::as_f64).unwrap_or(60.0).clamp(1.0, 600.0);
        tx.send(Job { action: cmd.action, args: cmd.args, reply: rtx }).map_err(|_| "the window is closing".to_string())?;
        if let Some(ctx) = slot.get() {
            ctx.request_repaint();
        }
        // The window may be minimized or hidden, when frames stop: keep nudging it while waiting.
        let deadline = Instant::now() + Duration::from_secs_f64(timeout);
        loop {
            match rrx.recv_timeout(Duration::from_millis(200)) {
                Ok(r) => return r,
                Err(mpsc::RecvTimeoutError::Timeout) if Instant::now() < deadline => {
                    if let Some(ctx) = slot.get() {
                        ctx.request_repaint();
                    }
                }
                Err(_) => return Err(format!("the window did not answer in {timeout}s")),
            }
        }
    });
    AutomatedApp { inner, jobs: rx, steps: VecDeque::new(), screenshots: vec![], waits: vec![], ctx_slot, accesskit_on: false }
}

fn page_name(p: Page) -> &'static str {
    match p {
        Page::Onboarding => "onboarding",
        Page::Home => "home",
        Page::Chat => "chat",
        Page::GroupChat => "group_chat",
    }
}

const TABS: &[(&str, Tab)] = &[
    ("chats", Tab::Chats),
    ("groups", Tab::Groups),
    ("contacts", Tab::Contacts),
    ("transfers", Tab::Transfers),
    ("settings", Tab::Settings),
    ("telemetry", Tab::Telemetry),
    ("connections", Tab::Connections),
];

fn tab_name(t: Tab) -> &'static str {
    TABS.iter().find(|(_, x)| *x == t).map(|(n, _)| *n).unwrap_or("chats")
}

fn key_of(name: &str) -> Option<egui::Key> {
    let alias = match name.to_lowercase().as_str() {
        "enter" | "return" => "Enter",
        "esc" | "escape" => "Escape",
        "tab" => "Tab",
        "space" => "Space",
        "backspace" => "Backspace",
        "delete" | "del" => "Delete",
        "up" | "arrowup" => "ArrowUp",
        "down" | "arrowdown" => "ArrowDown",
        "left" | "arrowleft" => "ArrowLeft",
        "right" | "arrowright" => "ArrowRight",
        "home" => "Home",
        "end" => "End",
        "pageup" => "PageUp",
        "pagedown" => "PageDown",
        "comma" | "," => "Comma",
        _ => "",
    };
    if !alias.is_empty() {
        return egui::Key::from_name(alias);
    }
    egui::Key::from_name(name).or_else(|| egui::Key::from_name(&name.to_uppercase()))
}

fn key_events(keys: &str) -> Result<Vec<Vec<egui::Event>>, String> {
    let mut frames = vec![];
    for (mods, key) in transferd_control::chords(keys) {
        let k = key_of(&key).ok_or_else(|| format!("unknown key {key:?}"))?;
        let mut m = egui::Modifiers::NONE;
        for x in &mods {
            match x.as_str() {
                "ctrl" | "control" => { m.ctrl = true; m.command = true; }
                "cmd" | "command" => { m.command = true; m.mac_cmd = cfg!(target_os = "macos"); }
                "shift" => m.shift = true,
                "alt" | "option" => m.alt = true,
                other => return Err(format!("unknown modifier {other:?}")),
            }
        }
        frames.push(vec![egui::Event::Key { key: k, physical_key: None, pressed: true, repeat: false, modifiers: m }]);
        frames.push(vec![egui::Event::Key { key: k, physical_key: None, pressed: false, repeat: false, modifiers: m }]);
    }
    Ok(frames)
}

/// What an icon-only button does, so `{text: "send"}` finds the ➤ button.
const ICONS: &[(&str, &str)] = &[
    ("\u{27a4}", "send"), ("\u{1f4ce}", "attach file"), ("\u{1f4de}", "voice call"), ("\u{1f4f9}", "video call"),
    ("\u{1f50d}", "search"), ("\u{1f512}", "lock"), ("\u{2699}", "settings"), ("\u{2190}", "back"), ("+", "add"),
    ("\u{2715}", "close"), ("\u{2716}", "close"), ("\u{1f4cb}", "copy"), ("\u{1f5d1}", "delete"), ("\u{270f}", "edit"),
    ("\u{1f4f7}", "camera"), ("\u{1f3a4}", "microphone"), ("\u{1f507}", "mute"), ("\u{2b50}", "favorite"), ("\u{22ee}", "more"),
    ("\u{2026}", "more"), ("\u{1f504}", "refresh"), ("\u{23f8}", "pause"), ("\u{25b6}", "resume"), ("\u{23f9}", "stop"),
];

fn alias(label: &str) -> &'static str {
    let t = label.trim().trim_end_matches('\u{fe0f}');
    ICONS.iter().find(|(icon, _)| t == *icon).map(|(_, a)| *a).unwrap_or("")
}

/// egui text fields carry no label of their own; give each unlabeled field the text a person reads as its label: the
/// placeholder if any, else the nearest text to its left on the same row, else the text just above it.
fn name_fields(ws: &mut [Widget]) {
    let texts: Vec<(String, egui::Rect)> = ws
        .iter()
        .filter(|w| w.role == "static_text" || w.role == "label")
        .filter_map(|w| w.rect.map(|r| (w.label.trim().trim_end_matches(':').trim().to_string(), r)))
        .filter(|(t, _)| !t.is_empty())
        .collect();
    for w in ws.iter_mut() {
        if !w.label.is_empty() || !(w.role.contains("text_input") || w.role.contains("combo") || w.role.contains("spin") || w.role == "slider") {
            continue;
        }
        let Some(r) = w.rect else { continue };
        let left = texts
            .iter()
            .filter(|(_, t)| t.max.x <= r.min.x + 4.0 && t.max.y > r.min.y - 8.0 && t.min.y < r.max.y)
            .min_by(|a, b| (r.min.x - a.1.max.x).total_cmp(&(r.min.x - b.1.max.x)));
        let above = texts
            .iter()
            .filter(|(_, t)| t.max.y <= r.min.y + 2.0 && r.min.y - t.max.y < 32.0 && t.min.x < r.max.x && t.max.x > r.min.x - 24.0)
            .min_by(|a, b| (r.min.y - a.1.max.y).total_cmp(&(r.min.y - b.1.max.y)));
        if let Some((t, _)) = left.or(above) {
            w.label = t.clone();
        }
    }
}

fn id_of(v: u64) -> egui::Id {
    // egui's Id has no public constructor from a raw value; its serde form is that value.
    serde_json::from_value(json!(v)).unwrap_or(egui::Id::NULL)
}

fn role_name(r: egui::accesskit::Role) -> String {
    let s = format!("{r:?}");
    let mut out = String::new();
    for (i, ch) in s.chars().enumerate() {
        if ch.is_uppercase() && i > 0 {
            out.push('_');
        }
        out.extend(ch.to_lowercase());
    }
    out
}

impl AutomatedApp {
    /// Every node in this frame's AccessKit tree (call after the app drew the frame).
    fn widgets(&self, ctx: &egui::Context) -> Vec<Widget> {
        let focused = ctx.memory(|m| m.focused()).map(|i| i.value());
        let mut out = vec![];
        let mut stack = vec![egui::accesskit_root_id().value()];
        let mut seen = std::collections::HashSet::new();
        while let Some(raw) = stack.pop() {
            if !seen.insert(raw) || out.len() > 5000 {
                continue;
            }
            let node = ctx.accesskit_node_builder(id_of(raw), |b| {
                let checked = b.checked().map(|c| matches!(c, egui::accesskit::Checked::True));
                let rect = b.bounds().map(|r| egui::Rect::from_min_max(egui::pos2(r.x0 as f32, r.y0 as f32), egui::pos2(r.x1 as f32, r.y1 as f32)));
                let value = b.value().map(str::to_string).or_else(|| b.numeric_value().map(|n| n.to_string())).unwrap_or_default();
                let label = b.name().or_else(|| b.placeholder()).unwrap_or_default().to_string();
                (role_name(b.role()), label, value, !b.is_disabled(), checked, rect,
                 b.children().iter().map(|c| c.0).collect::<Vec<_>>())
            });
            let Some((role, label, value, enabled, checked, rect, children)) = node else { break };
            for c in children.into_iter().rev() {
                stack.push(c);
            }
            if raw == egui::accesskit_root_id().value() {
                continue;
            }
            out.push(Widget { id: raw, role, label, value, enabled, checked, focused: focused == Some(raw), rect });
        }
        name_fields(&mut out);
        out
    }

    fn resolve(&self, ctx: &egui::Context, target: &Value) -> Result<Widget, String> {
        let ws = self.widgets(ctx);
        if let Some(id) = target.get("id").and_then(Value::as_str) {
            let raw = u64::from_str_radix(id.trim_start_matches("0x"), 16).map_err(|_| format!("bad widget id {id:?}"))?;
            return ws.into_iter().find(|w| w.id == raw).ok_or_else(|| format!("no widget {id} on screen now (gui.inspect lists them)"));
        }
        let text = target.get("text").and_then(Value::as_str).unwrap_or_default().trim().to_lowercase();
        let role = target.get("role").and_then(Value::as_str).map(str::to_lowercase);
        if text.is_empty() {
            // {role, index?}: the n-th widget of that role on screen (e.g. the chat's message box).
            let Some(role) = role else { return Err("target needs id, text or role".into()) };
            let n = target.get("index").and_then(Value::as_u64).unwrap_or(0) as usize;
            return ws.into_iter().filter(|w| w.rect.is_some() && w.role.contains(role.as_str())).nth(n)
                .ok_or_else(|| format!("no {role} #{n} on screen now"));
        }
        let fits = |w: &&Widget| role.as_ref().map(|r| w.role.contains(r.as_str())).unwrap_or(true) && w.rect.is_some();
        let exact: Vec<&Widget> = ws.iter().filter(fits)
            .filter(|w| w.label.trim().to_lowercase() == text || w.value.trim().to_lowercase() == text || alias(&w.label) == text)
            .collect();
        // Prefer something you can act on over a plain label with the same text.
        let pick = |c: Vec<&Widget>| -> Option<Widget> {
            c.iter().find(|w| w.role != "label" && w.enabled).or_else(|| c.first()).map(|w| (*w).clone())
        };
        if let Some(w) = pick(exact) {
            return Ok(w);
        }
        let contains: Vec<&Widget> = ws.iter().filter(fits).filter(|w| w.text().contains(&text)).collect();
        pick(contains).ok_or_else(|| format!("nothing on screen matches {text:?} (gui.inspect lists what is there)"))
    }

    fn state(&self, ctx: &egui::Context) -> Value {
        let s = &self.inner.state;
        let open_chat = s.open_chat.as_ref().map(|id| {
            let name = s.contacts.iter().find(|c| &c.id == id).map(|c| c.display_name().to_string()).unwrap_or_default();
            json!({"id": id, "name": name})
        });
        let open_group = s.open_group.as_ref().map(|id| {
            let name = s.groups.iter().find(|g| &g.id == id).map(|g| g.name.clone()).unwrap_or_default();
            json!({"id": id, "name": name})
        });
        let size = ctx.screen_rect();
        json!({
            "page": page_name(s.page),
            "tab": if s.page == Page::Home { json!(tab_name(self.inner.home.tab)) } else { Value::Null },
            "open_chat": open_chat,
            "open_group": open_group,
            "identity": s.identity.as_ref().map(|i| json!({"display_name": i.display_name, "public_key": i.public_key})),
            "contacts": s.contacts.len(),
            "online": s.contacts.iter().filter(|c| c.online).count(),
            "groups": s.groups.len(),
            "transfers": s.transfers.len(),
            "locked": s.locked,
            "daemon_live": s.daemon_is_live,
            "size": [size.width().round(), size.height().round()],
            "focused": self.widgets(ctx).into_iter().find(|w| w.focused).map(|w| w.json()),
        })
    }

    fn pointer_steps(&mut self, pos: egui::Pos2, double: bool, done: Option<(Reply, Value)>) {
        let m = egui::Modifiers::NONE;
        let press = |pressed| egui::Event::PointerButton { pos, button: egui::PointerButton::Primary, pressed, modifiers: m };
        self.steps.push_back(Step { events: vec![egui::Event::PointerMoved(pos)], done: None });
        self.steps.push_back(Step { events: vec![press(true)], done: None });
        self.steps.push_back(Step { events: vec![press(false)], done: None });
        if double {
            self.steps.push_back(Step { events: vec![press(true)], done: None });
            self.steps.push_back(Step { events: vec![press(false)], done: None });
        }
        self.steps.push_back(Step { events: vec![], done });
    }

    /// Commands that need this frame's widgets (after the app drew it).
    fn after_frame(&mut self, ctx: &egui::Context, job: Job) {
        let args = &job.args;
        let r: Result<Value, String> = match job.action.as_str() {
            "inspect" | "find" => {
                let q = args.get("query").and_then(Value::as_str).unwrap_or_default().to_lowercase();
                let max = args.get("max").and_then(Value::as_u64).unwrap_or(400) as usize;
                let ws: Vec<Value> = self
                    .widgets(ctx)
                    .into_iter()
                    .filter(|w| w.rect.is_some() && (!w.label.is_empty() || !w.value.is_empty() || w.role != "unknown"))
                    .filter(|w| q.is_empty() || w.text().contains(&q))
                    .take(max)
                    .map(|w| w.json())
                    .collect();
                Ok(json!({"page": page_name(self.inner.state.page), "widgets": ws}))
            }
            "click" => match self.resolve(ctx, args.get("target").unwrap_or(&Value::Null)) {
                Ok(w) if !w.enabled => Err(format!("{:?} is disabled", w.label)),
                Ok(w) => match w.rect {
                    Some(r) if ctx.screen_rect().contains(r.center()) => {
                        let double = args.get("double").and_then(Value::as_bool).unwrap_or(false);
                        self.pointer_steps(r.center(), double, Some((job.reply, json!({"clicked": w.json()}))));
                        return;
                    }
                    _ => Err(format!("{:?} is not visible (scroll to it first)", w.label)),
                },
                Err(e) => Err(e),
            },
            "set" => match self.resolve(ctx, &{
                // A value goes into something editable: prefer text fields unless the caller named a role.
                let mut t = args.get("target").cloned().unwrap_or(Value::Null);
                if t.is_object() && t.get("role").is_none() && t.get("id").is_none() {
                    t["role"] = json!("text_input");
                }
                t
            }) {
                Ok(w) => match w.rect {
                    Some(r) if ctx.screen_rect().contains(r.center()) => {
                        let value = args.get("value").and_then(Value::as_str).unwrap_or_default().to_string();
                        let submit = args.get("submit").and_then(Value::as_bool).unwrap_or(false);
                        self.pointer_steps(r.center(), false, None);
                        self.steps.pop_back(); // no answer yet: typing follows
                        let select_all = egui::Modifiers::COMMAND;
                        for pressed in [true, false] {
                            self.steps.push_back(Step { events: vec![egui::Event::Key { key: egui::Key::A, physical_key: None, pressed, repeat: false, modifiers: select_all }], done: None });
                        }
                        self.steps.push_back(Step { events: vec![egui::Event::Key { key: egui::Key::Delete, physical_key: None, pressed: true, repeat: false, modifiers: egui::Modifiers::NONE }], done: None });
                        self.steps.push_back(Step { events: vec![egui::Event::Text(value.clone())], done: None });
                        if submit {
                            if let Ok(frames) = key_events("Enter") {
                                for f in frames {
                                    self.steps.push_back(Step { events: f, done: None });
                                }
                            }
                        }
                        self.steps.push_back(Step { events: vec![], done: Some((job.reply, json!({"set": w.json(), "value": value}))) });
                        return;
                    }
                    _ => Err(format!("{:?} is not visible", w.label)),
                },
                Err(e) => Err(e),
            },
            "scroll" => {
                let dy = args.get("dy").and_then(Value::as_f64).unwrap_or(200.0) as f32;
                let pos = match args.get("target") {
                    Some(t) if !t.is_null() => match self.resolve(ctx, t) {
                        Ok(w) => w.rect.map(|r| r.center()).unwrap_or(ctx.screen_rect().center()),
                        Err(e) => {
                            let _ = job.reply.send(Err(e));
                            return;
                        }
                    },
                    _ => ctx.screen_rect().center(),
                };
                self.steps.push_back(Step { events: vec![egui::Event::PointerMoved(pos)], done: None });
                self.steps.push_back(Step {
                    events: vec![egui::Event::MouseWheel { unit: egui::MouseWheelUnit::Point, delta: egui::vec2(0.0, -dy), modifiers: egui::Modifiers::NONE }],
                    done: None,
                });
                self.steps.push_back(Step { events: vec![], done: Some((job.reply, json!({"scrolled": dy}))) });
                return;
            }
            "wait" => {
                let text = args.get("text").and_then(Value::as_str).unwrap_or_default().to_lowercase();
                let gone = args.get("gone").and_then(Value::as_bool).unwrap_or(false);
                let t = args.get("timeout_s").and_then(Value::as_f64).unwrap_or(30.0).clamp(0.5, 600.0);
                self.waits.push((job.reply, text, gone, Instant::now() + Duration::from_secs_f64(t)));
                return;
            }
            "state" => Ok(self.state(ctx)),
            other => Err(format!("unknown gui action {other:?}")),
        };
        let _ = job.reply.send(r);
    }

    /// Commands that act before the app draws.
    fn before_frame(&mut self, ctx: &egui::Context, job: Job) -> Option<Job> {
        let args = &job.args;
        let r: Result<Value, String> = match job.action.as_str() {
            "pages" => Ok(json!({"pages": ["onboarding", "home", "chat", "group_chat"],
                                 "tabs": TABS.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
                                 "shortcuts": {"ctrl+N": "contacts", "ctrl+comma": "settings", "ctrl+Tab": "next tab", "Escape": "leave a chat"}})),
            "navigate" => {
                let to = args.get("to").and_then(Value::as_str).unwrap_or_default().to_lowercase();
                if let Some((_, tab)) = TABS.iter().find(|(n, _)| *n == to) {
                    self.inner.state.page = Page::Home;
                    self.inner.home.tab = *tab;
                    Ok(json!({"page": "home", "tab": to}))
                } else if to == "home" {
                    self.inner.state.page = Page::Home;
                    Ok(json!({"page": "home"}))
                } else if to == "onboarding" {
                    self.inner.state.page = Page::Onboarding;
                    Ok(json!({"page": "onboarding"}))
                } else {
                    Err(format!("no page {to:?}; one of: home, onboarding, {}", TABS.iter().map(|(n, _)| *n).collect::<Vec<_>>().join(", ")))
                }
            }
            "open_chat" => {
                let s = &mut self.inner.state;
                if let Some(g) = args.get("group").and_then(Value::as_str) {
                    let gl = g.to_lowercase();
                    match s.groups.iter().find(|x| x.id == g || x.name.to_lowercase() == gl).map(|x| (x.id.clone(), x.name.clone())) {
                        Some((id, name)) => {
                            s.open_group = Some(id.clone());
                            s.page = Page::GroupChat;
                            Ok(json!({"group": id, "name": name}))
                        }
                        None => Err(format!("no group {g:?}")),
                    }
                } else {
                    let c = args.get("contact").and_then(Value::as_str).unwrap_or_default();
                    let cl = c.to_lowercase();
                    let hit = s.contacts.iter().find(|x| x.id == c || x.display_name().to_lowercase() == cl)
                        .or_else(|| s.contacts.iter().find(|x| x.display_name().to_lowercase().contains(&cl) || x.id.starts_with(c)))
                        .map(|x| (x.id.clone(), x.display_name().to_string()));
                    match hit {
                        Some((id, name)) if !c.is_empty() => {
                            s.open_chat = Some(id.clone());
                            s.page = Page::Chat;
                            Ok(json!({"contact": id, "name": name}))
                        }
                        _ => Err(format!("no contact {c:?}")),
                    }
                }
            }
            "type" => {
                let text = args.get("text").and_then(Value::as_str).unwrap_or_default().to_string();
                self.steps.push_back(Step { events: vec![egui::Event::Text(text.clone())], done: None });
                self.steps.push_back(Step { events: vec![], done: Some((job.reply, json!({"typed": text}))) });
                return None;
            }
            "key" => match key_events(args.get("keys").and_then(Value::as_str).unwrap_or_default()) {
                Ok(frames) => {
                    for f in frames {
                        self.steps.push_back(Step { events: f, done: None });
                    }
                    self.steps.push_back(Step { events: vec![], done: Some((job.reply, json!({"pressed": args["keys"]}))) });
                    return None;
                }
                Err(e) => Err(e),
            },
            "screenshot" => {
                let max = args.get("max_width").and_then(Value::as_u64).unwrap_or(0) as u32;
                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot);
                self.screenshots.push((job.reply, max));
                return None;
            }
            "window" => {
                let action = args.get("action").and_then(Value::as_str).unwrap_or_default();
                let cmd = match action {
                    "show" => vec![egui::ViewportCommand::Visible(true), egui::ViewportCommand::Minimized(false)],
                    "focus" | "raise" => vec![egui::ViewportCommand::Visible(true), egui::ViewportCommand::Minimized(false), egui::ViewportCommand::Focus],
                    "minimize" => vec![egui::ViewportCommand::Minimized(true)],
                    "maximize" => vec![egui::ViewportCommand::Maximized(true)],
                    "restore" => vec![egui::ViewportCommand::Minimized(false), egui::ViewportCommand::Maximized(false)],
                    "resize" => {
                        let w = args.get("width").and_then(Value::as_f64).unwrap_or(420.0) as f32;
                        let h = args.get("height").and_then(Value::as_f64).unwrap_or(740.0) as f32;
                        vec![egui::ViewportCommand::InnerSize(egui::vec2(w.max(300.0), h.max(400.0)))]
                    }
                    "close" => vec![egui::ViewportCommand::Close],
                    other => {
                        let _ = job.reply.send(Err(format!("unknown window action {other:?}")));
                        return None;
                    }
                };
                for c in cmd {
                    ctx.send_viewport_cmd(c);
                }
                Ok(json!({"window": action}))
            }
            _ => return Some(job),
        };
        let _ = job.reply.send(r);
        None
    }
}

fn png(image: &egui::ColorImage, max_width: u32) -> Result<Value, String> {
    use image::ImageEncoder as _;
    let [w, h] = image.size;
    let mut rgba = Vec::with_capacity(w * h * 4);
    for p in &image.pixels {
        rgba.extend_from_slice(&p.to_srgba_unmultiplied());
    }
    let mut img = image::RgbaImage::from_raw(w as u32, h as u32, rgba).ok_or("bad screenshot")?;
    if max_width > 0 && img.width() > max_width {
        let nh = (img.height() as f64 * max_width as f64 / img.width() as f64).round() as u32;
        img = image::imageops::resize(&img, max_width, nh.max(1), image::imageops::FilterType::Triangle);
    }
    let mut out = Vec::new();
    image::codecs::png::PngEncoder::new(&mut out)
        .write_image(img.as_raw(), img.width(), img.height(), image::ExtendedColorType::Rgba8)
        .map_err(|e| e.to_string())?;
    use base64::Engine as _;
    Ok(json!({"format": "png", "width": img.width(), "height": img.height(), "base64": base64::engine::general_purpose::STANDARD.encode(out)}))
}

impl eframe::App for AutomatedApp {
    fn raw_input_hook(&mut self, ctx: &egui::Context, raw: &mut egui::RawInput) {
        // Screenshots come back as an input event.
        if !self.screenshots.is_empty() {
            for ev in &raw.events {
                if let egui::Event::Screenshot { image, .. } = ev {
                    for (reply, max) in self.screenshots.drain(..) {
                        let _ = reply.send(png(image, max));
                    }
                    break;
                }
            }
        }
        if let Some(step) = self.steps.front_mut() {
            raw.events.append(&mut step.events);
            ctx.request_repaint();
        }
        eframe::App::raw_input_hook(&mut self.inner, ctx, raw);
    }

    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        if !self.accesskit_on {
            ctx.enable_accesskit();
            self.accesskit_on = true;
        }
        let _ = &self.ctx_slot;
        let mut later = vec![];
        while let Ok(job) = self.jobs.try_recv() {
            if let Some(job) = self.before_frame(ctx, job) {
                later.push(job);
            }
        }
        eframe::App::update(&mut self.inner, ctx, frame);
        for job in later {
            self.after_frame(ctx, job);
        }
        // Finish the input step injected for this frame.
        if let Some(step) = self.steps.pop_front() {
            if let Some((reply, v)) = step.done {
                let _ = reply.send(Ok(v));
            }
            ctx.request_repaint();
        }
        if !self.waits.is_empty() {
            let ws = self.widgets(ctx);
            let now = Instant::now();
            let mut keep = vec![];
            for (reply, text, gone, deadline) in self.waits.drain(..) {
                let present = ws.iter().any(|w| w.rect.is_some() && w.text().contains(&text));
                if present != gone {
                    let _ = reply.send(Ok(json!({"text": text, "present": present})));
                } else if now > deadline {
                    let _ = reply.send(Err(format!("{text:?} still {} after the timeout", if gone { "there" } else { "not there" })));
                } else {
                    keep.push((reply, text, gone, deadline));
                }
            }
            self.waits = keep;
            if !self.waits.is_empty() {
                ctx.request_repaint_after(Duration::from_millis(100));
            }
        }
    }

    fn on_exit(&mut self, gl: Option<&eframe::glow::Context>) {
        transferd_control::client::detach("gui");
        eframe::App::on_exit(&mut self.inner, gl);
    }
}
