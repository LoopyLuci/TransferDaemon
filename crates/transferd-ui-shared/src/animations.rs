//! Animation utilities — transitions, transitions, and visual effects.

use egui::{Color32, Rect, Vec2, pos2};
use std::time::{Duration, Instant};

/// A smooth transition between two values.
pub struct Transition {
    from: f32,
    to: f32,
    current: f32,
    start_time: Instant,
    duration: Duration,
    easing: EasingFn,
}

type EasingFn = fn(f32) -> f32;

impl Transition {
    pub fn new(from: f32, to: f32, duration: Duration, easing: EasingFn) -> Self {
        Self {
            from,
            to,
            current: from,
            start_time: Instant::now(),
            duration,
            easing,
        }
    }

    pub fn ease_out(duration: Duration) -> impl Fn(f32, f32) -> Self {
        move |from, to| Transition::new(from, to, duration, ease_out_cubic)
    }

    pub fn spring(duration: Duration) -> impl Fn(f32, f32) -> Self {
        move |from, to| Transition::new(from, to, duration, ease_spring)
    }

    pub fn update(&mut self) -> f32 {
        let elapsed = self.start_time.elapsed().as_secs_f32();
        let t = (elapsed / self.duration.as_secs_f32()).min(1.0);
        let eased = (self.easing)(t);
        self.current = self.from + (self.to - self.from) * eased;
        self.current
    }

    pub fn value(&self) -> f32 {
        self.current
    }

    pub fn is_done(&self) -> bool {
        self.start_time.elapsed() >= self.duration
    }

    pub fn reset(&mut self, new_to: Option<f32>) {
        self.from = self.current;
        if let Some(to) = new_to {
            self.to = to;
        }
        self.start_time = Instant::now();
    }
}

pub fn ease_out_cubic(t: f32) -> f32 {
    1.0 - (1.0 - t).powi(3)
}

pub fn ease_in_cubic(t: f32) -> f32 {
    t * t * t
}

pub fn ease_in_out_cubic(t: f32) -> f32 {
    if t < 0.5 {
        4.0 * t * t * t
    } else {
        1.0 - (-2.0 * t + 2.0).powi(3) / 2.0
    }
}

pub fn ease_spring(t: f32) -> f32 {
    let c4 = (2.0 * std::f32::consts::PI) / 3.0;
    if t < 0.5 {
        (2.0_f32.powf(20.0 * t - 10.0) * ((20.0 * t - 11.125) * c4).sin()) / 2.0
    } else {
        (2.0_f32.powf(-20.0 * t + 10.0) * ((20.0 * t - 11.125) * c4).sin()) / -2.0 + 1.0
    }
}

pub fn ease_bounce(t: f32) -> f32 {
    const N1: f32 = 7.5625;
    const D1: f32 = 2.75;
    if t < 1.0 / D1 {
        N1 * t * t
    } else if t < 2.0 / D1 {
        let t = t - 1.5 / D1;
        N1 * t * t + 0.75
    } else if t < 2.5 / D1 {
        let t = t - 2.25 / D1;
        N1 * t * t + 0.9375
    } else {
        let t = t - 2.625 / D1;
        N1 * t * t + 0.984375
    }
}

// ---------------------------------------------------------------------------
// Fade effect
// ---------------------------------------------------------------------------

/// A fade-in/out effect.
#[derive(Default)]
pub struct Fade {
    opacity: f32,
    target: f32,
    speed: f32,
}

impl Fade {
    pub fn new(visible: bool) -> Self {
        Self {
            opacity: if visible { 1.0 } else { 0.0 },
            target: if visible { 1.0 } else { 0.0 },
            speed: 4.0,
        }
    }

    pub fn show(&mut self) {
        self.target = 1.0;
    }

    pub fn hide(&mut self) {
        self.target = 0.0;
    }

    pub fn toggle(&mut self) {
        if self.target > 0.5 {
            self.hide();
        } else {
            self.show();
        }
    }

    pub fn update(&mut self, dt: f32) {
        let diff = self.target - self.opacity;
        self.opacity += diff * (dt * self.speed).min(1.0);
        if diff.abs() < 0.01 {
            self.opacity = self.target;
        }
    }

    pub fn opacity(&self) -> f32 {
        self.opacity
    }

    pub fn is_visible(&self) -> bool {
        self.opacity > 0.01
    }

    /// Apply opacity to a color.
    pub fn apply_color(&self, color: Color32) -> Color32 {
        let a = (color.a() as f32 * self.opacity) as u8;
        Color32::from_rgba_premultiplied(color.r(), color.g(), color.b(), a)
    }
}

// ---------------------------------------------------------------------------
// Slide effect
// ---------------------------------------------------------------------------

/// A slide-in/out effect from a direction.
pub struct Slide {
    offset: f32,
    target_offset: f32,
    axis: SlideAxis,
    speed: f32,
}

#[derive(Clone, Copy)]
pub enum SlideAxis {
    Horizontal,
    Vertical,
}

impl Slide {
    pub fn from_left() -> Self {
        Self::new(SlideAxis::Horizontal, -1.0)
    }

    pub fn from_right() -> Self {
        Self::new(SlideAxis::Horizontal, 1.0)
    }

    pub fn from_top() -> Self {
        Self::new(SlideAxis::Vertical, -1.0)
    }

    pub fn from_bottom() -> Self {
        Self::new(SlideAxis::Vertical, 1.0)
    }

    fn new(axis: SlideAxis, initial: f32) -> Self {
        Self {
            offset: initial,
            target_offset: 0.0,
            axis,
            speed: 5.0,
        }
    }

    pub fn show(&mut self) {
        self.target_offset = 0.0;
    }

    pub fn hide(&mut self) {
        match self.axis {
            SlideAxis::Horizontal => self.target_offset = -1.0,
            SlideAxis::Vertical => self.target_offset = -1.0,
        }
    }

    pub fn update(&mut self, dt: f32) {
        let diff = self.target_offset - self.offset;
        self.offset += diff * (dt * self.speed).min(1.0);
        if diff.abs() < 0.01 {
            self.offset = self.target_offset;
        }
    }

    /// Get the offset as a Vec2.
    pub fn offset_vec(&self, max_distance: f32) -> Vec2 {
        match self.axis {
            SlideAxis::Horizontal => Vec2::new(self.offset * max_distance, 0.0),
            SlideAxis::Vertical => Vec2::new(0.0, self.offset * max_distance),
        }
    }

    pub fn is_done(&self) -> bool {
        (self.offset - self.target_offset).abs() < 0.01
    }
}

// ---------------------------------------------------------------------------
// Pulse effect
// ---------------------------------------------------------------------------

/// A pulsing glow effect for attention.
pub struct Pulse {
    phase: f32,
    speed: f32,
    min_intensity: f32,
    max_intensity: f32,
}

impl Pulse {
    pub fn new() -> Self {
        Self {
            phase: 0.0,
            speed: 2.0,
            min_intensity: 0.3,
            max_intensity: 1.0,
        }
    }

    pub fn subtle() -> Self {
        Self {
            phase: 0.0,
            speed: 1.5,
            min_intensity: 0.7,
            max_intensity: 1.0,
        }
    }

    pub fn update(&mut self, dt: f32) {
        self.phase += dt * self.speed;
        if self.phase > std::f32::consts::TAU {
            self.phase -= std::f32::consts::TAU;
        }
    }

    pub fn intensity(&self) -> f32 {
        let t = (self.phase.sin() + 1.0) / 2.0;
        self.min_intensity + (self.max_intensity - self.min_intensity) * t
    }

    pub fn color(&self, base: Color32) -> Color32 {
        let i = self.intensity();
        Color32::from_rgba_premultiplied(
            (base.r() as f32 * i) as u8,
            (base.g() as f32 * i) as u8,
            (base.b() as f32 * i) as u8,
            base.a(),
        )
    }
}

impl Default for Pulse {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Toast notifications
// ---------------------------------------------------------------------------

/// A toast notification that slides in and fades out.
pub struct Toast {
    pub message: String,
    pub kind: ToastKind,
    created_at: Instant,
    duration: Duration,
    fade: Fade,
    slide: Slide,
}

#[derive(Clone, Copy, PartialEq)]
pub enum ToastKind {
    Info,
    Success,
    Warning,
    Error,
}

impl Toast {
    pub fn new(message: impl Into<String>, kind: ToastKind) -> Self {
        Self {
            message: message.into(),
            kind,
            created_at: Instant::now(),
            duration: Duration::from_secs(3),
            fade: Fade::new(true),
            slide: Slide::from_bottom(),
        }
    }

    pub fn with_duration(mut self, duration: Duration) -> Self {
        self.duration = duration;
        self
    }

    pub fn update(&mut self, dt: f32) {
        self.slide.update(dt);
        self.fade.update(dt);

        if self.created_at.elapsed() > self.duration {
            self.fade.hide();
        }
    }

    pub fn is_done(&self) -> bool {
        self.fade.opacity() < 0.01 && self.created_at.elapsed() > self.duration
    }

    pub fn opacity(&self) -> f32 {
        self.fade.opacity()
    }

    pub fn offset(&self, max_distance: f32) -> Vec2 {
        self.slide.offset_vec(max_distance)
    }
}

/// Toast manager — manages a stack of toast notifications.
pub struct ToastManager {
    toasts: Vec<Toast>,
    max_visible: usize,
}

impl ToastManager {
    pub fn new() -> Self {
        Self {
            toasts: Vec::new(),
            max_visible: 3,
        }
    }

    pub fn push(&mut self, toast: Toast) {
        self.toasts.push(toast);
    }

    pub fn info(&mut self, message: impl Into<String>) {
        self.push(Toast::new(message, ToastKind::Info));
    }

    pub fn success(&mut self, message: impl Into<String>) {
        self.push(Toast::new(message, ToastKind::Success));
    }

    pub fn warning(&mut self, message: impl Into<String>) {
        self.push(Toast::new(message, ToastKind::Warning));
    }

    pub fn error(&mut self, message: impl Into<String>) {
        self.push(Toast::new(message, ToastKind::Error));
    }

    pub fn update(&mut self, dt: f32) {
        for toast in &mut self.toasts {
            toast.update(dt);
        }
        self.toasts.retain(|t| !t.is_done());
    }

    pub fn toasts(&self) -> &[Toast] {
        &self.toasts
    }

    pub fn show(&mut self, ctx: &egui::Context) {
        let screen = ctx.screen_rect();
        let margin = 16.0;
        let toast_width = 300.0_f32.min(screen.width() - margin * 2.0);
        let toast_height = 48.0;
        let spacing = 8.0;

        let visible: Vec<usize> = self.toasts
            .iter()
            .enumerate()
            .rev()
            .take(self.max_visible)
            .map(|(i, _)| i)
            .collect();

        for (stack_pos, &idx) in visible.iter().enumerate() {
            let toast = &mut self.toasts[idx];
            let base_y = screen.max.y - margin - (toast_height + spacing) * (stack_pos as f32 + 1.0);
            let offset = toast.offset(50.0);
            let opacity = toast.opacity();

            let rect = Rect::from_min_size(
                pos2(
                    (screen.center().x - toast_width / 2.0) + offset.x,
                    base_y + offset.y,
                ),
                Vec2::new(toast_width, toast_height),
            );

            let bg = match toast.kind {
                ToastKind::Info => Color32::from_rgb(28, 28, 32),
                ToastKind::Success => Color32::from_rgb(20, 50, 30),
                ToastKind::Warning => Color32::from_rgb(50, 40, 15),
                ToastKind::Error => Color32::from_rgb(50, 20, 20),
            };
            let border = match toast.kind {
                ToastKind::Info => Color32::from_rgb(90, 200, 250),
                ToastKind::Success => Color32::from_rgb(48, 209, 88),
                ToastKind::Warning => Color32::from_rgb(255, 149, 0),
                ToastKind::Error => Color32::from_rgb(255, 69, 58),
            };
            let icon = match toast.kind {
                ToastKind::Info => "ℹ",
                ToastKind::Success => "✓",
                ToastKind::Warning => "⚠",
                ToastKind::Error => "✕",
            };

            let alpha = (opacity * 255.0) as u8;
            let bg = Color32::from_rgba_premultiplied(bg.r(), bg.g(), bg.b(), alpha);
            let border = Color32::from_rgba_premultiplied(border.r(), border.g(), border.b(), alpha);
            let text = Color32::from_rgba_premultiplied(240, 240, 245, alpha);

            let painter = ctx.layer_painter(egui::LayerId::new(
                egui::Order::Foreground,
                egui::Id::new(("toast", idx)),
            ));

            painter.rect_filled(rect, 10.0, bg);
            painter.rect_stroke(rect, 10.0, egui::Stroke::new(1.0_f32, border));

            painter.text(
                rect.left_center() + Vec2::new(12.0, 0.0),
                egui::Align2::LEFT_CENTER,
                icon,
                egui::FontId::proportional(14.0),
                border,
            );

            painter.text(
                rect.left_center() + Vec2::new(28.0, 0.0),
                egui::Align2::LEFT_CENTER,
                &toast.message,
                egui::FontId::proportional(13.0),
                text,
            );
        }
    }
}

impl Default for ToastManager {
    fn default() -> Self {
        Self::new()
    }
}
