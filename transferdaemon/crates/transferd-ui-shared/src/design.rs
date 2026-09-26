//! Design system — themes, colors, typography, spacing, animations, and responsive layout.
//!
//! This module provides a unified design language for the entire UI, ensuring
//! consistency, accessibility, and a modern bleeding-edge aesthetic.

use egui::{Color32, FontId, Vec2};

// ---------------------------------------------------------------------------
// Theme
// ---------------------------------------------------------------------------

/// Available UI themes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Theme {
    Dark,
    Light,
    HighContrast,
    /// OLED-optimized: pure black backgrounds to save power on AMOLED screens.
    #[default]
    Oled,
}

// ---------------------------------------------------------------------------
// Color Palette
// ---------------------------------------------------------------------------

/// Semantic color tokens — every UI element references these instead of raw values.
#[derive(Clone)]
pub struct Palette {
    // Backgrounds
    pub bg_primary: Color32,
    pub bg_secondary: Color32,
    pub bg_tertiary: Color32,
    pub bg_elevated: Color32,
    pub bg_overlay: Color32,

    // Surfaces
    pub surface: Color32,
    pub surface_hover: Color32,
    pub surface_active: Color32,

    // Borders
    pub border: Color32,
    pub border_focus: Color32,
    pub border_subtle: Color32,

    // Text
    pub text_primary: Color32,
    pub text_secondary: Color32,
    pub text_tertiary: Color32,
    pub text_disabled: Color32,
    pub text_inverse: Color32,

    // Accent
    pub accent: Color32,
    pub accent_hover: Color32,
    pub accent_active: Color32,
    pub accent_subtle: Color32,

    // Status
    pub success: Color32,
    pub success_subtle: Color32,
    pub warning: Color32,
    pub warning_subtle: Color32,
    pub error: Color32,
    pub error_subtle: Color32,
    pub info: Color32,
    pub info_subtle: Color32,

    // Message bubbles
    pub bubble_inbound: Color32,
    pub bubble_outbound: Color32,
    pub bubble_text: Color32,

    // Chat
    pub chat_header: Color32,
    pub chat_input_bg: Color32,
    pub chat_input_border: Color32,

    // Tabs
    pub tab_active: Color32,
    pub tab_inactive: Color32,
    pub tab_bar_bg: Color32,

    // Cards
    pub card_bg: Color32,
    pub card_border: Color32,

    // Scrollbar
    pub scrollbar_bg: Color32,
    pub scrollbar_thumb: Color32,
}

impl Palette {
    pub fn for_theme(theme: Theme) -> Self {
        match theme {
            Theme::Dark => Self::dark(),
            Theme::Light => Self::light(),
            Theme::HighContrast => Self::high_contrast(),
            Theme::Oled => Self::oled(),
        }
    }

    fn dark() -> Self {
        Self {
            bg_primary: Color32::from_rgb(15, 15, 17),
            bg_secondary: Color32::from_rgb(22, 22, 26),
            bg_tertiary: Color32::from_rgb(28, 28, 32),
            bg_elevated: Color32::from_rgb(35, 35, 40),
            bg_overlay: Color32::from_rgba_premultiplied(0, 0, 0, 180),

            surface: Color32::from_rgb(28, 28, 32),
            surface_hover: Color32::from_rgb(38, 38, 44),
            surface_active: Color32::from_rgb(48, 48, 56),

            border: Color32::from_rgb(50, 50, 58),
            border_focus: Color32::from_rgb(0, 122, 255),
            border_subtle: Color32::from_rgb(35, 35, 40),

            text_primary: Color32::from_rgb(240, 240, 245),
            text_secondary: Color32::from_rgb(160, 160, 172),
            text_tertiary: Color32::from_rgb(110, 110, 120),
            text_disabled: Color32::from_rgb(70, 70, 78),
            text_inverse: Color32::from_rgb(15, 15, 17),

            accent: Color32::from_rgb(0, 122, 255),
            accent_hover: Color32::from_rgb(30, 142, 255),
            accent_active: Color32::from_rgb(60, 162, 255),
            accent_subtle: Color32::from_rgb(0, 122, 255),

            success: Color32::from_rgb(48, 209, 88),
            success_subtle: Color32::from_rgb(48, 209, 88),
            warning: Color32::from_rgb(255, 149, 0),
            warning_subtle: Color32::from_rgb(255, 149, 0),
            error: Color32::from_rgb(255, 69, 58),
            error_subtle: Color32::from_rgb(255, 69, 58),
            info: Color32::from_rgb(90, 200, 250),
            info_subtle: Color32::from_rgb(90, 200, 250),

            bubble_inbound: Color32::from_rgb(38, 38, 44),
            bubble_outbound: Color32::from_rgb(0, 122, 255),
            bubble_text: Color32::from_rgb(240, 240, 245),

            chat_header: Color32::from_rgb(18, 18, 22),
            chat_input_bg: Color32::from_rgb(28, 28, 32),
            chat_input_border: Color32::from_rgb(50, 50, 58),

            tab_active: Color32::from_rgb(0, 122, 255),
            tab_inactive: Color32::from_rgb(110, 110, 120),
            tab_bar_bg: Color32::from_rgb(15, 15, 17),

            card_bg: Color32::from_rgb(28, 28, 32),
            card_border: Color32::from_rgb(50, 50, 58),

            scrollbar_bg: Color32::from_rgb(22, 22, 26),
            scrollbar_thumb: Color32::from_rgb(55, 55, 62),
        }
    }

    fn oled() -> Self {
        let mut p = Self::dark();
        // Pure black backgrounds for AMOLED power savings
        p.bg_primary = Color32::from_rgb(0, 0, 0);
        p.bg_secondary = Color32::from_rgb(12, 12, 14);
        p.bg_tertiary = Color32::from_rgb(22, 22, 24);
        p.bg_elevated = Color32::from_rgb(30, 30, 34);
        p.chat_header = Color32::from_rgb(0, 0, 0);
        p.tab_bar_bg = Color32::from_rgb(0, 0, 0);
        p.scrollbar_bg = Color32::from_rgb(12, 12, 14);
        p
    }

    fn light() -> Self {
        Self {
            bg_primary: Color32::from_rgb(242, 242, 247),
            bg_secondary: Color32::from_rgb(235, 235, 240),
            bg_tertiary: Color32::from_rgb(228, 228, 234),
            bg_elevated: Color32::from_rgb(255, 255, 255),
            bg_overlay: Color32::from_rgba_premultiplied(242, 242, 247, 200),

            surface: Color32::from_rgb(255, 255, 255),
            surface_hover: Color32::from_rgb(240, 240, 245),
            surface_active: Color32::from_rgb(228, 228, 234),

            border: Color32::from_rgb(200, 200, 210),
            border_focus: Color32::from_rgb(0, 122, 255),
            border_subtle: Color32::from_rgb(220, 220, 228),

            text_primary: Color32::from_rgb(28, 28, 30),
            text_secondary: Color32::from_rgb(100, 100, 110),
            text_tertiary: Color32::from_rgb(140, 140, 150),
            text_disabled: Color32::from_rgb(180, 180, 190),
            text_inverse: Color32::from_rgb(255, 255, 255),

            accent: Color32::from_rgb(0, 122, 255),
            accent_hover: Color32::from_rgb(0, 102, 235),
            accent_active: Color32::from_rgb(0, 82, 215),
            accent_subtle: Color32::from_rgb(0, 122, 255),

            success: Color32::from_rgb(36, 168, 72),
            success_subtle: Color32::from_rgb(36, 168, 72),
            warning: Color32::from_rgb(255, 130, 0),
            warning_subtle: Color32::from_rgb(255, 130, 0),
            error: Color32::from_rgb(255, 50, 40),
            error_subtle: Color32::from_rgb(255, 50, 40),
            info: Color32::from_rgb(0, 140, 220),
            info_subtle: Color32::from_rgb(0, 140, 220),

            bubble_inbound: Color32::from_rgb(228, 228, 234),
            bubble_outbound: Color32::from_rgb(0, 122, 255),
            bubble_text: Color32::from_rgb(28, 28, 30),

            chat_header: Color32::from_rgb(255, 255, 255),
            chat_input_bg: Color32::from_rgb(255, 255, 255),
            chat_input_border: Color32::from_rgb(200, 200, 210),

            tab_active: Color32::from_rgb(0, 122, 255),
            tab_inactive: Color32::from_rgb(140, 140, 150),
            tab_bar_bg: Color32::from_rgb(255, 255, 255),

            card_bg: Color32::from_rgb(255, 255, 255),
            card_border: Color32::from_rgb(200, 200, 210),

            scrollbar_bg: Color32::from_rgb(235, 235, 240),
            scrollbar_thumb: Color32::from_rgb(180, 180, 190),
        }
    }

    fn high_contrast() -> Self {
        Self {
            bg_primary: Color32::from_rgb(0, 0, 0),
            bg_secondary: Color32::from_rgb(10, 10, 12),
            bg_tertiary: Color32::from_rgb(20, 20, 24),
            bg_elevated: Color32::from_rgb(30, 30, 36),
            bg_overlay: Color32::from_rgba_premultiplied(0, 0, 0, 220),

            surface: Color32::from_rgb(20, 20, 24),
            surface_hover: Color32::from_rgb(40, 40, 48),
            surface_active: Color32::from_rgb(60, 60, 70),

            border: Color32::from_rgb(120, 120, 140),
            border_focus: Color32::from_rgb(80, 180, 255),
            border_subtle: Color32::from_rgb(80, 80, 95),

            text_primary: Color32::from_rgb(255, 255, 255),
            text_secondary: Color32::from_rgb(200, 200, 210),
            text_tertiary: Color32::from_rgb(150, 150, 165),
            text_disabled: Color32::from_rgb(90, 90, 105),
            text_inverse: Color32::from_rgb(0, 0, 0),

            accent: Color32::from_rgb(80, 180, 255),
            accent_hover: Color32::from_rgb(100, 195, 255),
            accent_active: Color32::from_rgb(120, 210, 255),
            accent_subtle: Color32::from_rgb(80, 180, 255),

            success: Color32::from_rgb(60, 230, 110),
            success_subtle: Color32::from_rgb(60, 230, 110),
            warning: Color32::from_rgb(255, 170, 30),
            warning_subtle: Color32::from_rgb(255, 170, 30),
            error: Color32::from_rgb(255, 80, 70),
            error_subtle: Color32::from_rgb(255, 80, 70),
            info: Color32::from_rgb(110, 220, 255),
            info_subtle: Color32::from_rgb(110, 220, 255),

            bubble_inbound: Color32::from_rgb(35, 35, 42),
            bubble_outbound: Color32::from_rgb(80, 180, 255),
            bubble_text: Color32::from_rgb(255, 255, 255),

            chat_header: Color32::from_rgb(0, 0, 0),
            chat_input_bg: Color32::from_rgb(20, 20, 24),
            chat_input_border: Color32::from_rgb(120, 120, 140),

            tab_active: Color32::from_rgb(80, 180, 255),
            tab_inactive: Color32::from_rgb(150, 150, 165),
            tab_bar_bg: Color32::from_rgb(0, 0, 0),

            card_bg: Color32::from_rgb(20, 20, 24),
            card_border: Color32::from_rgb(120, 120, 140),

            scrollbar_bg: Color32::from_rgb(10, 10, 12),
            scrollbar_thumb: Color32::from_rgb(90, 90, 105),
        }
    }
}

// ---------------------------------------------------------------------------
// Typography
// ---------------------------------------------------------------------------

/// Typography scale for consistent text styling.
#[derive(Clone)]
pub struct Typography {
    pub display: FontId,
    pub heading: FontId,
    pub title: FontId,
    pub body_large: FontId,
    pub body: FontId,
    pub body_small: FontId,
    pub caption: FontId,
    pub mono: FontId,
    pub mono_small: FontId,
}

impl Default for Typography {
    fn default() -> Self {
        Self {
            display: FontId::proportional(32.0),
            heading: FontId::proportional(24.0),
            title: FontId::proportional(20.0),
            body_large: FontId::proportional(16.0),
            body: FontId::proportional(14.0),
            body_small: FontId::proportional(13.0),
            caption: FontId::proportional(11.0),
            mono: FontId::monospace(14.0),
            mono_small: FontId::monospace(11.0),
        }
    }
}

// ---------------------------------------------------------------------------
// Spacing
// ---------------------------------------------------------------------------

/// Spacing system for consistent layout.
#[derive(Clone)]
pub struct Spacing {
    /// Extra large spacing (32px)
    pub xl: f32,
    /// Large spacing (24px)
    pub lg: f32,
    /// Medium spacing (16px)
    pub md: f32,
    /// Small spacing (12px)
    pub sm: f32,
    /// Extra small spacing (8px)
    pub xs: f32,
    /// Tiny spacing (4px)
    pub xxs: f32,

    // Component-specific
    pub button_padding: Vec2,
    pub input_padding: Vec2,
    pub card_padding: Vec2,
    pub card_rounding: f32,
    pub button_rounding: f32,
    pub input_rounding: f32,
    pub bubble_rounding: f32,
    pub panel_rounding: f32,

    // Touch targets
    pub min_touch_target: f32,
    pub min_button_height: f32,
}

impl Default for Spacing {
    fn default() -> Self {
        Self {
            xl: 32.0,
            lg: 24.0,
            md: 16.0,
            sm: 12.0,
            xs: 8.0,
            xxs: 4.0,

            button_padding: Vec2::new(16.0, 10.0),
            input_padding: Vec2::new(12.0, 10.0),
            card_padding: Vec2::new(16.0, 12.0),
            card_rounding: 12.0,
            button_rounding: 10.0,
            input_rounding: 10.0,
            bubble_rounding: 16.0,
            panel_rounding: 0.0,

            min_touch_target: 44.0,
            min_button_height: 44.0,
        }
    }
}

// ---------------------------------------------------------------------------
// Animation
// ---------------------------------------------------------------------------

/// Easing functions for smooth animations.
pub enum Easing {
    Linear,
    EaseOut,
    EaseIn,
    EaseInOut,
    /// Snappy feel — fast start, smooth stop. Good for UI transitions.
    Spring,
}

impl Easing {
    /// Evaluate the easing function at progress `t` (0.0..=1.0).
    pub fn apply(&self, t: f32) -> f32 {
        let t = t.clamp(0.0, 1.0);
        match self {
            Self::Linear => t,
            Self::EaseOut => 1.0 - (1.0 - t).powi(3),
            Self::EaseIn => t * t * t,
            Self::EaseInOut => {
                if t < 0.5 {
                    4.0 * t * t * t
                } else {
                    1.0 - (-2.0 * t + 2.0).powi(3) / 2.0
                }
            }
            Self::Spring => {
                // Approximate spring with a damped overshoot
                let c4 = (2.0 * std::f32::consts::PI) / 3.0;
                if t < 0.5 {
                    (2.0_f32.powf(20.0 * t - 10.0) * ((20.0 * t - 11.125) * c4).sin()) / 2.0
                } else {
                    (2.0_f32.powf(-20.0 * t + 10.0) * ((20.0 * t - 11.125) * c4).sin()) / -2.0 + 1.0
                }
            }
        }
    }
}

/// A stateful animator that drives smooth transitions between values.
pub struct Animator {
    /// Current interpolated value.
    value: f32,
    /// Target value.
    target: f32,
    /// Speed in units per second.
    speed: f32,
    /// Easing function.
    easing: Easing,
}

impl Animator {
    pub fn new(initial: f32, speed: f32, easing: Easing) -> Self {
        Self {
            value: initial,
            target: initial,
            speed,
            easing,
        }
    }

    pub fn set_target(&mut self, target: f32) {
        self.target = target;
    }

    /// Update and return the current interpolated value.
    pub fn update(&mut self, dt: f32) -> f32 {
        if (self.value - self.target).abs() < 0.01 {
            self.value = self.target;
            return self.value;
        }
        let t = (dt * self.speed).clamp(0.0, 1.0);
        let t = self.easing.apply(t);
        self.value += (self.target - self.value) * t;
        self.value
    }

    pub fn value(&self) -> f32 {
        self.value
    }

    pub fn is_at_target(&self) -> bool {
        (self.value - self.target).abs() < 0.01
    }
}

// ---------------------------------------------------------------------------
// Responsive
// ---------------------------------------------------------------------------

/// Window size breakpoints for responsive layout.
#[derive(Clone)]
pub struct Breakpoints {
    pub compact: f32,    // < 600px  (phone portrait)
    pub medium: f32,     // 600-900px (phone landscape / small tablet)
    pub expanded: f32,   // > 900px  (tablet / desktop)
}

impl Default for Breakpoints {
    fn default() -> Self {
        Self {
            compact: 600.0,
            medium: 900.0,
            expanded: 1200.0,
        }
    }
}

/// Determine the current layout mode from window width.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutMode {
    /// Phone portrait: stacked panels, bottom tab bar
    Compact,
    /// Tablet: split view possible, side tabs
    Medium,
    /// Desktop: full multi-panel layout
    Expanded,
}

impl LayoutMode {
    pub fn from_width(width: f32) -> Self {
        if width < Breakpoints::default().compact {
            Self::Compact
        } else if width < Breakpoints::default().medium {
            Self::Medium
        } else {
            Self::Expanded
        }
    }
}

// ---------------------------------------------------------------------------
// Global Design Tokens (singleton)
// ---------------------------------------------------------------------------

/// Global design tokens — accessed via `DesignTokens::current()`.
#[derive(Clone)]
pub struct DesignTokens {
    pub palette: Palette,
    pub typography: Typography,
    pub spacing: Spacing,
    pub breakpoints: Breakpoints,
    pub theme: Theme,
}

impl DesignTokens {
    /// Create tokens for the given theme.
    pub fn new(theme: Theme) -> Self {
        Self {
            palette: Palette::for_theme(theme),
            typography: Typography::default(),
            spacing: Spacing::default(),
            breakpoints: Breakpoints::default(),
            theme,
        }
    }

    /// Get a clone of the current tokens. Panics if not initialized.
    pub fn current() -> DesignTokens {
        DESIGN_TOKENS.with(|t| t.borrow().clone().expect("DesignTokens not initialized"))
    }

    /// Initialize the global tokens. Must be called once at startup.
    pub fn init(theme: Theme) {
        DESIGN_TOKENS.with(|t| {
            *t.borrow_mut() = Some(Self::new(theme));
        });
    }

    /// Switch theme at runtime.
    pub fn set_theme(theme: Theme) {
        Self::init(theme);
    }
}

thread_local! {
    static DESIGN_TOKENS: std::cell::RefCell<Option<DesignTokens>> = const { std::cell::RefCell::new(None) };
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Create a styled button frame.
pub fn button_frame(tokens: &DesignTokens) -> egui::Frame {
    egui::Frame::none()
        .fill(tokens.palette.accent)
        .rounding(tokens.spacing.button_rounding)
        .inner_margin(tokens.spacing.button_padding)
}

/// Create a secondary button frame.
pub fn secondary_button_frame(tokens: &DesignTokens) -> egui::Frame {
    egui::Frame::none()
        .fill(tokens.palette.surface)
        .rounding(tokens.spacing.button_rounding)
        .inner_margin(tokens.spacing.button_padding)
}

/// Create a card frame.
pub fn card_frame(tokens: &DesignTokens) -> egui::Frame {
    egui::Frame::none()
        .fill(tokens.palette.card_bg)
        .stroke(egui::Stroke::new(1.0_f32, tokens.palette.card_border))
        .rounding(tokens.spacing.card_rounding)
        .inner_margin(tokens.spacing.card_padding)
}

/// Create an input frame.
pub fn input_frame(tokens: &DesignTokens) -> egui::Frame {
    egui::Frame::none()
        .fill(tokens.palette.surface)
        .stroke(egui::Stroke::new(1.0_f32, tokens.palette.chat_input_border))
        .rounding(tokens.spacing.input_rounding)
        .inner_margin(tokens.spacing.input_padding)
}

/// Create a panel frame.
pub fn panel_frame(tokens: &DesignTokens) -> egui::Frame {
    egui::Frame::none()
        .fill(tokens.palette.bg_primary)
        .rounding(tokens.spacing.panel_rounding)
}

/// Apply the global theme to an egui context.
pub fn apply_theme(ctx: &egui::Context, theme: Theme) {
    DesignTokens::init(theme);
    let tokens = DesignTokens::current();

    let mut visuals = match theme {
        Theme::Light => egui::Visuals::light(),
        _ => egui::Visuals::dark(),
    };

    visuals.panel_fill = tokens.palette.bg_primary;
    visuals.window_fill = tokens.palette.bg_elevated;
    visuals.extreme_bg_color = tokens.palette.bg_primary;
    visuals.faint_bg_color = tokens.palette.bg_tertiary;
    visuals.selection.bg_fill = tokens.palette.accent;
    visuals.selection.stroke = egui::Stroke::new(1.0_f32, tokens.palette.text_primary);
    visuals.hyperlink_color = tokens.palette.accent;
    visuals.warn_fg_color = tokens.palette.warning;
    visuals.error_fg_color = tokens.palette.error;

    // Widget styling
    visuals.widgets.noninteractive.rounding = tokens.spacing.button_rounding.into();
    visuals.widgets.noninteractive.bg_fill = tokens.palette.surface;
    visuals.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0_f32, tokens.palette.text_secondary);
    visuals.widgets.noninteractive.bg_stroke = egui::Stroke::NONE;

    visuals.widgets.inactive.rounding = tokens.spacing.button_rounding.into();
    visuals.widgets.inactive.bg_fill = tokens.palette.surface;
    visuals.widgets.inactive.fg_stroke = egui::Stroke::new(1.0_f32, tokens.palette.text_primary);
    visuals.widgets.inactive.bg_stroke = egui::Stroke::new(1.0_f32, tokens.palette.border_subtle);

    visuals.widgets.hovered.rounding = tokens.spacing.button_rounding.into();
    visuals.widgets.hovered.bg_fill = tokens.palette.surface_hover;
    visuals.widgets.hovered.fg_stroke = egui::Stroke::new(1.0_f32, tokens.palette.text_primary);
    visuals.widgets.hovered.bg_stroke = egui::Stroke::new(1.0_f32, tokens.palette.border_focus);

    visuals.widgets.active.rounding = tokens.spacing.button_rounding.into();
    visuals.widgets.active.bg_fill = tokens.palette.surface_active;
    visuals.widgets.active.fg_stroke = egui::Stroke::new(1.5_f32, tokens.palette.text_primary);
    visuals.widgets.active.bg_stroke = egui::Stroke::new(2.0_f32, tokens.palette.accent);

    visuals.widgets.open.rounding = tokens.spacing.button_rounding.into();
    visuals.widgets.open.bg_fill = tokens.palette.surface_hover;
    visuals.widgets.open.fg_stroke = egui::Stroke::new(1.0_f32, tokens.palette.text_primary);
    visuals.widgets.open.bg_stroke = egui::Stroke::new(1.0_f32, tokens.palette.border_focus);

    ctx.set_visuals(visuals);
    ctx.set_fonts(egui::FontDefinitions::default());
    ctx.style_mut(|s| {
        s.spacing.item_spacing = Vec2::new(8.0, 6.0);
        s.spacing.button_padding = tokens.spacing.button_padding;
        s.spacing.indent = tokens.spacing.md;
    });
}
