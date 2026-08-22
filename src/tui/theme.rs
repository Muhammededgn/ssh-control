use std::sync::atomic::{AtomicU8, Ordering};

use ratatui::style::{Color, Modifier, Style};

/// The only place in the crate that names a `Color`.
///
/// Five *ink* roles, chosen to be exactly the five colours the screens were
/// already using, so `Auto` is the pre-theme appearance byte for byte and the
/// original migration could not change how anything looks:
///
/// | role | was |
/// |---|---|
/// | `hint` | `DarkGray` — every secondary line |
/// | `accent` | `Cyan` — focused field, active border, directory, command echo |
/// | `error` | `Red` |
/// | `success` | `Green` |
/// | `warning` | `Yellow` — status messages, marked files, warnings |
///
/// Plus three *surface* roles, which are what makes a preset visible at all.
/// Without them "light" only swapped five accents and the terminal stayed dark
/// underneath — which is exactly the bug they were added to fix.
///
/// | role | what it paints |
/// |---|---|
/// | `background` | the whole frame, under everything |
/// | `surface` | the chrome bands and modal fills, lifted off the background |
/// | `text` | default body foreground |
///
/// Deliberately *not* roles, because each would be a fold of one of the above
/// and folding two roles together is the one change this table forbids:
/// `text_muted` is `hint`; an idle border is `hint` and a focused one is
/// `accent` (the convention `file_browser::render_pane` already set); and a
/// selection is `Modifier::REVERSED`, which swaps `text` against `background`
/// on its own and is the only styling that survives `NO_COLOR`.
///
/// There is no `Default` and no preset uses `..Default::default()`, so a new
/// role forgotten in one preset is a compile error rather than a colour that
/// silently reads as black. That check is the feature, exactly as with
/// `i18n::Strings`.
struct Palette {
    hint: Color,
    accent: Color,
    error: Color,
    success: Color,
    warning: Color,
    background: Color,
    surface: Color,
    text: Color,
}

/// The terminal's own colours, unchanged — this is the appearance every
/// version before the surface roles had, and it stays the default.
///
/// Every surface role is `Reset`, so nothing is painted and the user's own
/// terminal theme shows through. `surface` too: a band tinted against a
/// background this preset does not control is a band that can land invisible.
const AUTO: Palette = Palette {
    hint: Color::DarkGray,
    accent: Color::Cyan,
    error: Color::Red,
    success: Color::Green,
    warning: Color::Yellow,
    background: Color::Reset,
    surface: Color::Reset,
    text: Color::Reset,
};

/// A dark preset that actually commits to being dark, rather than deferring.
/// Same five inks as `AUTO`; the difference is that it paints.
const DARK: Palette = Palette {
    hint: Color::DarkGray,
    accent: Color::Cyan,
    error: Color::Red,
    success: Color::Green,
    warning: Color::Yellow,
    background: Color::Indexed(234),
    surface: Color::Indexed(237),
    text: Color::Indexed(252),
};

/// For a light background, where `AUTO`'s `DarkGray` hints are close to
/// unreadable and `Yellow` is invisible outright.
///
/// Indexed rather than `Rgb`: the 256-colour cube is far more widely supported
/// than truecolor, and these are all darkened so they carry against white. The
/// bright ANSI names are deliberately avoided for exactly the reason this
/// preset exists.
const LIGHT: Palette = Palette {
    hint: Color::Indexed(240),
    // Blue rather than cyan — cyan on white is the same washout as the hints.
    accent: Color::Indexed(26),
    error: Color::Indexed(160),
    success: Color::Indexed(28),
    // Amber. `Yellow` on a white background is not a colour, it is a rumour.
    warning: Color::Indexed(130),
    background: Color::Indexed(255),
    surface: Color::Indexed(252),
    // Not pure black: 235 against 255 is the contrast a document has, not the
    // contrast a terminal has.
    text: Color::Indexed(235),
};

/// What `NO_COLOR` selects: every role is the terminal's own default, so the
/// styling collapses to the bold/reversed modifiers, which are not colour and
/// stay. That includes the surface roles — painting a background is a colour
/// decision like any other.
const NO_COLOR_PALETTE: Palette = Palette {
    hint: Color::Reset,
    accent: Color::Reset,
    error: Color::Reset,
    success: Color::Reset,
    warning: Color::Reset,
    background: Color::Reset,
    surface: Color::Reset,
    text: Color::Reset,
};

/// The user's preference. `NoColor` is not one of these — it is the
/// environment's decision, not the user's, and is never persisted or offered
/// in Settings.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Theme {
    /// Paint nothing; inherit whatever the terminal already is.
    #[default]
    Auto,
    Dark,
    Light,
}

pub const THEMES: [Theme; 3] = [Theme::Auto, Theme::Dark, Theme::Light];

impl Theme {
    pub fn code(self) -> &'static str {
        match self {
            Theme::Auto => "AUTO",
            Theme::Dark => "DARK",
            Theme::Light => "LIGHT",
        }
    }

    fn from_code(code: &str) -> Option<Self> {
        match code {
            "AUTO" => Some(Theme::Auto),
            "DARK" => Some(Theme::Dark),
            "LIGHT" => Some(Theme::Light),
            _ => None,
        }
    }

    /// Reads the remembered theme. Mirrors `Lang::load_from_file`, including
    /// the "never fatal" part: a missing, unreadable or unrecognized file is
    /// the default, not an error. It has to be readable before unlock, which
    /// is why it sits beside `prefs.lang` rather than inside the vault.
    pub fn load_from_file(path: &std::path::Path) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|s| Theme::from_code(s.trim()))
            .unwrap_or_default()
    }

    /// Best-effort, exactly like `Lang::save_to_file` — a preference that
    /// cannot be written must never block the app.
    pub fn save_to_file(self, path: &std::path::Path) {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(path, self.code());
    }
}

const AUTO_ID: u8 = 0;
const DARK_ID: u8 = 1;
const LIGHT_ID: u8 = 2;
const NO_COLOR_ID: u8 = 3;

/// The active palette.
///
/// A process global rather than a `&Theme` threaded through every `render`,
/// and unlike the state this codebase otherwise refuses to duplicate, there is
/// nothing here to drift *from*: exactly one value exists, `set` is the only
/// writer, and no screen keeps a copy. Threading it would mean a parameter on
/// fifteen `render` signatures and every closure inside them, in exchange for
/// no invariant.
static ACTIVE: AtomicU8 = AtomicU8::new(AUTO_ID);

/// Applies the user's preference unless `NO_COLOR` overrides it.
///
/// `NO_COLOR` wins and is not persisted: it is the environment's call, made
/// per-launch, and writing it into `prefs.theme` would leave the choice stuck
/// after the variable went away. See <https://no-color.org> for the "set and
/// non-empty" rule.
pub fn init(theme: Theme) {
    if no_color() {
        ACTIVE.store(NO_COLOR_ID, Ordering::Relaxed);
    } else {
        set(theme);
    }
}

/// Whether `NO_COLOR` is in force. Settings reads it to say why picking a
/// preset is currently doing nothing visible.
pub fn no_color() -> bool {
    std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty())
}

/// Switches presets at runtime. A no-op under `NO_COLOR`, so a preference the
/// user picks is still stored and still takes effect the next time they run
/// without the variable set.
pub fn set(theme: Theme) {
    if no_color() {
        return;
    }
    ACTIVE.store(match theme { Theme::Auto => AUTO_ID, Theme::Dark => DARK_ID, Theme::Light => LIGHT_ID }, Ordering::Relaxed);
}

fn active() -> &'static Palette {
    match ACTIVE.load(Ordering::Relaxed) {
        DARK_ID => &DARK,
        LIGHT_ID => &LIGHT,
        NO_COLOR_ID => &NO_COLOR_PALETTE,
        _ => &AUTO,
    }
}

pub fn hint() -> Color {
    active().hint
}

pub fn accent() -> Color {
    active().accent
}

pub fn error() -> Color {
    active().error
}

pub fn success() -> Color {
    active().success
}

pub fn warning() -> Color {
    active().warning
}

pub fn background() -> Color {
    active().background
}

pub fn surface() -> Color {
    active().surface
}

pub fn text() -> Color {
    active().text
}

/// The style the whole frame is painted with before anything else.
///
/// Both halves are load-bearing. A background with no foreground leaves body
/// text at the terminal's own colour, which under the light preset is white on
/// white. And because `Cell::set_style` patches rather than assigns, this one
/// widget reaches every `Style::default()` span drawn after it — which is why
/// no screen has to learn that `text()` exists.
pub fn root() -> Style {
    Style::default().fg(text()).bg(background())
}

/// The selected row of a list.
///
/// An accent foreground and a bold weight rather than the full-width
/// `REVERSED` band the screens used to carry: on a wide terminal that band was
/// the loudest thing on screen, and it drowned the row it was meant to point
/// at. The `▌` marker every list draws beside it is what keeps the selection
/// legible under `NO_COLOR`, where the accent collapses to the terminal's own
/// foreground — a marker is not colour.
pub fn selection() -> Style {
    Style::default().fg(accent()).add_modifier(Modifier::BOLD)
}

/// The chrome bands and the fill behind a modal: one step off the background
/// so a panel reads as sitting on top of the frame rather than cut out of it.
pub fn band() -> Style {
    Style::default().fg(text()).bg(surface())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Auto` has to be the pre-theme appearance exactly, or the original
    /// migration was not a refactor. The five inks:
    #[test]
    fn auto_is_the_colours_the_screens_already_used() {
        assert_eq!(AUTO.hint, Color::DarkGray);
        assert_eq!(AUTO.accent, Color::Cyan);
        assert_eq!(AUTO.error, Color::Red);
        assert_eq!(AUTO.success, Color::Green);
        assert_eq!(AUTO.warning, Color::Yellow);
    }

    /// ...and the promise that it paints nothing at all. This is the half that
    /// keeps "I never picked a theme" identical to every earlier version.
    #[test]
    fn auto_defers_entirely_to_the_terminal() {
        assert_eq!(AUTO.background, Color::Reset);
        assert_eq!(AUTO.surface, Color::Reset);
        assert_eq!(AUTO.text, Color::Reset);
    }

    /// The whole point of the light preset: nothing in it may be a colour that
    /// disappears on white.
    #[test]
    fn light_shares_no_role_with_auto() {
        assert_ne!(LIGHT.hint, AUTO.hint);
        assert_ne!(LIGHT.warning, AUTO.warning);
        assert_ne!(LIGHT.accent, AUTO.accent);
    }

    /// The regression guard for "the light theme does nothing". Before the
    /// surface roles existed this is the assertion that would have failed:
    /// picking `Light` swapped five accents and left the terminal's own dark
    /// background showing through underneath.
    #[test]
    fn a_preset_that_is_not_auto_paints_a_surface_of_its_own() {
        for palette in [&DARK, &LIGHT] {
            assert_ne!(palette.background, Color::Reset, "an explicit preset has to paint, or it is indistinguishable from Auto");
            assert_ne!(palette.text, Color::Reset);
            assert_ne!(palette.surface, palette.background, "the bands have to lift off the canvas");
        }
        assert_ne!(DARK.background, LIGHT.background);
        assert_ne!(DARK.text, LIGHT.text);
    }

    /// Painting a background is a colour decision like any other, so it has to
    /// go away with the rest of them.
    #[test]
    fn no_color_leaves_every_role_at_the_terminals_default() {
        let p = &NO_COLOR_PALETTE;
        for role in [p.hint, p.accent, p.error, p.success, p.warning, p.background, p.surface, p.text] {
            assert_eq!(role, Color::Reset);
        }
    }

    #[test]
    fn a_theme_round_trips_through_its_code() {
        for theme in THEMES {
            assert_eq!(Theme::from_code(theme.code()), Some(theme));
        }
        assert_eq!(Theme::from_code("magenta-on-magenta"), None);
    }

    #[test]
    fn an_unreadable_preference_file_is_the_default_not_an_error() {
        assert_eq!(Theme::load_from_file(std::path::Path::new("/nonexistent/prefs.theme")), Theme::Auto);
    }

    /// The issue's first acceptance criterion, pinned rather than trusted: no
    /// literal `Color::` may reappear outside this module. A screen that names
    /// one is a screen the light preset cannot reach.
    #[test]
    fn no_screen_names_a_colour_of_its_own() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut offenders = Vec::new();
        let mut stack = vec![root];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("src is readable") {
                let path = entry.expect("dir entry").path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|e| e == "rs") && path.file_name().is_some_and(|n| n != "theme.rs") {
                    let text = std::fs::read_to_string(&path).expect("source is utf-8");
                    if text.contains("Color::") {
                        offenders.push(path.display().to_string());
                    }
                }
            }
        }
        assert!(offenders.is_empty(), "these name a colour instead of a theme role: {offenders:?}");
    }

    /// The second acceptance criterion: the preset has to survive a restart,
    /// which for a file-backed preference means surviving a round trip.
    #[test]
    fn a_chosen_preset_survives_a_restart() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("prefs.theme");
        Theme::Light.save_to_file(&path);
        assert_eq!(Theme::load_from_file(&path), Theme::Light);
    }
}
