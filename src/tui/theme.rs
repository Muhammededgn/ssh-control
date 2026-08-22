use std::sync::atomic::{AtomicU8, Ordering};

use ratatui::style::Color;

/// The only place in the crate that names a `Color`.
///
/// Five roles, chosen to be exactly the five colours the screens were already
/// using, so the dark preset is the old appearance byte for byte and the
/// migration could not change how anything looks:
///
/// | role | was |
/// |---|---|
/// | `hint` | `DarkGray` — every secondary line |
/// | `accent` | `Cyan` — focused field, active border, directory, command echo |
/// | `error` | `Red` |
/// | `success` | `Green` |
/// | `warning` | `Yellow` — status messages, marked files, warnings |
struct Palette {
    hint: Color,
    accent: Color,
    error: Color,
    success: Color,
    warning: Color,
}

/// Today's colours, unchanged.
const DARK: Palette = Palette {
    hint: Color::DarkGray,
    accent: Color::Cyan,
    error: Color::Red,
    success: Color::Green,
    warning: Color::Yellow,
};

/// For a light-background terminal, where the dark preset's `DarkGray` hints
/// are close to unreadable and `Yellow` is invisible outright.
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
};

/// What `NO_COLOR` selects: every role is the terminal's own default, so the
/// styling collapses to the bold/reversed modifiers, which are not colour and
/// stay.
const NO_COLOR_PALETTE: Palette = Palette {
    hint: Color::Reset,
    accent: Color::Reset,
    error: Color::Reset,
    success: Color::Reset,
    warning: Color::Reset,
};

/// The user's preference. `NoColor` is not one of these — it is the
/// environment's decision, not the user's, and is never persisted or offered
/// in Settings.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Theme {
    #[default]
    Dark,
    Light,
}

pub const THEMES: [Theme; 2] = [Theme::Dark, Theme::Light];

impl Theme {
    pub fn code(self) -> &'static str {
        match self {
            Theme::Dark => "DARK",
            Theme::Light => "LIGHT",
        }
    }

    fn from_code(code: &str) -> Option<Self> {
        match code {
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

const DARK_ID: u8 = 0;
const LIGHT_ID: u8 = 1;
const NO_COLOR_ID: u8 = 2;

/// The active palette.
///
/// A process global rather than a `&Theme` threaded through every `render`,
/// and unlike the state this codebase otherwise refuses to duplicate, there is
/// nothing here to drift *from*: exactly one value exists, `set` is the only
/// writer, and no screen keeps a copy. Threading it would mean a parameter on
/// fifteen `render` signatures and every closure inside them, in exchange for
/// no invariant.
static ACTIVE: AtomicU8 = AtomicU8::new(DARK_ID);

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
    ACTIVE.store(match theme { Theme::Dark => DARK_ID, Theme::Light => LIGHT_ID }, Ordering::Relaxed);
}

fn active() -> &'static Palette {
    match ACTIVE.load(Ordering::Relaxed) {
        LIGHT_ID => &LIGHT,
        NO_COLOR_ID => &NO_COLOR_PALETTE,
        _ => &DARK,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The dark preset has to be the pre-theme appearance exactly, or the
    /// change was not a refactor.
    #[test]
    fn dark_is_the_colours_the_screens_already_used() {
        assert_eq!(DARK.hint, Color::DarkGray);
        assert_eq!(DARK.accent, Color::Cyan);
        assert_eq!(DARK.error, Color::Red);
        assert_eq!(DARK.success, Color::Green);
        assert_eq!(DARK.warning, Color::Yellow);
    }

    /// The whole point of the light preset: nothing in it may be a colour that
    /// disappears on white.
    #[test]
    fn light_shares_no_role_with_dark() {
        assert_ne!(LIGHT.hint, DARK.hint);
        assert_ne!(LIGHT.warning, DARK.warning);
        assert_ne!(LIGHT.accent, DARK.accent);
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
        assert_eq!(Theme::load_from_file(std::path::Path::new("/nonexistent/prefs.theme")), Theme::Dark);
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
