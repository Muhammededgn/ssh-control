//! The "something is already there" prompt.
//!
//! A sibling of `confirm.rs` rather than an extension of it: that widget is a
//! two-outcome yes/no used by eleven call sites, and this one has three
//! outcomes plus a sticky "apply to all". Folding the second into the first
//! would make every "are you sure" carry state it does not want.
//!
//! It is not a `Screen`. The transfer flow owns it, draws it, and reads keys
//! for it directly, because by then the main loop is blocked inside the flow's
//! await — the same reason the script run screen has no key handling of its own
//! while a run is in progress.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};

use super::widgets::centered_rect;
use crate::i18n::Strings;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OverwriteChoice {
    None,
    Overwrite,
    Skip,
    Cancel,
}

/// What the user decided, and whether it stands for the rest of the run.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Decision {
    Overwrite,
    Skip,
}

pub struct OverwriteState {
    pub name: String,
    /// How many more conflicts are queued behind this one. "Apply to all" is
    /// only offered when there is more than one, because otherwise it says
    /// nothing.
    pub remaining: usize,
    pub apply_to_all: bool,
}

impl OverwriteState {
    pub fn new(name: String, remaining: usize) -> Self {
        Self { name, remaining, apply_to_all: false }
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> OverwriteChoice {
        match key.code {
            KeyCode::Char('o') | KeyCode::Char('O') | KeyCode::Enter => OverwriteChoice::Overwrite,
            KeyCode::Char('s') | KeyCode::Char('S') => OverwriteChoice::Skip,
            KeyCode::Char('a') | KeyCode::Char('A') if self.remaining > 1 => {
                self.apply_to_all = !self.apply_to_all;
                OverwriteChoice::None
            }
            KeyCode::Esc | KeyCode::Char('q') => OverwriteChoice::Cancel,
            _ => OverwriteChoice::None,
        }
    }

    pub fn render(&self, frame: &mut Frame, area: Rect, strings: &Strings) {
        let mut lines = vec![
            Line::from(vec![
                Span::raw(strings.overwrite_exists_prefix),
                Span::styled(self.name.clone(), Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(strings.overwrite_exists_suffix),
            ]),
            Line::from(""),
        ];
        if self.remaining > 1 {
            let mark = if self.apply_to_all { "[x]" } else { "[ ]" };
            lines.push(Line::from(Span::styled(
                format!("{mark} {}", strings.overwrite_apply_all_label),
                Style::default().fg(if self.apply_to_all { Color::Yellow } else { Color::DarkGray }),
            )));
        }
        lines.push(Line::from(Span::styled(strings.overwrite_hint, Style::default().fg(Color::DarkGray))));

        let box_area = centered_rect(60, lines.len() as u16 + 2, area);
        let block = Block::default()
            .borders(Borders::ALL)
            .title(strings.overwrite_title)
            .style(Style::default().fg(Color::Yellow));
        frame.render_widget(Clear, box_area);
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }).block(block), box_area);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn press(state: &mut OverwriteState, code: KeyCode) -> OverwriteChoice {
        state.handle_key(KeyEvent::from(code))
    }

    #[test]
    fn the_three_answers_map_to_the_obvious_keys() {
        let mut state = OverwriteState::new("a".into(), 1);
        assert_eq!(press(&mut state, KeyCode::Char('o')), OverwriteChoice::Overwrite);
        assert_eq!(press(&mut state, KeyCode::Enter), OverwriteChoice::Overwrite);
        assert_eq!(press(&mut state, KeyCode::Char('s')), OverwriteChoice::Skip);
        assert_eq!(press(&mut state, KeyCode::Esc), OverwriteChoice::Cancel);
    }

    /// With one conflict there is no "rest of the run" to apply anything to,
    /// so the toggle is inert rather than misleading.
    #[test]
    fn apply_to_all_is_only_offered_when_more_than_one_file_is_queued() {
        let mut single = OverwriteState::new("a".into(), 1);
        press(&mut single, KeyCode::Char('a'));
        assert!(!single.apply_to_all);

        let mut many = OverwriteState::new("a".into(), 4);
        assert_eq!(press(&mut many, KeyCode::Char('a')), OverwriteChoice::None, "the toggle is not an answer");
        assert!(many.apply_to_all);
        press(&mut many, KeyCode::Char('a'));
        assert!(!many.apply_to_all, "and it toggles back");
    }
}
