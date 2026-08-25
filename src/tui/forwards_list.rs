//! The port forwards on one server.
//!
//! Modelled on `scripts_list`, because it is the same shape: a per-server list
//! with add, edit and delete, reached from the server list and returning to it.
//! The one addition is Space, which turns a rule off without deleting it —
//! deleting a rule to stop it for an afternoon means retyping four fields to
//! get it back.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{ListItem, ListState};
use uuid::Uuid;

use crate::config::ForwardRule;
use crate::i18n::Strings;
use crate::tui::chrome;
use crate::tui::theme;
use crate::tui::widgets::{self, list_title_with_position, render_list_scrollbar};

pub struct ForwardsListState {
    pub server_id: Uuid,
    pub server_name: String,
    selected: usize,
    list_state: ListState,
}

pub enum ForwardsListAction {
    None,
    Add,
    Edit(Uuid),
    Delete(Uuid),
    /// Flip `enabled` on this rule and save.
    Toggle(Uuid),
    Back,
    Help,
}

impl ForwardsListState {
    pub fn new(server_id: Uuid, server_name: String) -> Self {
        let mut list_state = ListState::default();
        list_state.select(Some(0));
        Self { server_id, server_name, selected: 0, list_state }
    }

    /// Keeps the selection inside a list that just got shorter.
    pub fn clamp_selection(&mut self, forwards: &[ForwardRule]) {
        self.selected = self.selected.min(forwards.len().saturating_sub(1));
        self.list_state.select(Some(self.selected));
    }

    fn selected_id(&self, forwards: &[ForwardRule]) -> Option<Uuid> {
        forwards.get(self.selected).map(|f| f.id)
    }

    pub fn handle_key(&mut self, key: KeyEvent, forwards: &[ForwardRule]) -> ForwardsListAction {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                if self.selected > 0 {
                    self.selected -= 1;
                    self.list_state.select(Some(self.selected));
                }
                ForwardsListAction::None
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.selected + 1 < forwards.len() {
                    self.selected += 1;
                    self.list_state.select(Some(self.selected));
                }
                ForwardsListAction::None
            }
            KeyCode::Char('a') => ForwardsListAction::Add,
            KeyCode::Char('e') | KeyCode::Enter => {
                self.selected_id(forwards).map(ForwardsListAction::Edit).unwrap_or(ForwardsListAction::None)
            }
            KeyCode::Char('d') => self.selected_id(forwards).map(ForwardsListAction::Delete).unwrap_or(ForwardsListAction::None),
            KeyCode::Char(' ') => self.selected_id(forwards).map(ForwardsListAction::Toggle).unwrap_or(ForwardsListAction::None),
            KeyCode::Char('?') => ForwardsListAction::Help,
            KeyCode::Esc | KeyCode::Char('q') => ForwardsListAction::Back,
            _ => ForwardsListAction::None,
        }
    }

    pub fn render(&mut self, frame: &mut Frame, area: Rect, forwards: &[ForwardRule], status: Option<&str>, strings: &Strings) {
        let mut footer = vec![Line::from(Span::styled(strings.forwards_hint, Style::default().fg(theme::hint())))];
        if let Some(status) = status {
            footer.insert(0, Line::from(Span::styled(status.to_string(), Style::default().fg(theme::success()))));
        }
        let body = chrome::render(frame, area, strings.forwards_title, footer, strings);

        let items: Vec<ListItem> = forwards
            .iter()
            .map(|rule| {
                // A disabled rule is dim throughout and says so, rather than
                // being distinguished only by a marker the eye has to hunt for.
                let style = if rule.enabled {
                    Style::default().add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(theme::hint())
                };
                let mut spans = vec![Span::styled(rule.label(), style)];
                if !rule.enabled {
                    spans.push(Span::styled(format!("  ({})", strings.forward_disabled_label), Style::default().fg(theme::hint())));
                }
                ListItem::new(Line::from(spans))
            })
            .collect();

        let title = list_title_with_position(
            &format!(" {} — {} ", strings.forwards_title.trim(), self.server_name),
            self.selected,
            forwards.len(),
        );
        widgets::render_list(frame, body, &title, items, &mut self.list_state, Some(strings.forwards_empty), None, true);
        render_list_scrollbar(frame, body, self.selected, forwards.len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ForwardKind;

    fn rules() -> Vec<ForwardRule> {
        vec![
            ForwardRule::new(ForwardKind::Local {
                bind_addr: "127.0.0.1".into(),
                bind_port: 8080,
                dest_host: "db.internal".into(),
                dest_port: 5432,
            }),
            ForwardRule::new(ForwardKind::Dynamic { bind_addr: "127.0.0.1".into(), bind_port: 1080 }),
        ]
    }

    fn press(state: &mut ForwardsListState, forwards: &[ForwardRule], code: KeyCode) -> ForwardsListAction {
        state.handle_key(KeyEvent::from(code), forwards)
    }

    /// Space is the reason this screen is not just add/edit/delete: turning a
    /// rule off has to be cheaper than deleting and retyping it.
    #[test]
    fn space_toggles_the_selected_rule_rather_than_deleting_it() {
        let forwards = rules();
        let mut state = ForwardsListState::new(Uuid::new_v4(), "web".into());
        press(&mut state, &forwards, KeyCode::Down);
        match press(&mut state, &forwards, KeyCode::Char(' ')) {
            ForwardsListAction::Toggle(id) => assert_eq!(id, forwards[1].id),
            _ => panic!("space must toggle"),
        }
    }

    #[test]
    fn an_empty_list_has_nothing_to_edit_or_delete() {
        let mut state = ForwardsListState::new(Uuid::new_v4(), "web".into());
        assert!(matches!(press(&mut state, &[], KeyCode::Char('e')), ForwardsListAction::None));
        assert!(matches!(press(&mut state, &[], KeyCode::Char('d')), ForwardsListAction::None));
        // But adding the first one must still be reachable.
        assert!(matches!(press(&mut state, &[], KeyCode::Char('a')), ForwardsListAction::Add));
    }

    #[test]
    fn the_selection_survives_the_list_getting_shorter() {
        let forwards = rules();
        let mut state = ForwardsListState::new(Uuid::new_v4(), "web".into());
        press(&mut state, &forwards, KeyCode::Down);
        state.clamp_selection(&forwards[..1]);
        assert_eq!(state.selected_id(&forwards[..1]), Some(forwards[0].id));
    }
}
