use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{ListItem, ListState};
use uuid::Uuid;

use crate::config::Script;
use crate::i18n::Strings;
use crate::tui::chrome;
use crate::tui::theme;
use crate::tui::widgets::{self, list_title_with_position, render_list_scrollbar};

pub struct ScriptsListState {
    pub server_id: Uuid,
    pub server_name: String,
    selected: usize,
    list_state: ListState,
}

pub enum ScriptsListAction {
    None,
    Run(Uuid),
    Add,
    Edit(Uuid),
    Delete(Uuid),
    Back,
    Help,
}

impl ScriptsListState {
    pub fn new(server_id: Uuid, server_name: String) -> Self {
        let mut list_state = ListState::default();
        list_state.select(Some(0));
        Self { server_id, server_name, selected: 0, list_state }
    }

    pub fn handle_key(&mut self, key: KeyEvent, scripts: &[Script]) -> ScriptsListAction {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                if self.selected > 0 {
                    self.selected -= 1;
                    self.list_state.select(Some(self.selected));
                }
                ScriptsListAction::None
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if !scripts.is_empty() && self.selected + 1 < scripts.len() {
                    self.selected += 1;
                    self.list_state.select(Some(self.selected));
                }
                ScriptsListAction::None
            }
            KeyCode::Enter => scripts
                .get(self.selected)
                .map(|s| ScriptsListAction::Run(s.id))
                .unwrap_or(ScriptsListAction::None),
            KeyCode::Char('a') => ScriptsListAction::Add,
            KeyCode::Char('e') => scripts
                .get(self.selected)
                .map(|s| ScriptsListAction::Edit(s.id))
                .unwrap_or(ScriptsListAction::None),
            KeyCode::Char('d') => scripts
                .get(self.selected)
                .map(|s| ScriptsListAction::Delete(s.id))
                .unwrap_or(ScriptsListAction::None),
            KeyCode::Char('?') => ScriptsListAction::Help,
            KeyCode::Esc => ScriptsListAction::Back,
            _ => ScriptsListAction::None,
        }
    }

    /// Clamps the selection after the script list changes (add/delete).
    pub fn clamp_selection(&mut self, scripts: &[Script]) {
        if scripts.is_empty() {
            self.selected = 0;
        } else if self.selected >= scripts.len() {
            self.selected = scripts.len() - 1;
        }
        self.list_state.select(Some(self.selected));
    }

    pub fn render(&mut self, frame: &mut Frame, area: Rect, scripts: &[Script], status: Option<&str>, strings: &Strings) {
        // The status goes on its own line and the hint is always pushed, so a
        // "Saved." never takes the keybindings away — which is exactly when
        // someone still learning the screen needs them most.
        let mut footer = Vec::new();
        if let Some(s) = status {
            footer.push(Line::from(Span::styled(s.to_string(), Style::default().fg(theme::warning()))));
        }
        footer.push(Line::from(Span::styled(strings.scripts_list_hint, Style::default().fg(theme::hint()))));

        let body = chrome::render(frame, area, strings.scripts_list_title, footer, strings);

        let items: Vec<ListItem> = scripts
            .iter()
            .map(|s| {
                let run_marker = if s.run_on_connect { " [auto]" } else { "" };
                ListItem::new(format!("{}  ({} steps){run_marker}", s.name, s.steps.len()))
            })
            .collect();

        let title = list_title_with_position(
            &format!(" {} — {} ", strings.scripts_list_title.trim(), self.server_name),
            self.selected,
            scripts.len(),
        );
        widgets::render_list(frame, body, &title, items, &mut self.list_state, Some(strings.scripts_list_empty), None, true);
        render_list_scrollbar(frame, body, self.selected, scripts.len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::EN;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn render_to_string(status: Option<&str>) -> String {
        let scripts = vec![Script {
            id: Uuid::new_v4(),
            name: "deploy".to_string(),
            run_on_connect: false,
            steps: Vec::new(),
        }];
        let mut state = ScriptsListState::new(Uuid::new_v4(), "web-1".to_string());
        let mut terminal = Terminal::new(TestBackend::new(100, 20)).expect("test backend");
        terminal
            .draw(|frame| state.render(frame, frame.area(), &scripts, status, &EN))
            .expect("render");
        terminal.backend().buffer().content().iter().map(|c| c.symbol()).collect()
    }

    /// The bug: the footer used to render the status *or* the hint, so the keys
    /// vanished the moment an action landed — exactly when someone still
    /// learning the screen needs them.
    #[test]
    fn a_status_message_does_not_take_the_keybindings_away() {
        let with_status = render_to_string(Some(EN.status_saved));

        assert!(with_status.contains(EN.status_saved), "the status should be shown");
        // A single distinctive token: the hint is one long line, and the buffer
        // is row-major over the whole terminal, so phrases straddle rows.
        assert!(with_status.contains("Esc:"), "the hint must survive alongside it");
    }

    #[test]
    fn the_hint_is_shown_when_there_is_no_status() {
        let without = render_to_string(None);

        assert!(without.contains("Esc:"));
        assert!(!without.contains(EN.status_saved));
    }
}
