use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};
use uuid::Uuid;

use crate::config::Script;
use crate::i18n::Strings;
use crate::tui::theme;
use crate::tui::widgets::{list_title_with_position, render_list_scrollbar};

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
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            // 4, not 3: two borders plus room for both the status line and the
            // hint that now sit under each other.
            .constraints([Constraint::Min(3), Constraint::Length(4)])
            .split(area);

        let items: Vec<ListItem> = if scripts.is_empty() {
            vec![ListItem::new(strings.scripts_list_empty)]
        } else {
            scripts
                .iter()
                .map(|s| {
                    let run_marker = if s.run_on_connect { " [auto]" } else { "" };
                    ListItem::new(format!("{}  ({} steps){run_marker}", s.name, s.steps.len()))
                })
                .collect()
        };

        let title = list_title_with_position(
            &format!(" {} — {} ", strings.scripts_list_title, self.server_name),
            self.selected,
            scripts.len(),
        );
        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title(title))
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
            .highlight_symbol("> ");

        frame.render_stateful_widget(list, chunks[0], &mut self.list_state);
        render_list_scrollbar(frame, chunks[0], self.selected, scripts.len());

        // The status goes on its own line and the hint is always pushed, so a
        // "Saved." never takes the keybindings away — which is exactly when
        // someone still learning the screen needs them most.
        let mut help_text = Vec::new();

        if let Some(s) = status {
            help_text.push(Line::from(Span::styled(s.to_string(), Style::default().fg(theme::warning()))));
        }
        help_text.push(Line::from(strings.scripts_list_hint));

        let help = Paragraph::new(help_text).block(Block::default().borders(Borders::ALL));
        frame.render_widget(help, chunks[1]);
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
