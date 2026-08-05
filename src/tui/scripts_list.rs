use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};
use uuid::Uuid;

use crate::config::Script;
use crate::i18n::Strings;

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
            .constraints([Constraint::Min(3), Constraint::Length(3)])
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

        let title = format!(" {} — {} ", strings.scripts_list_title, self.server_name);
        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title(title))
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
            .highlight_symbol("> ");

        frame.render_stateful_widget(list, chunks[0], &mut self.list_state);

        let help_text = status
            .map(|s| Line::from(Span::styled(s.to_string(), Style::default().fg(Color::Yellow))))
            .unwrap_or_else(|| Line::from(strings.scripts_list_hint));
        let help = Paragraph::new(help_text).block(Block::default().borders(Borders::ALL));
        frame.render_widget(help, chunks[1]);
    }
}
