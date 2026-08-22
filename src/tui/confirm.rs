use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::Line;
use ratatui::widgets::Paragraph;

use super::widgets::{self, centered_rect};
use crate::i18n::Strings;
use crate::tui::theme;

/// Generic reusable yes/no confirmation overlay.
pub struct ConfirmState {
    pub message: String,
}

pub enum ConfirmOutcome {
    None,
    Yes,
    No,
}

impl ConfirmState {
    pub fn new(message: String) -> Self {
        Self { message }
    }

    pub fn handle_key(&self, key: KeyEvent) -> ConfirmOutcome {
        match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => ConfirmOutcome::Yes,
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => ConfirmOutcome::No,
            _ => ConfirmOutcome::None,
        }
    }

    pub fn render(&self, frame: &mut Frame, area: Rect, strings: &Strings) {
        let box_area = centered_rect(50, 5, area);
        let hint = ratatui::text::Span::styled(strings.confirm_hint, Style::default().fg(theme::hint()));
        let lines = vec![Line::from(self.message.clone()), Line::from(""), Line::from(hint)];
        // The border carries the alarm; the message stays body text. A whole
        // box in `error()` made the name being deleted harder to read, which is
        // the one thing the dialog exists to show.
        let block = widgets::modal(strings.confirm_title).border_style(Style::default().fg(theme::error()));
        let paragraph = Paragraph::new(lines).block(block);
        frame.render_widget(paragraph, box_area);
    }
}
