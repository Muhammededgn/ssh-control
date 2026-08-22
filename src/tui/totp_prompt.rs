use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use super::widgets::centered_rect;
use crate::i18n::Strings;
use crate::tui::theme;

/// Second-factor prompt shown after a successful master-password unlock, when
/// the vault has "Password + TOTP (2FA)" enabled. Esc re-locks the whole app
/// rather than merely cancelling — no half-authenticated state is left around.
pub struct TotpPromptState {
    code: String,
    pub error: Option<String>,
}

pub enum TotpPromptOutcome {
    None,
    Submit(String),
    Cancel,
}

impl Default for TotpPromptState {
    fn default() -> Self {
        Self::new()
    }
}

impl TotpPromptState {
    pub fn new() -> Self {
        Self { code: String::new(), error: None }
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> TotpPromptOutcome {
        self.error = None;
        match key.code {
            KeyCode::Esc => return TotpPromptOutcome::Cancel,
            KeyCode::Backspace => {
                self.code.pop();
            }
            KeyCode::Char(c) if c.is_ascii_digit() && self.code.len() < 6 => self.code.push(c),
            KeyCode::Enter if self.code.len() == 6 => {
                return TotpPromptOutcome::Submit(std::mem::take(&mut self.code));
            }
            _ => {}
        }
        TotpPromptOutcome::None
    }

    pub fn render(&self, frame: &mut Frame, area: Rect, strings: &Strings) {
        let box_area = centered_rect(46, 7, area);
        let mut lines = vec![Line::from(""), Line::from(format!("{}: {}_", strings.totp_code_label, self.code)), Line::from("")];

        if let Some(err) = &self.error {
            lines.push(Line::from(Span::styled(err.clone(), Style::default().fg(theme::error()))));
        } else {
            lines.push(Line::from(Span::styled(strings.totp_prompt_hint, Style::default().fg(theme::hint()))));
        }

        let block = Block::default().borders(Borders::ALL).title(strings.totp_prompt_title);
        frame.render_widget(Paragraph::new(lines).block(block), box_area);
    }
}
