use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use super::widgets::centered_rect;
use crate::i18n::Strings;

/// Full unlock screen for "TOTP-only" mode vaults — no password is ever
/// asked; the live 6-digit code is the only input.
pub struct TotpUnlockState {
    code: String,
    pub error: Option<String>,
    /// Non-failure notice shown in place of the hint — currently only "the
    /// vault auto-locked", which is not an error and must not be red.
    pub info: Option<String>,
}

pub enum TotpUnlockOutcome {
    None,
    Submit(String),
    Quit,
}

impl Default for TotpUnlockState {
    fn default() -> Self {
        Self::new()
    }
}

impl TotpUnlockState {
    pub fn new() -> Self {
        Self { code: String::new(), error: None, info: None }
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> TotpUnlockOutcome {
        self.error = None;
        self.info = None;
        match key.code {
            KeyCode::Esc => return TotpUnlockOutcome::Quit,
            KeyCode::Backspace => {
                self.code.pop();
            }
            KeyCode::Char(c) if c.is_ascii_digit() && self.code.len() < 6 => self.code.push(c),
            KeyCode::Enter if self.code.len() == 6 => {
                return TotpUnlockOutcome::Submit(std::mem::take(&mut self.code));
            }
            _ => {}
        }
        TotpUnlockOutcome::None
    }

    pub fn render(&self, frame: &mut Frame, area: Rect, strings: &Strings) {
        let box_area = centered_rect(46, 8, area);
        let mut lines = vec![Line::from(""), Line::from(format!("{}: {}_", strings.totp_code_label, self.code)), Line::from("")];

        if let Some(err) = &self.error {
            lines.push(Line::from(Span::styled(err.clone(), Style::default().fg(Color::Red))));
        } else if let Some(info) = &self.info {
            lines.push(Line::from(Span::styled(info.clone(), Style::default().fg(Color::Yellow))));
        } else {
            lines.push(Line::from(Span::styled(strings.totp_unlock_hint, Style::default().fg(Color::DarkGray))));
        }

        let block = Block::default().borders(Borders::ALL).title(strings.totp_unlock_title);
        frame.render_widget(Paragraph::new(lines).block(block), box_area);
    }
}
