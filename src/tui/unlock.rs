use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use zeroize::Zeroizing;

use super::widgets::{centered_rect, mask};
use crate::i18n::Strings;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum UnlockMode {
    FirstRun,
    Unlock,
    /// A vault carried over from the old TOTP-only mode. Behaves like
    /// `FirstRun` — the user is setting a password that does not exist yet —
    /// but says why it is being asked, since from the user's point of view the
    /// app has suddenly started demanding something it never did before.
    MigrateTotpOnly,
}

impl UnlockMode {
    /// Whether this mode is collecting a *new* password (two fields, length and
    /// match checks) rather than trying an existing one.
    fn is_new_password(self) -> bool {
        matches!(self, Self::FirstRun | Self::MigrateTotpOnly)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Focus {
    Password,
    Confirm,
}

pub struct UnlockState {
    pub mode: UnlockMode,
    password: Zeroizing<String>,
    confirm: Zeroizing<String>,
    focus: Focus,
    pub error: Option<String>,
    /// Non-failure notice shown in place of the hint — currently only "the
    /// vault auto-locked", which is not an error and must not be red.
    pub info: Option<String>,
}

pub enum UnlockOutcome {
    None,
    /// First-run: the password to set as the new master password.
    SetPassword(Zeroizing<String>),
    /// Unlock: the password to try against the existing config.
    TryPassword(Zeroizing<String>),
    Quit,
}

impl UnlockState {
    pub fn new(mode: UnlockMode) -> Self {
        Self {
            mode,
            password: Zeroizing::new(String::new()),
            confirm: Zeroizing::new(String::new()),
            focus: Focus::Password,
            error: None,
            info: None,
        }
    }

    pub fn handle_key(&mut self, key: KeyEvent, strings: &Strings) -> UnlockOutcome {
        self.error = None;
        self.info = None;
        match key.code {
            KeyCode::Esc => return UnlockOutcome::Quit,
            KeyCode::Tab | KeyCode::Down if self.mode.is_new_password() => {
                self.focus = match self.focus {
                    Focus::Password => Focus::Confirm,
                    Focus::Confirm => Focus::Password,
                };
            }
            KeyCode::Up if self.mode.is_new_password() => {
                self.focus = match self.focus {
                    Focus::Password => Focus::Confirm,
                    Focus::Confirm => Focus::Password,
                };
            }
            KeyCode::Backspace => {
                self.active_buffer_mut().pop();
            }
            KeyCode::Char(c) => {
                self.active_buffer_mut().push(c);
            }
            KeyCode::Enter => {
                return self.submit(strings);
            }
            _ => {}
        }
        UnlockOutcome::None
    }

    fn active_buffer_mut(&mut self) -> &mut Zeroizing<String> {
        match self.focus {
            Focus::Confirm if self.mode.is_new_password() => &mut self.confirm,
            _ => &mut self.password,
        }
    }

    fn submit(&mut self, strings: &Strings) -> UnlockOutcome {
        match self.mode {
            UnlockMode::Unlock => {
                if self.password.is_empty() {
                    self.error = Some(strings.err_password_empty.to_string());
                    return UnlockOutcome::None;
                }
                UnlockOutcome::TryPassword(std::mem::replace(&mut self.password, Zeroizing::new(String::new())))
            }
            UnlockMode::FirstRun | UnlockMode::MigrateTotpOnly => {
                if self.password.len() < 8 {
                    self.error = Some(strings.err_password_too_short.to_string());
                    return UnlockOutcome::None;
                }
                if *self.password != *self.confirm {
                    self.error = Some(strings.err_passwords_dont_match.to_string());
                    self.confirm.clear();
                    return UnlockOutcome::None;
                }
                UnlockOutcome::SetPassword(std::mem::replace(&mut self.password, Zeroizing::new(String::new())))
            }
        }
    }

    pub fn render(&self, frame: &mut Frame, area: Rect, strings: &Strings) {
        // The migration screen carries a paragraph explaining why a password is
        // suddenly being asked for, so it needs noticeably more room.
        let (width, height) = match self.mode {
            UnlockMode::MigrateTotpOnly => (72, 16),
            UnlockMode::FirstRun => (50, 10),
            UnlockMode::Unlock => (50, 8),
        };
        let box_area = centered_rect(width, height, area);

        let title = match self.mode {
            UnlockMode::FirstRun => strings.unlock_title_first_run,
            UnlockMode::Unlock => strings.unlock_title_unlock,
            UnlockMode::MigrateTotpOnly => strings.migrate_totp_only_title,
        };

        let mut lines = Vec::new();
        if self.mode == UnlockMode::MigrateTotpOnly {
            lines.push(Line::from(Span::styled(strings.migrate_totp_only_message, Style::default().fg(Color::Yellow))));
        }
        lines.extend([
            Line::from(""),
            Line::from(vec![
                Span::raw(format!("{}: ", strings.unlock_password_label)),
                Span::raw(mask(&self.password)),
                Span::styled(
                    if self.focus == Focus::Password { "_" } else { "" },
                    Style::default(),
                ),
            ]),
        ]);

        if self.mode.is_new_password() {
            lines.push(Line::from(vec![
                Span::raw(format!("{}: ", strings.unlock_confirm_label)),
                Span::raw(mask(&self.confirm)),
                Span::styled(
                    if self.focus == Focus::Confirm { "_" } else { "" },
                    Style::default(),
                ),
            ]));
        }

        lines.push(Line::from(""));
        if let Some(err) = &self.error {
            lines.push(Line::from(Span::styled(err.clone(), Style::default().fg(Color::Red))));
        } else if let Some(info) = &self.info {
            lines.push(Line::from(Span::styled(info.clone(), Style::default().fg(Color::Yellow))));
        } else {
            lines.push(Line::from(Span::styled(
                strings.unlock_hint,
                Style::default().fg(Color::DarkGray),
            )));
        }

        let block = Block::default().borders(Borders::ALL).title(title);
        let paragraph = Paragraph::new(lines).wrap(Wrap { trim: false }).block(block);
        frame.render_widget(paragraph, box_area);
    }
}
