//! The first-run security mode chooser, and the same flow reused from settings
//! when the mode is changed later.
//!
//! Every mode ends in the same place — a master key wrapped by some set of
//! slots — so this screen's only job is collecting the inputs those slots need:
//! a password, a TOTP secret, or neither.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use zeroize::{Zeroize, Zeroizing};

use crate::i18n::Strings;
use crate::totp::{self, AuthMode};
use crate::tui::widgets::{centered_rect, mask, qr_lines};

const MIN_PASSWORD_LEN: usize = 8;

/// The modes in the order they are offered, weakest first.
const MODES: [AuthMode; 4] = [AuthMode::None, AuthMode::Password, AuthMode::PasswordTotp, AuthMode::TotpDaily];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Step {
    ChooseMode,
    /// Mode 1 only: a recovery password is optional there, so it is offered
    /// rather than demanded — but skipping it means a lost credential-store
    /// entry loses the vault, which the prompt says outright.
    OfferRecovery,
    Password,
    TotpEnroll,
}

pub enum SetupOutcome {
    None,
    Quit,
    /// Everything the caller needs to build the slot set.
    Create {
        mode: AuthMode,
        password: Option<Zeroizing<String>>,
        totp_secret: Option<String>,
    },
}

pub struct SetupState {
    step: Step,
    /// Modes 1 and 4 keep their key material in the OS credential store, so
    /// they are only offered when one is actually reachable. Not being able to
    /// reach one is shown as a reason, never as a silent downgrade.
    credential_store: bool,
    selected: usize,
    mode: AuthMode,
    password: String,
    confirm: String,
    focus_confirm: bool,
    want_recovery: bool,
    pending_secret: String,
    code: String,
    pub error: Option<String>,
}

impl SetupState {
    pub fn new(credential_store: bool) -> Self {
        Self {
            step: Step::ChooseMode,
            credential_store,
            // Land on "password only": the safe default that works everywhere.
            selected: 1,
            mode: AuthMode::Password,
            password: String::new(),
            confirm: String::new(),
            focus_confirm: false,
            want_recovery: true,
            pending_secret: String::new(),
            code: String::new(),
            error: None,
        }
    }

    fn mode_available(&self, mode: AuthMode) -> bool {
        match mode {
            AuthMode::None | AuthMode::TotpDaily => self.credential_store,
            AuthMode::Password | AuthMode::PasswordTotp => true,
        }
    }

    pub fn handle_key(&mut self, key: KeyEvent, strings: &Strings) -> SetupOutcome {
        if key.code == KeyCode::Esc {
            return SetupOutcome::Quit;
        }
        match self.step {
            Step::ChooseMode => self.handle_choose_mode(key, strings),
            Step::OfferRecovery => self.handle_offer_recovery(key),
            Step::Password => self.handle_password(key, strings),
            Step::TotpEnroll => self.handle_totp_enroll(key, strings),
        }
    }

    fn handle_choose_mode(&mut self, key: KeyEvent, strings: &Strings) -> SetupOutcome {
        match key.code {
            KeyCode::Up => self.selected = self.selected.saturating_sub(1),
            KeyCode::Down => self.selected = (self.selected + 1).min(MODES.len() - 1),
            KeyCode::Enter => {
                let mode = MODES[self.selected];
                if !self.mode_available(mode) {
                    self.error = Some(strings.setup_no_credential_store.to_string());
                    return SetupOutcome::None;
                }
                self.mode = mode;
                self.error = None;
                return self.advance_from_mode();
            }
            _ => {}
        }
        SetupOutcome::None
    }

    fn advance_from_mode(&mut self) -> SetupOutcome {
        match self.mode {
            AuthMode::None => {
                self.step = Step::OfferRecovery;
                SetupOutcome::None
            }
            _ => {
                self.step = Step::Password;
                SetupOutcome::None
            }
        }
    }

    fn handle_offer_recovery(&mut self, key: KeyEvent) -> SetupOutcome {
        match key.code {
            KeyCode::Left | KeyCode::Right | KeyCode::Up | KeyCode::Down => self.want_recovery = !self.want_recovery,
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                self.want_recovery = true;
                self.step = Step::Password;
            }
            KeyCode::Char('n') | KeyCode::Char('N') => {
                return SetupOutcome::Create { mode: AuthMode::None, password: None, totp_secret: None };
            }
            KeyCode::Enter => {
                if self.want_recovery {
                    self.step = Step::Password;
                } else {
                    return SetupOutcome::Create { mode: AuthMode::None, password: None, totp_secret: None };
                }
            }
            _ => {}
        }
        SetupOutcome::None
    }

    fn handle_password(&mut self, key: KeyEvent, strings: &Strings) -> SetupOutcome {
        match key.code {
            KeyCode::Tab | KeyCode::Up | KeyCode::Down => self.focus_confirm = !self.focus_confirm,
            KeyCode::Char(c) => {
                if self.focus_confirm {
                    self.confirm.push(c);
                } else {
                    self.password.push(c);
                }
            }
            KeyCode::Backspace => {
                if self.focus_confirm {
                    self.confirm.pop();
                } else {
                    self.password.pop();
                }
            }
            KeyCode::Enter => {
                if !self.focus_confirm {
                    self.focus_confirm = true;
                    return SetupOutcome::None;
                }
                if self.password.chars().count() < MIN_PASSWORD_LEN {
                    self.error = Some(strings.err_password_too_short.to_string());
                    return SetupOutcome::None;
                }
                if self.password != self.confirm {
                    self.error = Some(strings.err_passwords_dont_match.to_string());
                    return SetupOutcome::None;
                }
                self.error = None;
                return self.advance_from_password();
            }
            _ => {}
        }
        SetupOutcome::None
    }

    fn advance_from_password(&mut self) -> SetupOutcome {
        match self.mode {
            AuthMode::PasswordTotp | AuthMode::TotpDaily => {
                self.pending_secret = totp::generate_secret_base32();
                self.code.clear();
                self.step = Step::TotpEnroll;
                SetupOutcome::None
            }
            _ => self.finish(),
        }
    }

    fn handle_totp_enroll(&mut self, key: KeyEvent, strings: &Strings) -> SetupOutcome {
        match key.code {
            KeyCode::Char(c) if c.is_ascii_digit() && self.code.len() < 6 => self.code.push(c),
            KeyCode::Backspace => {
                self.code.pop();
            }
            KeyCode::Enter => {
                // Confirming a live code before anything is written is the only
                // thing standing between the user and a vault their
                // authenticator cannot open.
                if totp::verify_enrollment(&self.pending_secret, &self.code) {
                    self.error = None;
                    return self.finish();
                }
                self.error = Some(strings.err_totp_invalid_code.to_string());
                self.code.clear();
            }
            _ => {}
        }
        SetupOutcome::None
    }

    fn finish(&mut self) -> SetupOutcome {
        let password = if self.password.is_empty() {
            None
        } else {
            Some(Zeroizing::new(std::mem::take(&mut self.password)))
        };
        let totp_secret = match self.mode {
            AuthMode::PasswordTotp | AuthMode::TotpDaily => Some(std::mem::take(&mut self.pending_secret)),
            _ => None,
        };
        self.confirm.zeroize();
        SetupOutcome::Create { mode: self.mode, password, totp_secret }
    }

    pub fn render(&self, frame: &mut Frame, area: Rect, strings: &Strings) {
        match self.step {
            Step::ChooseMode => self.render_choose_mode(frame, area, strings),
            Step::OfferRecovery => self.render_offer_recovery(frame, area, strings),
            Step::Password => self.render_password(frame, area, strings),
            Step::TotpEnroll => self.render_totp_enroll(frame, area, strings),
        }
    }

    fn render_choose_mode(&self, frame: &mut Frame, area: Rect, strings: &Strings) {
        let mut lines = vec![Line::from(Span::styled(strings.setup_intro, Style::default().fg(Color::DarkGray))), Line::from("")];

        for (i, mode) in MODES.iter().enumerate() {
            let available = self.mode_available(*mode);
            let marker = if i == self.selected { "> " } else { "  " };
            let style = if !available {
                Style::default().fg(Color::DarkGray).add_modifier(Modifier::DIM)
            } else if i == self.selected {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };
            lines.push(Line::from(Span::styled(format!("{marker}{}", mode_title(*mode, strings)), style)));
            lines.push(Line::from(Span::styled(
                format!("    {}", mode_description(*mode, strings)),
                Style::default().fg(Color::DarkGray),
            )));
            if !available {
                lines.push(Line::from(Span::styled(
                    format!("    {}", strings.setup_needs_credential_store),
                    Style::default().fg(Color::Yellow),
                )));
            }
            lines.push(Line::from(""));
        }

        if let Some(err) = &self.error {
            lines.push(Line::from(Span::styled(err.clone(), Style::default().fg(Color::Red))));
        } else {
            lines.push(Line::from(Span::styled(strings.setup_choose_hint, Style::default().fg(Color::DarkGray))));
        }

        let height = (lines.len() as u16 + 2).min(area.height);
        let rect = centered_rect(76, height, area);
        let block = Block::default().borders(Borders::ALL).title(strings.setup_title);
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }).block(block), rect);
    }

    fn render_offer_recovery(&self, frame: &mut Frame, area: Rect, strings: &Strings) {
        let lines = vec![
            Line::from(Span::styled(strings.setup_recovery_warning, Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))),
            Line::from(""),
            Line::from(strings.setup_recovery_question),
            Line::from(""),
            Line::from(Span::styled(strings.setup_recovery_hint, Style::default().fg(Color::DarkGray))),
        ];
        let rect = centered_rect(70, lines.len() as u16 + 2, area);
        let block = Block::default().borders(Borders::ALL).title(strings.setup_recovery_title);
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }).block(block), rect);
    }

    fn render_password(&self, frame: &mut Frame, area: Rect, strings: &Strings) {
        let label = if self.mode == AuthMode::None { strings.setup_recovery_password_label } else { strings.setup_password_label };
        let cursor = |focused: bool| if focused { "_" } else { "" };

        let mut lines = vec![
            Line::from(format!("{label}: {}{}", mask(&self.password), cursor(!self.focus_confirm))),
            Line::from(format!("{}: {}{}", strings.unlock_confirm_label, mask(&self.confirm), cursor(self.focus_confirm))),
            Line::from(""),
        ];
        if let Some(err) = &self.error {
            lines.push(Line::from(Span::styled(err.clone(), Style::default().fg(Color::Red))));
        } else {
            lines.push(Line::from(Span::styled(strings.setup_password_hint, Style::default().fg(Color::DarkGray))));
        }

        let rect = centered_rect(64, lines.len() as u16 + 2, area);
        let block = Block::default().borders(Borders::ALL).title(mode_title(self.mode, strings));
        frame.render_widget(Paragraph::new(lines).block(block), rect);
    }

    fn render_totp_enroll(&self, frame: &mut Frame, area: Rect, strings: &Strings) {
        let qr = qr_lines(&totp::otpauth_url(&self.pending_secret).unwrap_or_default());
        let qr_height = qr.len() as u16 + 1;

        let top = vec![
            Line::from(format!("{}: {}", strings.tf_secret_label, self.pending_secret)),
            Line::from(Span::styled(strings.tf_scan_hint, Style::default().fg(Color::DarkGray))),
        ];

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(4), Constraint::Length(qr_height), Constraint::Length(4)])
            .split(area);

        let block = Block::default().borders(Borders::ALL).title(mode_title(self.mode, strings));
        frame.render_widget(Paragraph::new(top).wrap(Wrap { trim: true }).block(block), chunks[0]);
        frame.render_widget(Paragraph::new(qr), chunks[1]);

        let mut bottom = vec![Line::from(format!("{}: {}_", strings.totp_code_label, self.code))];
        if let Some(err) = &self.error {
            bottom.push(Line::from(Span::styled(err.clone(), Style::default().fg(Color::Red))));
        } else {
            bottom.push(Line::from(Span::styled(strings.tf_verify_hint, Style::default().fg(Color::DarkGray))));
        }
        frame.render_widget(Paragraph::new(bottom).block(Block::default().borders(Borders::ALL)), chunks[2]);
    }
}

pub fn mode_title(mode: AuthMode, strings: &Strings) -> &'static str {
    match mode {
        AuthMode::None => strings.mode_none_title,
        AuthMode::Password => strings.mode_password_title,
        AuthMode::PasswordTotp => strings.mode_password_totp_title,
        AuthMode::TotpDaily => strings.mode_totp_daily_title,
    }
}

pub fn mode_description(mode: AuthMode, strings: &Strings) -> &'static str {
    match mode {
        AuthMode::None => strings.mode_none_description,
        AuthMode::Password => strings.mode_password_description,
        AuthMode::PasswordTotp => strings.mode_password_totp_description,
        AuthMode::TotpDaily => strings.mode_totp_daily_description,
    }
}

/// The dead end: a mode-1 vault carried to a machine that has no device key for
/// it and no recovery password to fall back on. Says so plainly instead of
/// offering a prompt that could never succeed.
pub fn render_unopenable(frame: &mut Frame, area: Rect, strings: &Strings) {
    let lines = vec![
        Line::from(Span::styled(strings.unopenable_message, Style::default().fg(Color::Red))),
    ];
    let rect = centered_rect(70, 10, area);
    let block = Block::default().borders(Borders::ALL).title(strings.unopenable_title);
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }).block(block), rect);
}
