use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use qrcode::QrCode;
use qrcode::render::unicode;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use zeroize::Zeroizing;

use super::widgets::mask;
use crate::i18n::{Lang, Strings};
use crate::totp::{self, AuthMode};

const LANGS: [Lang; 4] = [Lang::En, Lang::Tr, Lang::Es, Lang::Ru];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Language,
    Password,
    TwoFactor,
}

const TABS: [Tab; 3] = [Tab::Language, Tab::Password, Tab::TwoFactor];

#[derive(Clone, Copy, PartialEq, Eq)]
enum PwField {
    Current,
    New,
    Confirm,
}

const PW_FIELDS: [PwField; 3] = [PwField::Current, PwField::New, PwField::Confirm];

#[derive(Clone, Copy, PartialEq, Eq)]
enum TwoFactorView {
    Overview,
    SetupTwoFactor,
    SetupTotpOnly,
    ConfirmDisableTwoFactor,
    SwitchToPasswordForm,
}

/// F1 settings screen: a right-hand sidebar lists tabs (Language, Master
/// Password, Two-Factor); the main area to its left shows the selected tab's
/// content.
pub struct SettingsState {
    tab: Tab,
    lang_list_state: ListState,
    lang_selected: usize,
    pw_focus: PwField,
    current_password: Zeroizing<String>,
    new_password: Zeroizing<String>,
    confirm_password: Zeroizing<String>,
    pub error: Option<String>,
    pub info: Option<String>,

    // Two-Factor tab
    auth_mode: AuthMode,
    tf_view: TwoFactorView,
    tf_selected: usize,
    pending_secret: String,
    tf_code: String,
    switch_new_password: Zeroizing<String>,
    switch_confirm_password: Zeroizing<String>,
    switch_focus_new: bool,
}

pub enum SettingsOutcome {
    None,
    Close,
    LanguageSelected(Lang),
    ChangePassword { current: Zeroizing<String>, new: Zeroizing<String> },
    EnableTwoFactor { secret_base32: String },
    DisableTwoFactor,
    EnableTotpOnly { secret_base32: String },
    SwitchToPassword { new: Zeroizing<String> },
}

impl SettingsState {
    /// Called by the app after a successful mode transition (enable/disable
    /// 2FA, switch to/from TOTP-only) so the Overview sub-view immediately
    /// reflects the new mode without requiring the user to close and reopen
    /// Settings.
    pub fn set_auth_mode(&mut self, auth_mode: AuthMode) {
        self.auth_mode = auth_mode;
        self.tf_selected = 0;
    }

    pub fn new(current_lang: Lang, auth_mode: AuthMode) -> Self {
        let lang_selected = LANGS.iter().position(|l| *l == current_lang).unwrap_or(0);
        let mut lang_list_state = ListState::default();
        lang_list_state.select(Some(lang_selected));

        Self {
            tab: Tab::Language,
            lang_list_state,
            lang_selected,
            pw_focus: PwField::Current,
            current_password: Zeroizing::new(String::new()),
            new_password: Zeroizing::new(String::new()),
            confirm_password: Zeroizing::new(String::new()),
            error: None,
            info: None,

            auth_mode,
            tf_view: TwoFactorView::Overview,
            tf_selected: 0,
            pending_secret: String::new(),
            tf_code: String::new(),
            switch_new_password: Zeroizing::new(String::new()),
            switch_confirm_password: Zeroizing::new(String::new()),
            switch_focus_new: true,
        }
    }

    pub fn handle_key(&mut self, key: KeyEvent, strings: &Strings) -> SettingsOutcome {
        match key.code {
            KeyCode::Esc if self.tab == Tab::TwoFactor && self.tf_view != TwoFactorView::Overview => {
                self.tf_view = TwoFactorView::Overview;
                self.error = None;
                self.info = None;
                return SettingsOutcome::None;
            }
            KeyCode::Esc => return SettingsOutcome::Close,
            KeyCode::Left | KeyCode::Right
                if !(self.tab == Tab::TwoFactor && self.tf_view != TwoFactorView::Overview) =>
            {
                self.tab = match self.tab {
                    Tab::Language => Tab::Password,
                    Tab::Password => Tab::TwoFactor,
                    Tab::TwoFactor => Tab::Language,
                };
                self.error = None;
                self.info = None;
                return SettingsOutcome::None;
            }
            _ => {}
        }

        match self.tab {
            Tab::Language => self.handle_language_key(key),
            Tab::Password => self.handle_password_key(key, strings),
            Tab::TwoFactor => self.handle_two_factor_key(key, strings),
        }
    }

    fn handle_language_key(&mut self, key: KeyEvent) -> SettingsOutcome {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                if self.lang_selected > 0 {
                    self.lang_selected -= 1;
                    self.lang_list_state.select(Some(self.lang_selected));
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.lang_selected + 1 < LANGS.len() {
                    self.lang_selected += 1;
                    self.lang_list_state.select(Some(self.lang_selected));
                }
            }
            KeyCode::Enter => return SettingsOutcome::LanguageSelected(LANGS[self.lang_selected]),
            _ => {}
        }
        SettingsOutcome::None
    }

    fn handle_password_key(&mut self, key: KeyEvent, strings: &Strings) -> SettingsOutcome {
        self.error = None;
        self.info = None;
        match key.code {
            KeyCode::Tab => self.move_pw_focus(1),
            KeyCode::BackTab => self.move_pw_focus(-1),
            KeyCode::Backspace => {
                self.active_pw_buffer_mut().pop();
            }
            KeyCode::Char(c) => {
                self.active_pw_buffer_mut().push(c);
            }
            KeyCode::Enter if key.modifiers.contains(KeyModifiers::CONTROL) => {
                return self.submit_password(strings);
            }
            KeyCode::Enter => {
                if self.pw_focus == PwField::Confirm {
                    return self.submit_password(strings);
                }
                self.move_pw_focus(1);
            }
            _ => {}
        }
        SettingsOutcome::None
    }

    fn move_pw_focus(&mut self, delta: i32) {
        let idx = PW_FIELDS.iter().position(|f| *f == self.pw_focus).unwrap_or(0);
        let len = PW_FIELDS.len() as i32;
        let next = (idx as i32 + delta).rem_euclid(len) as usize;
        self.pw_focus = PW_FIELDS[next];
    }

    fn active_pw_buffer_mut(&mut self) -> &mut Zeroizing<String> {
        match self.pw_focus {
            PwField::Current => &mut self.current_password,
            PwField::New => &mut self.new_password,
            PwField::Confirm => &mut self.confirm_password,
        }
    }

    fn submit_password(&mut self, strings: &Strings) -> SettingsOutcome {
        if self.new_password.len() < 8 {
            self.error = Some(strings.err_password_too_short.to_string());
            return SettingsOutcome::None;
        }
        if *self.new_password != *self.confirm_password {
            self.error = Some(strings.err_passwords_dont_match.to_string());
            self.confirm_password.clear();
            return SettingsOutcome::None;
        }

        let current = std::mem::replace(&mut self.current_password, Zeroizing::new(String::new()));
        let new = std::mem::replace(&mut self.new_password, Zeroizing::new(String::new()));
        self.confirm_password.clear();
        SettingsOutcome::ChangePassword { current, new }
    }

    fn overview_action_count(&self) -> usize {
        match self.auth_mode {
            AuthMode::Password => 2,
            AuthMode::TwoFactor => 1,
            AuthMode::TotpOnly => 1,
        }
    }

    fn handle_two_factor_key(&mut self, key: KeyEvent, strings: &Strings) -> SettingsOutcome {
        match self.tf_view {
            TwoFactorView::Overview => self.handle_tf_overview_key(key),
            TwoFactorView::SetupTwoFactor => self.handle_tf_setup_key(key, strings, false),
            TwoFactorView::SetupTotpOnly => self.handle_tf_setup_key(key, strings, true),
            TwoFactorView::ConfirmDisableTwoFactor => self.handle_tf_confirm_disable_key(key),
            TwoFactorView::SwitchToPasswordForm => self.handle_tf_switch_form_key(key, strings),
        }
    }

    fn handle_tf_overview_key(&mut self, key: KeyEvent) -> SettingsOutcome {
        self.error = None;
        self.info = None;
        let count = self.overview_action_count();
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                if self.tf_selected > 0 {
                    self.tf_selected -= 1;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.tf_selected + 1 < count {
                    self.tf_selected += 1;
                }
            }
            KeyCode::Enter => match (self.auth_mode, self.tf_selected) {
                (AuthMode::Password, 0) => self.begin_setup(TwoFactorView::SetupTwoFactor),
                (AuthMode::Password, 1) => self.begin_setup(TwoFactorView::SetupTotpOnly),
                (AuthMode::TwoFactor, 0) => self.tf_view = TwoFactorView::ConfirmDisableTwoFactor,
                (AuthMode::TotpOnly, 0) => {
                    self.switch_new_password = Zeroizing::new(String::new());
                    self.switch_confirm_password = Zeroizing::new(String::new());
                    self.switch_focus_new = true;
                    self.tf_view = TwoFactorView::SwitchToPasswordForm;
                }
                _ => {}
            },
            _ => {}
        }
        SettingsOutcome::None
    }

    fn begin_setup(&mut self, view: TwoFactorView) {
        self.pending_secret = totp::generate_secret_base32();
        self.tf_code.clear();
        self.error = None;
        self.tf_view = view;
    }

    fn handle_tf_setup_key(&mut self, key: KeyEvent, strings: &Strings, totp_only: bool) -> SettingsOutcome {
        self.error = None;
        match key.code {
            KeyCode::Backspace => {
                self.tf_code.pop();
            }
            KeyCode::Char(c) if c.is_ascii_digit() && self.tf_code.len() < 6 => self.tf_code.push(c),
            KeyCode::Enter if self.tf_code.len() == 6 => {
                if totp::verify_code(&self.pending_secret, &self.tf_code) {
                    let secret_base32 = std::mem::take(&mut self.pending_secret);
                    self.tf_code.clear();
                    self.tf_view = TwoFactorView::Overview;
                    self.tf_selected = 0;
                    return if totp_only {
                        SettingsOutcome::EnableTotpOnly { secret_base32 }
                    } else {
                        SettingsOutcome::EnableTwoFactor { secret_base32 }
                    };
                }
                self.error = Some(strings.err_totp_invalid_code.to_string());
                self.tf_code.clear();
            }
            _ => {}
        }
        SettingsOutcome::None
    }

    fn handle_tf_confirm_disable_key(&mut self, key: KeyEvent) -> SettingsOutcome {
        match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                self.tf_view = TwoFactorView::Overview;
                self.tf_selected = 0;
                return SettingsOutcome::DisableTwoFactor;
            }
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                self.tf_view = TwoFactorView::Overview;
            }
            _ => {}
        }
        SettingsOutcome::None
    }

    fn handle_tf_switch_form_key(&mut self, key: KeyEvent, strings: &Strings) -> SettingsOutcome {
        self.error = None;
        match key.code {
            KeyCode::Tab | KeyCode::BackTab => self.switch_focus_new = !self.switch_focus_new,
            KeyCode::Backspace => {
                if self.switch_focus_new {
                    self.switch_new_password.pop();
                } else {
                    self.switch_confirm_password.pop();
                }
            }
            KeyCode::Char(c) => {
                if self.switch_focus_new {
                    self.switch_new_password.push(c);
                } else {
                    self.switch_confirm_password.push(c);
                }
            }
            KeyCode::Enter if key.modifiers.contains(KeyModifiers::CONTROL) || !self.switch_focus_new => {
                if self.switch_new_password.len() < 8 {
                    self.error = Some(strings.err_password_too_short.to_string());
                    return SettingsOutcome::None;
                }
                if *self.switch_new_password != *self.switch_confirm_password {
                    self.error = Some(strings.err_passwords_dont_match.to_string());
                    self.switch_confirm_password.clear();
                    return SettingsOutcome::None;
                }
                let new = std::mem::replace(&mut self.switch_new_password, Zeroizing::new(String::new()));
                self.switch_confirm_password.clear();
                self.tf_view = TwoFactorView::Overview;
                self.tf_selected = 0;
                return SettingsOutcome::SwitchToPassword { new };
            }
            KeyCode::Enter => self.switch_focus_new = false,
            _ => {}
        }
        SettingsOutcome::None
    }

    pub fn render(&mut self, frame: &mut Frame, area: Rect, strings: &Strings) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Min(0), Constraint::Length(24)])
            .split(area);

        self.render_content(frame, chunks[0], strings);
        self.render_sidebar(frame, chunks[1], strings);
    }

    fn render_sidebar(&self, frame: &mut Frame, area: Rect, strings: &Strings) {
        let items: Vec<ListItem> = TABS
            .iter()
            .map(|t| {
                let label = match t {
                    Tab::Language => strings.settings_tab_language,
                    Tab::Password => strings.settings_tab_password,
                    Tab::TwoFactor => strings.settings_tab_two_factor,
                };
                let style = if *t == self.tab {
                    Style::default().add_modifier(Modifier::REVERSED)
                } else {
                    Style::default()
                };
                ListItem::new(label).style(style)
            })
            .collect();

        let list = List::new(items).block(Block::default().borders(Borders::ALL).title(strings.settings_title));
        frame.render_widget(list, area);
    }

    fn render_content(&mut self, frame: &mut Frame, area: Rect, strings: &Strings) {
        match self.tab {
            Tab::Language => self.render_language_tab(frame, area, strings),
            Tab::Password => self.render_password_tab(frame, area, strings),
            Tab::TwoFactor => self.render_two_factor_tab(frame, area, strings),
        }
    }

    fn render_language_tab(&mut self, frame: &mut Frame, area: Rect, strings: &Strings) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(3), Constraint::Length(1)])
            .split(area);

        let items: Vec<ListItem> = LANGS
            .iter()
            .map(|l| ListItem::new(format!("{} ({})", native_name(*l), l.code())))
            .collect();
        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title(strings.settings_tab_language))
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
            .highlight_symbol("> ");
        frame.render_stateful_widget(list, chunks[0], &mut self.lang_list_state);

        let hint = Paragraph::new(Line::from(Span::styled(
            strings.settings_lang_hint,
            Style::default().fg(Color::DarkGray),
        )));
        frame.render_widget(hint, chunks[1]);
    }

    fn render_password_tab(&self, frame: &mut Frame, area: Rect, strings: &Strings) {
        let field_line = |label: &str, value: String, field: PwField, this: &Self| {
            let cursor = if this.pw_focus == field { "_" } else { "" };
            let style = if this.pw_focus == field {
                Style::default().fg(Color::Cyan)
            } else {
                Style::default()
            };
            Line::from(vec![
                Span::styled(format!("{label}: "), style),
                Span::raw(format!("{value}{cursor}")),
            ])
        };

        let mut lines = vec![
            field_line(strings.settings_current_password, mask(&self.current_password), PwField::Current, self),
            field_line(strings.settings_new_password, mask(&self.new_password), PwField::New, self),
            field_line(
                strings.settings_confirm_password,
                mask(&self.confirm_password),
                PwField::Confirm,
                self,
            ),
            Line::from(""),
        ];

        if let Some(err) = &self.error {
            lines.push(Line::from(Span::styled(err.clone(), Style::default().fg(Color::Red))));
        } else if let Some(info) = &self.info {
            lines.push(Line::from(Span::styled(info.clone(), Style::default().fg(Color::Green))));
        } else {
            lines.push(Line::from(Span::styled(
                strings.settings_password_hint,
                Style::default().fg(Color::DarkGray),
            )));
        }

        let block = Block::default().borders(Borders::ALL).title(strings.settings_tab_password);
        frame.render_widget(Paragraph::new(lines).block(block), area);
    }

    fn render_two_factor_tab(&mut self, frame: &mut Frame, area: Rect, strings: &Strings) {
        match self.tf_view {
            TwoFactorView::Overview => self.render_tf_overview(frame, area, strings),
            TwoFactorView::SetupTwoFactor => self.render_tf_setup(frame, area, strings, false),
            TwoFactorView::SetupTotpOnly => self.render_tf_setup(frame, area, strings, true),
            TwoFactorView::ConfirmDisableTwoFactor => self.render_tf_confirm_disable(frame, area, strings),
            TwoFactorView::SwitchToPasswordForm => self.render_tf_switch_form(frame, area, strings),
        }
    }

    fn render_tf_overview(&self, frame: &mut Frame, area: Rect, strings: &Strings) {
        let mode_label = match self.auth_mode {
            AuthMode::Password => strings.auth_mode_password,
            AuthMode::TwoFactor => strings.auth_mode_two_factor,
            AuthMode::TotpOnly => strings.auth_mode_totp_only,
        };
        let action_labels: Vec<&str> = match self.auth_mode {
            AuthMode::Password => vec![strings.tf_action_enable_2fa, strings.tf_action_enable_totp_only],
            AuthMode::TwoFactor => vec![strings.tf_action_disable_2fa],
            AuthMode::TotpOnly => vec![strings.tf_action_switch_to_password],
        };

        let mut lines = vec![
            Line::from(format!("{}: {}", strings.tf_mode_label, mode_label)),
            Line::from(""),
        ];
        for (i, label) in action_labels.iter().enumerate() {
            let style = if i == self.tf_selected {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };
            lines.push(Line::from(Span::styled(format!("> {label}"), style)));
        }
        lines.push(Line::from(""));

        if let Some(err) = &self.error {
            lines.push(Line::from(Span::styled(err.clone(), Style::default().fg(Color::Red))));
        } else if let Some(info) = &self.info {
            lines.push(Line::from(Span::styled(info.clone(), Style::default().fg(Color::Green))));
        }

        let block = Block::default().borders(Borders::ALL).title(strings.settings_tab_two_factor);
        frame.render_widget(Paragraph::new(lines).block(block), area);
    }

    fn render_tf_setup(&self, frame: &mut Frame, area: Rect, strings: &Strings, totp_only: bool) {
        let qr_lines = render_qr_lines(&totp::otpauth_url(&self.pending_secret).unwrap_or_default());
        let qr_height = qr_lines.len() as u16 + 1;

        let secret_line = format!("{}: {}", strings.tf_secret_label, self.pending_secret);
        let mut raw_lines = vec![secret_line.as_str(), strings.tf_scan_hint];
        if totp_only {
            raw_lines.push(strings.tf_totp_only_warning);
        }
        // Border eats 2 columns; estimate wrapped row count per line at this width.
        let content_width = area.width.saturating_sub(2).max(1) as usize;
        let wrapped_rows: usize = raw_lines.iter().map(|l| l.chars().count().div_ceil(content_width).max(1)).sum();
        let top_height = wrapped_rows as u16 + 2;

        let mut top = vec![
            Line::from(secret_line.clone()),
            Line::from(Span::styled(strings.tf_scan_hint, Style::default().fg(Color::DarkGray))),
        ];
        if totp_only {
            top.push(Line::from(Span::styled(
                strings.tf_totp_only_warning,
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            )));
        }

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(top_height), Constraint::Length(qr_height), Constraint::Length(4)])
            .split(area);

        let title = if totp_only { strings.tf_setup_totp_only_title } else { strings.tf_setup_2fa_title };
        let top_paragraph = Paragraph::new(top)
            .wrap(Wrap { trim: true })
            .block(Block::default().borders(Borders::ALL).title(title));
        frame.render_widget(top_paragraph, chunks[0]);

        frame.render_widget(Paragraph::new(qr_lines), chunks[1]);

        let mut bottom = vec![Line::from(format!("{}: {}_", strings.totp_code_label, self.tf_code))];
        if let Some(err) = &self.error {
            bottom.push(Line::from(Span::styled(err.clone(), Style::default().fg(Color::Red))));
        } else {
            bottom.push(Line::from(Span::styled(strings.tf_verify_hint, Style::default().fg(Color::DarkGray))));
        }
        frame.render_widget(Paragraph::new(bottom).block(Block::default().borders(Borders::ALL)), chunks[2]);
    }

    fn render_tf_confirm_disable(&self, frame: &mut Frame, area: Rect, strings: &Strings) {
        let lines = vec![
            Line::from(strings.tf_confirm_disable_message),
            Line::from(""),
            Line::from(Span::styled(strings.confirm_hint, Style::default().fg(Color::DarkGray))),
        ];
        let block = Block::default().borders(Borders::ALL).title(strings.settings_tab_two_factor);
        frame.render_widget(Paragraph::new(lines).block(block), area);
    }

    fn render_tf_switch_form(&self, frame: &mut Frame, area: Rect, strings: &Strings) {
        let field_line = |label: &str, value: String, is_new: bool, this: &Self| {
            let focused = this.switch_focus_new == is_new;
            let cursor = if focused { "_" } else { "" };
            let style = if focused { Style::default().fg(Color::Cyan) } else { Style::default() };
            Line::from(vec![
                Span::styled(format!("{label}: "), style),
                Span::raw(format!("{value}{cursor}")),
            ])
        };

        let mut lines = vec![
            field_line(strings.settings_new_password, mask(&self.switch_new_password), true, self),
            field_line(strings.settings_confirm_password, mask(&self.switch_confirm_password), false, self),
            Line::from(""),
        ];
        if let Some(err) = &self.error {
            lines.push(Line::from(Span::styled(err.clone(), Style::default().fg(Color::Red))));
        } else {
            lines.push(Line::from(Span::styled(strings.settings_password_hint, Style::default().fg(Color::DarkGray))));
        }

        let block = Block::default().borders(Borders::ALL).title(strings.tf_switch_to_password_title);
        frame.render_widget(Paragraph::new(lines).block(block), area);
    }
}

fn native_name(lang: Lang) -> &'static str {
    match lang {
        Lang::En => "English",
        Lang::Tr => "Türkçe",
        Lang::Es => "Español",
        Lang::Ru => "Русский",
    }
}

/// Renders an `otpauth://` URI as a scannable QR code using half-block
/// Unicode characters (2 QR modules per terminal cell).
fn render_qr_lines(data: &str) -> Vec<Line<'static>> {
    if data.is_empty() {
        return vec![Line::from("")];
    }
    let Ok(code) = QrCode::new(data.as_bytes()) else {
        return vec![Line::from("")];
    };
    let rendered = code.render::<unicode::Dense1x2>().quiet_zone(false).build();
    rendered.lines().map(|l| Line::from(l.to_string())).collect()
}
