use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use zeroize::Zeroizing;

use super::setup::{self, SetupOutcome, SetupState};
use super::widgets::mask;
use crate::i18n::{Lang, Strings};
use crate::tui::theme::{self, THEMES, Theme};
use crate::totp::AuthMode;

const LANGS: [Lang; 4] = [Lang::En, Lang::Tr, Lang::Es, Lang::Ru];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Language,
    Theme,
    Password,
    Security,
    AutoLock,
}

const TABS: [Tab; 5] = [Tab::Language, Tab::Theme, Tab::Password, Tab::Security, Tab::AutoLock];

/// Idle auto-lock choices, in minutes. `0` is "off"; anything else is a
/// timeout. Presets rather than a free-text field so the value can never be
/// something like `0.5` or a typo'd `1000`.
const AUTO_LOCK_CHOICES: [u32; 6] = [0, 1, 5, 15, 30, 60];

#[derive(Clone, Copy, PartialEq, Eq)]
enum PwField {
    Current,
    New,
    Confirm,
}

const PW_FIELDS: [PwField; 3] = [PwField::Current, PwField::New, PwField::Confirm];


/// F1 settings screen: a right-hand sidebar lists tabs (Language, Master
/// Password, Two-Factor); the main area to its left shows the selected tab's
/// content.
pub struct SettingsState {
    tab: Tab,
    lang_list_state: ListState,
    lang_selected: usize,
    theme_list_state: ListState,
    theme_selected: usize,
    pw_focus: PwField,
    current_password: Zeroizing<String>,
    new_password: Zeroizing<String>,
    confirm_password: Zeroizing<String>,
    pub error: Option<String>,
    pub info: Option<String>,

    // Auto-lock tab
    auto_lock_list_state: ListState,
    auto_lock_selected: usize,

    // Two-Factor tab
    auth_mode: AuthMode,
    /// Whether this machine can back the modes that need an OS credential
    /// store. Captured when the screen opens rather than probed per keystroke.
    credential_store: bool,
    /// The mode-change wizard, when it is on screen. It is the same flow as
    /// first-run setup — there is no second implementation of "choose a mode
    /// and collect what it needs".
    security_setup: Option<SetupState>,
}

pub enum SettingsOutcome {
    None,
    Close,
    LanguageSelected(Lang),
    ThemeSelected(Theme),
    /// Idle auto-lock timeout in minutes; `0` disables it.
    AutoLockSelected(u32),
    ChangePassword { current: Zeroizing<String>, new: Zeroizing<String> },
    /// Rebuild the vault's key slots for a different security mode. One
    /// outcome covers every transition — the old per-transition variants were
    /// four ways of saying the same thing.
    ChangeSecurityMode { mode: AuthMode, password: Option<Zeroizing<String>>, totp_secret: Option<Zeroizing<String>> },
}

impl SettingsState {
    /// Called by the app after a successful mode transition (enable/disable
    /// 2FA, switch to/from TOTP-only) so the Overview sub-view immediately
    /// reflects the new mode without requiring the user to close and reopen
    /// Settings.
    pub fn set_auth_mode(&mut self, auth_mode: AuthMode) {
        self.auth_mode = auth_mode;
        self.security_setup = None;
    }

    pub fn new(
        current_lang: Lang,
        current_theme: Theme,
        auth_mode: AuthMode,
        credential_store: bool,
        auto_lock_minutes: u32,
    ) -> Self {
        let lang_selected = LANGS.iter().position(|l| *l == current_lang).unwrap_or(0);
        let mut lang_list_state = ListState::default();
        lang_list_state.select(Some(lang_selected));

        let theme_selected = THEMES.iter().position(|t| *t == current_theme).unwrap_or(0);
        let mut theme_list_state = ListState::default();
        theme_list_state.select(Some(theme_selected));

        // A stored value outside the preset list (hand-edited, or a preset we
        // dropped later) falls back to the first entry rather than showing no
        // selection at all.
        let auto_lock_selected = AUTO_LOCK_CHOICES.iter().position(|m| *m == auto_lock_minutes).unwrap_or(0);
        let mut auto_lock_list_state = ListState::default();
        auto_lock_list_state.select(Some(auto_lock_selected));

        Self {
            tab: Tab::Language,
            lang_list_state,
            lang_selected,
            theme_list_state,
            theme_selected,
            pw_focus: PwField::Current,
            current_password: Zeroizing::new(String::new()),
            new_password: Zeroizing::new(String::new()),
            confirm_password: Zeroizing::new(String::new()),
            error: None,
            info: None,

            auto_lock_list_state,
            auto_lock_selected,

            auth_mode,
            credential_store,
            security_setup: None,
        }
    }

    pub fn handle_key(&mut self, key: KeyEvent, strings: &Strings) -> SettingsOutcome {
        match key.code {
            KeyCode::Esc if self.tab == Tab::Security && self.security_setup.is_some() => {
                self.security_setup = None;
                self.error = None;
                self.info = None;
                return SettingsOutcome::None;
            }
            KeyCode::Esc => return SettingsOutcome::Close,
            KeyCode::Left | KeyCode::Right
                if !(self.tab == Tab::Security && self.security_setup.is_some()) =>
            {
                self.tab = match self.tab {
                    Tab::Language => Tab::Theme,
                    Tab::Theme => Tab::Password,
                    Tab::Password => Tab::Security,
                    Tab::Security => Tab::AutoLock,
                    Tab::AutoLock => Tab::Language,
                };
                self.error = None;
                self.info = None;
                return SettingsOutcome::None;
            }
            _ => {}
        }

        match self.tab {
            Tab::Language => self.handle_language_key(key),
            Tab::Theme => self.handle_theme_key(key),
            Tab::Password => self.handle_password_key(key, strings),
            Tab::Security => self.handle_security_key(key, strings),
            Tab::AutoLock => self.handle_auto_lock_key(key),
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

    fn handle_theme_key(&mut self, key: KeyEvent) -> SettingsOutcome {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                if self.theme_selected > 0 {
                    self.theme_selected -= 1;
                    self.theme_list_state.select(Some(self.theme_selected));
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.theme_selected + 1 < THEMES.len() {
                    self.theme_selected += 1;
                    self.theme_list_state.select(Some(self.theme_selected));
                }
            }
            KeyCode::Enter => return SettingsOutcome::ThemeSelected(THEMES[self.theme_selected]),
            _ => {}
        }
        SettingsOutcome::None
    }

    fn handle_auto_lock_key(&mut self, key: KeyEvent) -> SettingsOutcome {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                if self.auto_lock_selected > 0 {
                    self.auto_lock_selected -= 1;
                    self.auto_lock_list_state.select(Some(self.auto_lock_selected));
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.auto_lock_selected + 1 < AUTO_LOCK_CHOICES.len() {
                    self.auto_lock_selected += 1;
                    self.auto_lock_list_state.select(Some(self.auto_lock_selected));
                }
            }
            KeyCode::Enter => return SettingsOutcome::AutoLockSelected(AUTO_LOCK_CHOICES[self.auto_lock_selected]),
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


    /// The Security tab is a one-line summary plus a single action, because
    /// every mode change goes through the same wizard the first run uses.
    fn handle_security_key(&mut self, key: KeyEvent, strings: &Strings) -> SettingsOutcome {
        if let Some(setup) = &mut self.security_setup {
            return match setup.handle_key(key, strings) {
                SetupOutcome::None => SettingsOutcome::None,
                // Esc inside the wizard backs out of it, not out of settings.
                SetupOutcome::Quit => {
                    self.security_setup = None;
                    SettingsOutcome::None
                }
                SetupOutcome::Create { mode, password, totp_secret } => {
                    self.security_setup = None;
                    SettingsOutcome::ChangeSecurityMode { mode, password, totp_secret }
                }
            };
        }

        if key.code == KeyCode::Enter {
            self.security_setup = Some(SetupState::new(self.credential_store));
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
                    Tab::Theme => strings.settings_tab_theme,
                    Tab::Password => strings.settings_tab_password,
                    Tab::Security => strings.settings_tab_security,
                    Tab::AutoLock => strings.settings_tab_auto_lock,
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
            Tab::Theme => self.render_theme_tab(frame, area, strings),
            Tab::Password => self.render_password_tab(frame, area, strings),
            Tab::Security => self.render_security_tab(frame, area, strings),
            Tab::AutoLock => self.render_auto_lock_tab(frame, area, strings),
        }
    }

    fn render_auto_lock_tab(&mut self, frame: &mut Frame, area: Rect, strings: &Strings) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(3), Constraint::Length(1)])
            .split(area);

        let items: Vec<ListItem> = AUTO_LOCK_CHOICES
            .iter()
            .map(|m| {
                let label = if *m == 0 {
                    strings.auto_lock_off.to_string()
                } else {
                    format!("{m}{}", strings.auto_lock_minutes_suffix)
                };
                ListItem::new(label)
            })
            .collect();
        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title(strings.settings_tab_auto_lock))
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
            .highlight_symbol("> ");
        frame.render_stateful_widget(list, chunks[0], &mut self.auto_lock_list_state);

        let footer = if let Some(err) = &self.error {
            Span::styled(err.clone(), Style::default().fg(theme::error()))
        } else if let Some(info) = &self.info {
            Span::styled(info.clone(), Style::default().fg(theme::success()))
        } else {
            Span::styled(strings.settings_auto_lock_hint, Style::default().fg(theme::hint()))
        };
        frame.render_widget(Paragraph::new(Line::from(footer)), chunks[1]);
    }

    fn render_theme_tab(&mut self, frame: &mut Frame, area: Rect, strings: &Strings) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(3), Constraint::Length(1)])
            .split(area);

        let items: Vec<ListItem> = THEMES
            .iter()
            .map(|t| {
                ListItem::new(match t {
                    Theme::Dark => strings.theme_dark,
                    Theme::Light => strings.theme_light,
                })
            })
            .collect();
        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title(strings.settings_tab_theme))
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
            .highlight_symbol("> ");
        frame.render_stateful_widget(list, chunks[0], &mut self.theme_list_state);

        // Picking a preset under `NO_COLOR` still stores it and still applies
        // the next time the variable is unset — but nothing changes on screen
        // right now, and a setting that silently does nothing needs saying.
        let footer = if theme::no_color() {
            Span::styled(strings.theme_no_color_note, Style::default().fg(theme::warning()))
        } else {
            // The same keys as the language list, so the same string — and the
            // help overlay stays one row per binding rather than two identical ones.
            Span::styled(strings.settings_lang_hint, Style::default().fg(theme::hint()))
        };
        frame.render_widget(Paragraph::new(Line::from(footer)), chunks[1]);
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
            Style::default().fg(theme::hint()),
        )));
        frame.render_widget(hint, chunks[1]);
    }

    fn render_password_tab(&self, frame: &mut Frame, area: Rect, strings: &Strings) {
        let field_line = |label: &str, value: String, field: PwField, this: &Self| {
            let cursor = if this.pw_focus == field { "_" } else { "" };
            let style = if this.pw_focus == field {
                Style::default().fg(theme::accent())
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
            lines.push(Line::from(Span::styled(err.clone(), Style::default().fg(theme::error()))));
        } else if let Some(info) = &self.info {
            lines.push(Line::from(Span::styled(info.clone(), Style::default().fg(theme::success()))));
        } else {
            lines.push(Line::from(Span::styled(
                strings.settings_password_hint,
                Style::default().fg(theme::hint()),
            )));
        }

        let block = Block::default().borders(Borders::ALL).title(strings.settings_tab_password);
        frame.render_widget(Paragraph::new(lines).block(block), area);
    }

    fn render_security_tab(&mut self, frame: &mut Frame, area: Rect, strings: &Strings) {
        if let Some(setup) = &self.security_setup {
            setup.render(frame, area, strings);
            return;
        }

        let lines = vec![
            Line::from(format!("{}: {}", strings.settings_security_current, setup::mode_title(self.auth_mode, strings))),
            Line::from(Span::styled(setup::mode_description(self.auth_mode, strings), Style::default().fg(theme::hint()))),
            Line::from(""),
            Line::from(Span::styled(strings.settings_action_change_mode, Style::default().add_modifier(Modifier::REVERSED))),
        ];

        let block = Block::default().borders(Borders::ALL).title(strings.settings_tab_security);
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }).block(block), area);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::EN;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn state() -> SettingsState {
        SettingsState::new(Lang::En, Theme::Dark, AuthMode::Password, false, 15)
    }

    fn press(state: &mut SettingsState, code: KeyCode) -> SettingsOutcome {
        state.handle_key(KeyEvent::from(code), &EN)
    }

    fn render(state: &mut SettingsState) -> String {
        let mut terminal = Terminal::new(TestBackend::new(80, 20)).expect("test backend");
        terminal.draw(|frame| state.render(frame, frame.area(), &EN)).expect("render");
        terminal.backend().buffer().content().iter().map(|c| c.symbol()).collect()
    }

    /// The theme sits next to the language, which is where the issue asks for
    /// it and where a reader looking for "display settings" will go.
    #[test]
    fn the_theme_tab_is_the_one_after_language() {
        let mut s = state();
        press(&mut s, KeyCode::Right);
        let screen = render(&mut s);
        assert!(screen.contains("Dark"));
        assert!(screen.contains("Light"));
    }

    #[test]
    fn enter_picks_the_highlighted_preset() {
        let mut s = state();
        press(&mut s, KeyCode::Right);
        press(&mut s, KeyCode::Down);
        let SettingsOutcome::ThemeSelected(theme) = press(&mut s, KeyCode::Enter) else {
            panic!("Enter should select a theme");
        };
        assert_eq!(theme, Theme::Light);
    }

    /// Every tab has to stay reachable by walking right — a new one inserted
    /// mid-cycle is exactly how that breaks.
    #[test]
    fn the_tab_cycle_returns_to_where_it_started() {
        let mut s = state();
        for _ in 0..TABS.len() {
            press(&mut s, KeyCode::Right);
        }
        assert!(render(&mut s).contains("English"), "back on the language tab");
    }
}
