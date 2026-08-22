//! The first-run security mode chooser, and the same flow reused from settings
//! when the mode is changed later.
//!
//! Every mode ends in the same place — a master key wrapped by some set of
//! slots — so this screen's only job is collecting the inputs those slots need:
//! a password, a TOTP secret, or neither.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{List, ListItem, ListState, Paragraph, Wrap};
use zeroize::Zeroizing;

use crate::i18n::Strings;
use crate::tui::theme;
use crate::totp::{self, AuthMode};
use crate::tui::widgets::{self, mask, qr_lines};

const MIN_PASSWORD_LEN: usize = 8;

/// The modes in the order they are offered, weakest first.
const MODES: [AuthMode; 4] = [AuthMode::None, AuthMode::Password, AuthMode::PasswordTotp, AuthMode::TotpDaily];

/// `Debug` is safe here and only here among this screen's types: a step name
/// carries no credential. `SetupState` and `SetupOutcome` deliberately stay
/// undebuggable.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
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
        totp_secret: Option<Zeroizing<String>>,
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
    /// Wiping buffers, like every other credential form (`unlock.rs`,
    /// `settings.rs`, `server_form.rs`). Wrapping only on the way out would
    /// miss the copies `String::push` leaves behind when it reallocates, and
    /// would leave everything typed here intact if the user backs out with Esc.
    password: Zeroizing<String>,
    confirm: Zeroizing<String>,
    focus_confirm: bool,
    want_recovery: bool,
    /// The enrolled TOTP secret. A credential, not a display string: in
    /// `TotpDaily` this is what the device slot is gated on.
    pending_secret: Zeroizing<String>,
    /// Not wrapped: a six-digit single-use code, not a lasting secret.
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
            password: Zeroizing::new(String::new()),
            confirm: Zeroizing::new(String::new()),
            focus_confirm: false,
            want_recovery: true,
            pending_secret: Zeroizing::new(String::new()),
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
                if *self.password != *self.confirm {
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
            // `mem::replace`, not `mem::take`: `Zeroizing` has no `Default`.
            Some(std::mem::replace(&mut self.password, Zeroizing::new(String::new())))
        };
        let totp_secret = match self.mode {
            AuthMode::PasswordTotp | AuthMode::TotpDaily => {
                Some(std::mem::replace(&mut self.pending_secret, Zeroizing::new(String::new())))
            }
            _ => None,
        };
        self.confirm.clear();
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

    /// The mode chooser, as a `List` rather than a paragraph of hand-marked
    /// lines.
    ///
    /// The paragraph is what produced the reported bug: it built every mode
    /// into one line list, sized a `centered_rect` to it, and let the clamp
    /// silently drop whatever did not fit — so the fourth mode stayed
    /// selectable while being off screen, and the user could choose a security
    /// mode they had never read.
    ///
    /// A `List` scrolls for free, and scrolls *by item*, so a mode is never
    /// half-shown: `get_items_bounds` walks forward until the selection fits,
    /// which is the same smallest-scroll contract `form_scroll_offset` spells
    /// out by hand. The intro and the hint sit outside it, in bands of their
    /// own, so neither can be the thing that gets scrolled away.
    fn render_choose_mode(&self, frame: &mut Frame, area: Rect, strings: &Strings) {
        let width = 76.min(area.width.saturating_sub(4)).max(widgets::MIN_PANEL_WIDTH);
        let height = area.height.min(24);
        let rect = widgets::centered_rect(width, height, area);
        if widgets::render_if_too_small(frame, rect, widgets::MIN_PANEL_WIDTH, widgets::MIN_PANEL_HEIGHT, strings.terminal_too_small) {
            return;
        }

        let block = widgets::modal(strings.setup_title);
        let inner = block.inner(rect);
        widgets::clear_surface(frame, rect);
        frame.render_widget(block, rect);

        let footer = Line::from(match &self.error {
            Some(err) => Span::styled(err.clone(), Style::default().fg(theme::error())),
            None => Span::styled(strings.setup_choose_hint, Style::default().fg(theme::hint())),
        });
        let intro_rows = widgets::wrapped_height(&[Line::from(strings.setup_intro)], inner.width) as u16;
        let footer_rows = widgets::wrapped_height(std::slice::from_ref(&footer), inner.width) as u16;
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(intro_rows + 1), Constraint::Min(3), Constraint::Length(footer_rows)])
            .split(inner);

        let intro = Paragraph::new(Span::styled(strings.setup_intro, Style::default().fg(theme::hint()))).wrap(Wrap { trim: false });
        frame.render_widget(intro, rows[0]);

        let items: Vec<ListItem> = MODES
            .iter()
            .map(|mode| {
                let available = self.mode_available(*mode);
                let title = if available {
                    Span::raw(mode_title(*mode, strings))
                } else {
                    Span::styled(mode_title(*mode, strings), Style::default().fg(theme::hint()).add_modifier(Modifier::DIM))
                };
                let mut lines = vec![
                    Line::from(title),
                    Line::from(Span::styled(format!("  {}", mode_description(*mode, strings)), Style::default().fg(theme::hint()))),
                ];
                if !available {
                    lines.push(Line::from(Span::styled(
                        format!("  {}", strings.setup_needs_credential_store),
                        Style::default().fg(theme::warning()),
                    )));
                }
                lines.push(Line::from(""));
                ListItem::new(lines)
            })
            .collect();

        // Rebuilt every frame from `self.selected`, for the same reason
        // `form_scroll_offset` is stateless: that field is the only position
        // that exists, and a stored offset is one more thing to drift from it.
        let mut list_state = ListState::default();
        list_state.select(Some(self.selected));
        let list = List::new(items).highlight_style(theme::selection()).highlight_symbol(widgets::SELECT_MARKER);
        frame.render_stateful_widget(list, rows[1], &mut list_state);
        widgets::render_list_scrollbar(frame, rows[1], self.selected, MODES.len());

        frame.render_widget(Paragraph::new(footer).wrap(Wrap { trim: false }), rows[2]);
    }

    fn render_offer_recovery(&self, frame: &mut Frame, area: Rect, strings: &Strings) {
        let lines = vec![
            Line::from(Span::styled(strings.setup_recovery_warning, Style::default().fg(theme::warning()).add_modifier(Modifier::BOLD))),
            Line::from(""),
            Line::from(strings.setup_recovery_question),
            Line::from(""),
            Line::from(Span::styled(strings.setup_recovery_hint, Style::default().fg(theme::hint()))),
        ];
        let focus_row = lines.len() - 1;
        widgets::render_panel(frame, area, 70, strings.setup_recovery_title, lines, focus_row, strings.terminal_too_small);
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
            lines.push(Line::from(Span::styled(err.clone(), Style::default().fg(theme::error()))));
        } else {
            lines.push(Line::from(Span::styled(strings.setup_password_hint, Style::default().fg(theme::hint()))));
        }

        // The focused field, so a wrapped label or a long error can never
        // scroll the box the user is typing into off screen.
        let focus_row = usize::from(self.focus_confirm);
        widgets::render_panel(frame, area, 64, mode_title(self.mode, strings), lines, focus_row, strings.terminal_too_small);
    }

    fn render_totp_enroll(&self, frame: &mut Frame, area: Rect, strings: &Strings) {
        // `Zeroizing` has no `Default`, so no `unwrap_or_default` here. An
        // unencodable secret still degrades to the one blank line `qr_lines`
        // returns for empty input, exactly as before.
        let qr = totp::otpauth_url(&self.pending_secret).map_or_else(|| qr_lines(""), |url| qr_lines(&url));
        let qr_height = qr.len() as u16 + 1;

        let top = vec![
            Line::from(format!("{}: {}", strings.tf_secret_label, self.pending_secret.as_str())),
            Line::from(Span::styled(strings.tf_scan_hint, Style::default().fg(theme::hint()))),
        ];

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(4), Constraint::Length(qr_height), Constraint::Length(4)])
            .split(area);

        let block = widgets::modal(mode_title(self.mode, strings));
        frame.render_widget(Paragraph::new(top).wrap(Wrap { trim: true }).block(block), chunks[0]);
        frame.render_widget(Paragraph::new(qr), chunks[1]);

        let mut bottom = vec![Line::from(format!("{}: {}_", strings.totp_code_label, self.code))];
        if let Some(err) = &self.error {
            bottom.push(Line::from(Span::styled(err.clone(), Style::default().fg(theme::error()))));
        } else {
            bottom.push(Line::from(Span::styled(strings.tf_verify_hint, Style::default().fg(theme::hint()))));
        }
        frame.render_widget(Paragraph::new(bottom).block(widgets::modal("")), chunks[2]);
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
        Line::from(Span::styled(strings.unopenable_message, Style::default().fg(theme::error()))),
    ];
    widgets::render_panel(frame, area, 70, strings.unopenable_title, lines, 0, strings.terminal_too_small);
}

/// A vault that cannot be opened *right now* — another instance holds it, or a
/// newer build wrote it. Unlike `render_unopenable` these clear by themselves
/// once the user does the thing the message names, so they are yellow rather
/// than red and the caller supplies the wording.
pub fn render_cannot_open(frame: &mut Frame, area: Rect, title: &str, message: &str, strings: &Strings) {
    let lines = vec![Line::from(Span::styled(message.to_string(), Style::default().fg(theme::warning())))];
    widgets::render_panel(frame, area, 70, title, lines, 0, strings.terminal_too_small);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::EN;

    /// Drives the screen the way a user would. Being in the same module, these
    /// tests can then read the private buffers directly — which is the point:
    /// what matters is not only what `finish` hands out, but what it leaves
    /// behind.
    fn press(state: &mut SetupState, code: KeyCode) -> SetupOutcome {
        state.handle_key(KeyEvent::from(code), &EN)
    }

    fn type_str(state: &mut SetupState, s: &str) {
        for c in s.chars() {
            press(state, KeyCode::Char(c));
        }
    }

    /// Selects `mode` on the chooser and lands on the password step.
    fn choose(mode: AuthMode) -> SetupState {
        // A credential store is claimed so all four modes are selectable.
        let mut state = SetupState::new(true);
        let target = MODES.iter().position(|m| *m == mode).expect("mode is offered");
        while state.selected < target {
            press(&mut state, KeyCode::Down);
        }
        while state.selected > target {
            press(&mut state, KeyCode::Up);
        }
        press(&mut state, KeyCode::Enter);
        state
    }

    /// Types the password into both fields and confirms.
    fn enter_password(state: &mut SetupState, password: &str) -> SetupOutcome {
        type_str(state, password);
        press(state, KeyCode::Enter);
        type_str(state, password);
        press(state, KeyCode::Enter)
    }

    #[test]
    fn a_password_only_setup_hands_out_the_password_and_keeps_no_copy() {
        let mut state = choose(AuthMode::Password);
        assert_eq!(state.step, Step::Password);

        let outcome = enter_password(&mut state, "correct horse");

        let SetupOutcome::Create { mode, password, totp_secret } = outcome else {
            panic!("a confirmed password should finish the setup");
        };
        assert_eq!(mode, AuthMode::Password);
        assert_eq!(password.expect("a password was typed").as_str(), "correct horse");
        assert!(totp_secret.is_none(), "mode 2 has no TOTP secret");

        // The whole point of the change: nothing typed is still sitting in the
        // screen's buffers afterwards.
        assert!(state.password.is_empty());
        assert!(state.confirm.is_empty());
    }

    #[test]
    fn a_password_shorter_than_the_minimum_is_refused() {
        let mut state = choose(AuthMode::Password);
        let outcome = enter_password(&mut state, "short");

        assert!(matches!(outcome, SetupOutcome::None));
        assert!(state.error.is_some());
        assert_eq!(state.step, Step::Password, "the user stays on the password step");
    }

    #[test]
    fn a_mismatched_confirmation_emits_nothing() {
        let mut state = choose(AuthMode::Password);
        type_str(&mut state, "correct horse");
        press(&mut state, KeyCode::Enter);
        type_str(&mut state, "correct hose");
        let outcome = press(&mut state, KeyCode::Enter);

        assert!(matches!(outcome, SetupOutcome::None), "a mismatch must not create a vault");
        assert!(state.error.is_some());
    }

    #[test]
    fn totp_enrolment_hands_out_the_secret_and_keeps_no_copy() {
        let mut state = choose(AuthMode::PasswordTotp);
        assert!(matches!(enter_password(&mut state, "correct horse"), SetupOutcome::None));

        // The password step generates the secret and moves on to enrolment
        // rather than finishing.
        assert_eq!(state.step, Step::TotpEnroll);
        assert!(!state.pending_secret.is_empty());
        let enrolled = state.pending_secret.to_string();

        type_str(&mut state, &crate::totp::current_code(&enrolled));
        let outcome = press(&mut state, KeyCode::Enter);

        let SetupOutcome::Create { mode, password, totp_secret } = outcome else {
            panic!("a live code should finish the setup");
        };
        assert_eq!(mode, AuthMode::PasswordTotp);
        assert_eq!(password.expect("a password was typed").as_str(), "correct horse");
        assert_eq!(totp_secret.expect("mode 3 carries a secret").as_str(), enrolled);

        assert!(state.password.is_empty());
        assert!(state.confirm.is_empty());
        assert!(state.pending_secret.is_empty());
    }

    /// The enrolment screen is the one place the secret is deliberately on
    /// screen, and both of its render paths had to change shape when the buffer
    /// became `Zeroizing` — `otpauth_url` lost its `Default`, and the secret
    /// line lost its `Display`. This pins that the user can still read and scan
    /// what they are enrolling.
    #[test]
    fn the_enrolment_screen_still_shows_the_secret_and_a_qr() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let mut state = choose(AuthMode::PasswordTotp);
        enter_password(&mut state, "correct horse");
        let enrolled = state.pending_secret.to_string();

        let mut terminal = Terminal::new(TestBackend::new(100, 60)).expect("test backend");
        terminal.draw(|frame| state.render(frame, frame.area(), &EN)).expect("render");

        let rendered: String = terminal.backend().buffer().content().iter().map(|c| c.symbol()).collect();
        assert!(rendered.contains(&enrolled), "the base32 secret must stay readable for hand entry");
        // `qr_lines` draws in half-block characters; their presence means the
        // URI encoded rather than falling through to the blank-line path.
        assert!(rendered.contains('\u{2580}') || rendered.contains('\u{2584}'), "the QR code should have rendered");
    }

    /// The two dead-end screens must not be confusable: one says the vault
    /// cannot be opened on this machine at all, the other that it is open in
    /// another window right now. Showing the wrong one sends the user hunting
    /// for a recovery password they do not need.
    #[test]
    fn the_two_dead_end_screens_say_different_things() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let draw = |f: fn(&mut ratatui::Frame, ratatui::layout::Rect, &Strings)| {
            let mut terminal = Terminal::new(TestBackend::new(100, 30)).expect("test backend");
            terminal.draw(|frame| f(frame, frame.area(), &EN)).expect("render");
            terminal.backend().buffer().content().iter().map(|c| c.symbol()).collect::<String>()
        };

        // Single words, not phrases: the buffer is row-major over the whole
        // terminal, so a wrapped message is interleaved with the padding either
        // side of the centred box. Words survive a wrap; phrases do not.
        let unopenable = draw(render_unopenable);
        let in_use = {
            let mut terminal = Terminal::new(TestBackend::new(100, 30)).expect("test backend");
            terminal
                .draw(|frame| render_cannot_open(frame, frame.area(), EN.vault_in_use_title, EN.vault_in_use_message, &EN))
                .expect("render");
            terminal.backend().buffer().content().iter().map(|c| c.symbol()).collect::<String>()
        };

        assert!(unopenable.contains("recovery"), "the permanent one explains the missing fallback");
        assert!(in_use.contains("Close"), "the transient one says what to do about it");
        assert!(!in_use.contains("recovery"), "a contended vault is not a missing-credential problem");
    }

    fn draw(state: &mut SetupState, width: u16, height: u16) -> String {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;
        let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("test backend");
        terminal.draw(|frame| state.render(frame, frame.area(), &EN)).expect("render");
        terminal.backend().buffer().content().iter().map(|c| c.symbol()).collect()
    }

    /// The reported bug, pinned. The chooser used to build its lines and then
    /// hand them to a `centered_rect` clamped to the frame — so on anything
    /// short the fourth mode was selectable and invisible at the same time,
    /// and the user could pick a security mode they had never read.
    ///
    /// Every mode has to be readable at the size it is *reached* at, which is
    /// the worst case, not the best: the Security tab renders this same screen
    /// 24 columns narrower than the frame.
    #[test]
    fn every_security_mode_can_be_read_on_a_short_terminal() {
        for (width, height) in [(100, 24), (80, 20), (56, 16)] {
            for (index, mode) in MODES.iter().enumerate() {
                let mut state = SetupState::new(true);
                while state.selected < index {
                    press(&mut state, KeyCode::Down);
                }
                let rendered = draw(&mut state, width, height);
                assert!(
                    rendered.contains(mode_title(*mode, &EN)),
                    "{}x{}: mode {index} is selectable but not on screen",
                    width,
                    height
                );
            }
        }
    }

    /// The second instance of the same bug, and the quieter one: the enrolment
    /// screen split the frame into a fixed `[4, qr_height, 4]`, and a version-2
    /// QR is about 25 rows in half-blocks. On a 24-row terminal the last chunk
    /// — the box holding the six-digit field — got zero rows, so the user
    /// could not see the code they were typing.
    #[test]
    fn the_code_field_is_on_screen_during_enrolment() {
        let mut state = choose(AuthMode::PasswordTotp);
        enter_password(&mut state, "correct horse");
        assert_eq!(state.step, Step::TotpEnroll);
        for (width, height) in [(100, 40), (100, 24), (80, 20), (72, 16)] {
            let rendered = draw(&mut state, width, height);
            assert!(
                rendered.contains(EN.totp_code_label),
                "{width}x{height}: the field the user types into has to be visible"
            );
        }
    }

    /// Without this the user could enrol a secret their authenticator cannot
    /// produce codes for, and end up with a vault they cannot open.
    #[test]
    fn a_wrong_code_does_not_finish_enrolment() {
        let mut state = choose(AuthMode::PasswordTotp);
        enter_password(&mut state, "correct horse");
        assert_eq!(state.step, Step::TotpEnroll);

        type_str(&mut state, "000000");
        let outcome = press(&mut state, KeyCode::Enter);

        assert!(matches!(outcome, SetupOutcome::None));
        assert!(state.error.is_some());
        assert_eq!(state.step, Step::TotpEnroll);
        assert!(!state.pending_secret.is_empty(), "the secret survives a wrong code");
    }
}
