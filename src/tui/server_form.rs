use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::widgets::{mask, render_form};
use crate::config::{AuthMethod, Secret, ServerEntry};
use crate::i18n::Strings;
use crate::tui::chrome;
use crate::tui::theme;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FormMode {
    Add,
    Edit(Uuid),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AuthKind {
    Password,
    SshKey,
    /// Nothing to type: the agent holds the key and decides which one to
    /// offer, so this kind contributes no field to `fields()` at all.
    Agent,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Field {
    Name,
    Host,
    Port,
    Username,
    Tags,
    AuthType,
    JumpHost,
    Password,
    KeyPath,
    KeyPassphrase,
}

pub struct ServerFormState {
    pub mode: FormMode,
    name: String,
    host: String,
    port: String,
    username: String,
    tags: String,
    /// The bastion this host connects through, as an index into `jump_choices`
    /// — `None` is a direct connect.
    jump_host: Option<usize>,
    /// Every entry this one may point at, captured when the form opened.
    ///
    /// Held rather than threaded per call (the way `ServerSort` is) because the
    /// form needs a *name* to draw for an id, and because the set cannot change
    /// while the form is on screen. Already filtered: the entry being edited
    /// and anything that would close a loop are not in here, since offering a
    /// choice that submit would then refuse is the worse design.
    jump_choices: Vec<(Uuid, String)>,
    auth_kind: AuthKind,
    password: Zeroizing<String>,
    key_path: String,
    key_passphrase: Zeroizing<String>,
    focus: Field,
    pub error: Option<String>,
}

pub struct ServerFormData {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub tags: Vec<String>,
    pub auth: AuthMethod,
    pub jump_host: Option<Uuid>,
}

/// Splits the comma-separated tag field.
///
/// Blanks are dropped and duplicates collapse, so `a,,a, b` is `["a", "b"]` —
/// a trailing comma while typing is the normal case, not an error worth
/// stopping the save for. Case is preserved: what the user typed is what the
/// list shows, and matching and sorting fold case themselves.
fn parse_tags(raw: &str) -> Vec<String> {
    let mut tags: Vec<String> = Vec::new();
    for tag in raw.split(',').map(str::trim).filter(|t| !t.is_empty()) {
        if !tags.iter().any(|t| t.eq_ignore_ascii_case(tag)) {
            tags.push(tag.to_string());
        }
    }
    tags
}

pub enum FormOutcome {
    None,
    Cancel,
    Submit(ServerFormData),
}

/// Every server `subject` may be pointed at, excluding itself and anything
/// that would close a loop.
///
/// Filtering here rather than validating on submit is the point: a choice the
/// form would then refuse is a choice it should never have offered. The walk
/// is the same one `ssh::Target::from_entry` does — a candidate is unusable
/// exactly when following *its* chain arrives back at `subject`.
fn jump_candidates(subject: Uuid, servers: &[ServerEntry]) -> Vec<(Uuid, String)> {
    servers
        .iter()
        .filter(|c| c.id != subject && !reaches(c, subject, servers))
        .map(|c| (c.id, c.name.clone()))
        .collect()
}

/// Whether `from`'s own jump chain passes through `target`.
///
/// Bounded by the number of servers rather than by a chain length: a chain
/// already containing a cycle would otherwise spin here, and this runs on a
/// vault that may already hold one from an older build.
fn reaches(from: &ServerEntry, target: Uuid, servers: &[ServerEntry]) -> bool {
    let mut at = from;
    for _ in 0..servers.len() {
        let Some(next_id) = at.jump_host else { return false };
        if next_id == target {
            return true;
        }
        let Some(next) = servers.iter().find(|s| s.id == next_id) else { return false };
        at = next;
    }
    false
}

impl ServerFormState {
    pub fn new_add(servers: &[ServerEntry]) -> Self {
        Self {
            mode: FormMode::Add,
            name: String::new(),
            host: String::new(),
            port: "22".to_string(),
            username: String::new(),
            tags: String::new(),
            jump_host: None,
            // A new entry has no id yet, so nothing can point back at it and
            // every existing server is a candidate.
            jump_choices: servers.iter().map(|s| (s.id, s.name.clone())).collect(),
            auth_kind: AuthKind::Password,
            password: Zeroizing::new(String::new()),
            key_path: String::new(),
            key_passphrase: Zeroizing::new(String::new()),
            focus: Field::Name,
            error: None,
        }
    }

    pub fn new_edit(entry: &ServerEntry, servers: &[ServerEntry]) -> Self {
        let (auth_kind, password, key_path, key_passphrase) = match &entry.auth {
            AuthMethod::Password { password } => (
                AuthKind::Password,
                Zeroizing::new(password.as_str().to_string()),
                String::new(),
                Zeroizing::new(String::new()),
            ),
            AuthMethod::SshKey { key_path, passphrase } => (
                AuthKind::SshKey,
                Zeroizing::new(String::new()),
                key_path.clone(),
                Zeroizing::new(passphrase.as_ref().map(|p| p.as_str().to_string()).unwrap_or_default()),
            ),
            AuthMethod::Agent => (
                AuthKind::Agent,
                Zeroizing::new(String::new()),
                String::new(),
                Zeroizing::new(String::new()),
            ),
        };

        let jump_choices = jump_candidates(entry.id, servers);
        Self {
            mode: FormMode::Edit(entry.id),
            name: entry.name.clone(),
            host: entry.host.clone(),
            port: entry.port.to_string(),
            username: entry.username.clone(),
            tags: entry.tags.join(", "),
            jump_host: entry.jump_host.and_then(|id| jump_choices.iter().position(|(c, _)| *c == id)),
            jump_choices,
            auth_kind,
            password,
            key_path,
            key_passphrase,
            focus: Field::Name,
            error: None,
        }
    }

    fn fields(&self) -> Vec<Field> {
        let mut f = vec![Field::Name, Field::Host, Field::Port, Field::Username, Field::Tags, Field::AuthType];
        // Only when there is somewhere to go: a one-server vault has no
        // bastion to offer, and an unusable row is worse than no row.
        if !self.jump_choices.is_empty() {
            f.push(Field::JumpHost);
        }
        match self.auth_kind {
            AuthKind::Password => f.push(Field::Password),
            AuthKind::SshKey => {
                f.push(Field::KeyPath);
                f.push(Field::KeyPassphrase);
            }
            // Deliberately nothing. `Enter` on the auth row therefore submits,
            // because it is then the last field — the right behaviour for a
            // form that has nothing left to ask.
            AuthKind::Agent => {}
        }
        f
    }

    pub fn handle_key(&mut self, key: KeyEvent, strings: &Strings) -> FormOutcome {
        self.error = None;
        match key.code {
            KeyCode::Esc => return FormOutcome::Cancel,
            KeyCode::Tab => self.move_focus(1),
            KeyCode::BackTab => self.move_focus(-1),
            KeyCode::Left if self.focus == Field::AuthType => self.cycle_auth_kind(false),
            KeyCode::Right if self.focus == Field::AuthType => self.cycle_auth_kind(true),
            KeyCode::Left if self.focus == Field::JumpHost => self.cycle_jump_host(false),
            KeyCode::Right if self.focus == Field::JumpHost => self.cycle_jump_host(true),
            KeyCode::Enter if key.modifiers.contains(KeyModifiers::CONTROL) => return self.submit(strings),
            KeyCode::Enter => {
                let fields = self.fields();
                if fields.last() == Some(&self.focus) {
                    return self.submit(strings);
                }
                self.move_focus(1);
            }
            KeyCode::Backspace => {
                if let Some(buf) = self.active_buffer_mut() {
                    buf.pop();
                }
            }
            KeyCode::Char(c) if !matches!(self.focus, Field::AuthType | Field::JumpHost) => {
                if let Some(buf) = self.active_buffer_mut() {
                    buf.push(c);
                }
            }
            _ => {}
        }
        FormOutcome::None
    }

    fn move_focus(&mut self, delta: i32) {
        let fields = self.fields();
        let Some(current_idx) = fields.iter().position(|f| *f == self.focus) else {
            self.focus = fields[0];
            return;
        };
        let len = fields.len() as i32;
        let next = (current_idx as i32 + delta).rem_euclid(len) as usize;
        self.focus = fields[next];
    }

    /// Cycles rather than toggles, since there are three kinds now. Left and
    /// Right go opposite ways, so no kind sits two presses away in both
    /// directions.
    fn cycle_auth_kind(&mut self, forward: bool) {
        self.auth_kind = match (self.auth_kind, forward) {
            (AuthKind::Password, true) => AuthKind::SshKey,
            (AuthKind::SshKey, true) => AuthKind::Agent,
            (AuthKind::Agent, true) => AuthKind::Password,
            (AuthKind::Password, false) => AuthKind::Agent,
            (AuthKind::SshKey, false) => AuthKind::Password,
            (AuthKind::Agent, false) => AuthKind::SshKey,
        };
    }

    /// Steps through `(direct) -> each candidate -> (direct)`. The empty end
    /// is a real stop on the cycle rather than a separate key, so clearing a
    /// bastion needs no binding of its own.
    fn cycle_jump_host(&mut self, forward: bool) {
        let len = self.jump_choices.len();
        if len == 0 {
            return;
        }
        // One longer than the list: index `len` is "(direct)".
        let at = self.jump_host.map_or(len, |i| i);
        let next = if forward { (at + 1) % (len + 1) } else { (at + len) % (len + 1) };
        self.jump_host = (next < len).then_some(next);
    }

    fn active_buffer_mut(&mut self) -> Option<&mut String> {
        match self.focus {
            Field::Name => Some(&mut self.name),
            Field::Host => Some(&mut self.host),
            Field::Port => Some(&mut self.port),
            Field::Username => Some(&mut self.username),
            Field::Tags => Some(&mut self.tags),
            Field::Password => Some(&mut self.password),
            Field::KeyPath => Some(&mut self.key_path),
            Field::KeyPassphrase => Some(&mut self.key_passphrase),
            Field::AuthType | Field::JumpHost => None,
        }
    }

    fn submit(&mut self, strings: &Strings) -> FormOutcome {
        if self.name.trim().is_empty() {
            self.error = Some(strings.err_name_empty.to_string());
            return FormOutcome::None;
        }
        if self.host.trim().is_empty() {
            self.error = Some(strings.err_host_empty.to_string());
            return FormOutcome::None;
        }
        let port: u16 = match self.port.trim().parse() {
            Ok(p) if p > 0 => p,
            _ => {
                self.error = Some(strings.err_port_invalid.to_string());
                return FormOutcome::None;
            }
        };
        if self.username.trim().is_empty() {
            self.error = Some(strings.err_username_empty.to_string());
            return FormOutcome::None;
        }

        let auth = match self.auth_kind {
            AuthKind::Password => {
                if self.password.is_empty() {
                    self.error = Some(strings.err_form_password_empty.to_string());
                    return FormOutcome::None;
                }
                AuthMethod::password(self.password.to_string())
            }
            AuthKind::SshKey => {
                if self.key_path.trim().is_empty() {
                    self.error = Some(strings.err_key_path_empty.to_string());
                    return FormOutcome::None;
                }
                let passphrase = if self.key_passphrase.is_empty() {
                    None
                } else {
                    Some(Secret::from(self.key_passphrase.to_string()))
                };
                AuthMethod::SshKey { key_path: self.key_path.clone(), passphrase }
            }
            // No validation arm, because there is nothing here to be empty.
            AuthKind::Agent => AuthMethod::Agent,
        };

        FormOutcome::Submit(ServerFormData {
            name: self.name.trim().to_string(),
            host: self.host.trim().to_string(),
            port,
            username: self.username.trim().to_string(),
            tags: parse_tags(&self.tags),
            auth,
            jump_host: self.jump_host.map(|i| self.jump_choices[i].0),
        })
    }

    pub fn render(&self, frame: &mut Frame, area: Rect, strings: &Strings) {
        let title = match self.mode {
            FormMode::Add => strings.form_title_add,
            FormMode::Edit(_) => strings.form_title_edit,
        };

        let field_line = |label: &str, value: String, field: Field, this: &Self| {
            let cursor = if this.focus == field { "_" } else { "" };
            let style = if this.focus == field {
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
            field_line(strings.field_name, self.name.clone(), Field::Name, self),
            field_line(strings.field_host, self.host.clone(), Field::Host, self),
            field_line(strings.field_port, self.port.clone(), Field::Port, self),
            field_line(strings.field_username, self.username.clone(), Field::Username, self),
            field_line(strings.field_tags, self.tags.clone(), Field::Tags, self),
            field_line(
                strings.field_auth_type,
                match self.auth_kind {
                    AuthKind::Password => strings.auth_label_password.to_string(),
                    AuthKind::SshKey => strings.auth_label_key.to_string(),
                    AuthKind::Agent => strings.auth_label_agent.to_string(),
                },
                Field::AuthType,
                self,
            ),
        ];

        // `fields()` puts this straight after the auth type when there is
        // anywhere to go, so the `lines` vec has to as well — the two orders
        // are what `focus_row` below relies on.
        if !self.jump_choices.is_empty() {
            let via = match self.jump_host {
                Some(i) => self.jump_choices[i].1.clone(),
                None => strings.jump_host_none.to_string(),
            };
            lines.push(field_line(strings.field_jump_host, via, Field::JumpHost, self));
        }

        match self.auth_kind {
            AuthKind::Password => {
                lines.push(field_line(strings.field_password, mask(&self.password), Field::Password, self));
            }
            AuthKind::SshKey => {
                lines.push(field_line(strings.field_key_path, self.key_path.clone(), Field::KeyPath, self));
                lines.push(field_line(
                    strings.field_key_passphrase,
                    mask(&self.key_passphrase),
                    Field::KeyPassphrase,
                    self,
                ));
            }
            AuthKind::Agent => {}
        }

        lines.push(Line::from(""));
        if let Some(err) = &self.error {
            lines.push(Line::from(Span::styled(err.clone(), Style::default().fg(theme::error()))));
        }

        // `fields()` and `lines` are built in the same order, so the focused
        // field's index is its row — that is what `render_form` scrolls to.
        let focus_row = self.fields().iter().position(|f| *f == self.focus).unwrap_or(0);
        let body = chrome::render(frame, area, title, vec![Line::from(Span::styled(strings.form_hint, Style::default().fg(theme::hint())))], strings);
        render_form(frame, body, title, lines, focus_row, strings.terminal_too_small);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::EN;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn render(state: &ServerFormState, width: u16, height: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("test backend");
        terminal
            .draw(|frame| state.render(frame, frame.area(), &EN))
            .expect("render");
        terminal.backend().buffer().content().iter().map(|c| c.symbol()).collect()
    }

    /// The agent kind contributes no field, which makes `Field::AuthType` the
    /// last one — so `Enter` there submits rather than moving focus into
    /// nothing. Both halves of that matter, and neither is visible from the
    /// enum alone.
    #[test]
    fn the_agent_kind_asks_for_nothing_and_submits_from_the_auth_row() {
        let mut state = ServerFormState::new_add(&[]);
        state.name = "box".into();
        state.host = "example.com".into();
        state.username = "root".into();

        tab_to(&mut state, Field::AuthType);
        // password -> ssh-key -> agent
        state.handle_key(KeyEvent::from(KeyCode::Right), &EN);
        state.handle_key(KeyEvent::from(KeyCode::Right), &EN);

        assert_eq!(state.fields().last(), Some(&Field::AuthType), "the agent kind adds no field of its own");
        assert!(!render(&state, 80, 24).contains(EN.field_key_path), "no key path to fill in");

        match state.handle_key(KeyEvent::from(KeyCode::Enter), &EN) {
            FormOutcome::Submit(data) => assert!(matches!(data.auth, AuthMethod::Agent)),
            _ => panic!("Enter on the last field must submit"),
        }
    }

    /// Left and Right must not both be "next", or the third kind sits two
    /// presses away whichever way you turn.
    #[test]
    fn the_auth_kind_cycles_both_ways() {
        let mut state = ServerFormState::new_add(&[]);
        tab_to(&mut state, Field::AuthType);
        assert_eq!(state.auth_kind, AuthKind::Password);

        state.handle_key(KeyEvent::from(KeyCode::Left), &EN);
        assert_eq!(state.auth_kind, AuthKind::Agent, "Left from the first kind wraps to the last");
        state.handle_key(KeyEvent::from(KeyCode::Right), &EN);
        assert_eq!(state.auth_kind, AuthKind::Password);
    }

    fn server(name: &str) -> ServerEntry {
        ServerEntry::new(name.into(), format!("{name}.example.com"), 22, "root".into(), AuthMethod::Agent)
    }

    /// Offering a choice that submit would then refuse is the worse design, so
    /// the loop-formers are gone from the list rather than caught later.
    #[test]
    fn the_jump_candidates_exclude_self_and_anything_that_would_close_a_loop() {
        // behind -> bastion, so bastion must not be offered `behind`.
        let mut servers = vec![server("bastion"), server("behind"), server("unrelated")];
        let bastion_id = servers[0].id;
        servers[1].jump_host = Some(bastion_id);

        let state = ServerFormState::new_edit(&servers[0], &servers);
        let names: Vec<_> = state.jump_choices.iter().map(|(_, n)| n.as_str()).collect();
        assert_eq!(names, ["unrelated"], "self and the host behind it are both out");
    }

    /// A vault holding a cycle from an older build must not hang the form.
    #[test]
    fn a_cycle_already_in_the_vault_does_not_spin_the_candidate_walk() {
        let mut servers = vec![server("a"), server("b")];
        let (a, b) = (servers[0].id, servers[1].id);
        servers[0].jump_host = Some(b);
        servers[1].jump_host = Some(a);
        assert!(ServerFormState::new_edit(&servers[0], &servers).jump_choices.is_empty());
    }

    /// `(direct)` is a stop on the cycle rather than a key of its own, so
    /// clearing a bastion needs no extra binding — and the row only exists
    /// when there is somewhere to go.
    #[test]
    fn the_jump_row_cycles_through_direct_and_is_absent_with_no_candidates() {
        assert!(!ServerFormState::new_add(&[]).fields().contains(&Field::JumpHost));

        let servers = vec![server("bastion")];
        let mut state = ServerFormState::new_add(&servers);
        tab_to(&mut state, Field::JumpHost);
        assert_eq!(state.jump_host, None);

        state.handle_key(KeyEvent::from(KeyCode::Right), &EN);
        assert_eq!(state.jump_host, Some(0));
        state.handle_key(KeyEvent::from(KeyCode::Right), &EN);
        assert_eq!(state.jump_host, None, "one candidate means two stops, and it wraps");
        state.handle_key(KeyEvent::from(KeyCode::Left), &EN);
        assert_eq!(state.jump_host, Some(0));
    }

    /// The row has to appear in `fields()` and in `lines` at the same index,
    /// or `render_form` scrolls to a different row than the one with focus.
    #[test]
    fn the_jump_row_is_drawn_where_the_focus_order_puts_it() {
        let servers = vec![server("bastion")];
        let mut state = ServerFormState::new_add(&servers);
        tab_to(&mut state, Field::JumpHost);
        let screen = render(&state, 80, 24);
        assert!(screen.contains(EN.jump_host_none), "the direct end of the cycle is drawn");
        assert_eq!(state.fields().iter().position(|f| *f == Field::JumpHost), Some(6));
    }

    fn tab_to(state: &mut ServerFormState, field: Field) {
        for _ in 0..state.fields().len() {
            if state.focus == field {
                return;
            }
            state.handle_key(KeyEvent::from(KeyCode::Tab), &EN);
        }
        panic!("{field:?} is not in the focus order");
    }

    /// The issue's acceptance criterion: the field taking keystrokes must be on
    /// screen. Before this the form was drawn full height and the bottom fields
    /// were silently cut off, so focus could sit on a field nobody could see.
    #[test]
    fn the_focused_field_stays_on_screen_when_the_form_does_not_fit() {
        let mut state = ServerFormState::new_add(&[]);
        tab_to(&mut state, Field::Password);

        // Seven rows: two for the border, five for eight lines of form.
        let rendered = render(&state, 60, 7);
        assert!(rendered.contains(EN.field_password), "the focused field must be visible");
        assert!(!rendered.contains(EN.field_name), "the top of the form has scrolled off");
    }

    /// Scrolled content is only honest if the frame says there is more.
    #[test]
    fn a_clamped_form_says_there_is_more_above() {
        let mut state = ServerFormState::new_add(&[]);
        tab_to(&mut state, Field::Password);
        assert!(render(&state, 60, 7).contains('↑'));

        let fits = ServerFormState::new_add(&[]);
        let full = render(&fits, 60, 20);
        assert!(!full.contains('↑') && !full.contains('↓'), "a form that fits gets no arrows");
    }

    /// Below the minimum there is no honest way to draw the form, so it says so
    /// rather than rendering a frame with nothing in it.
    #[test]
    fn a_frame_too_small_for_the_form_says_so() {
        let state = ServerFormState::new_add(&[]);
        let rendered = render(&state, 60, 4);
        assert!(rendered.contains("too small"));
        assert!(!rendered.contains(EN.field_name));
    }

    /// A trailing comma is what typing looks like halfway through, not an
    /// error worth refusing the save for.
    #[test]
    fn the_tag_field_tolerates_how_people_actually_type_it() {
        assert_eq!(parse_tags("prod, eu-west , "), vec!["prod", "eu-west"]);
        assert_eq!(parse_tags(""), Vec::<String>::new());
        assert_eq!(parse_tags(" , ,"), Vec::<String>::new());
    }

    /// Duplicates collapse case-insensitively, but the first spelling wins —
    /// the list shows what the user typed.
    #[test]
    fn duplicate_tags_collapse_and_keep_the_first_spelling() {
        assert_eq!(parse_tags("Prod, prod, PROD"), vec!["Prod"]);
    }

    #[test]
    fn editing_an_entry_shows_its_tags_back() {
        let mut entry = ServerEntry::new("box".into(), "h".into(), 22, "root".into(), AuthMethod::password("x"));
        entry.tags = vec!["prod".into(), "eu".into()];
        let state = ServerFormState::new_edit(&entry, &[]);
        assert!(render(&state, 60, 20).contains("prod, eu"));
    }
}
