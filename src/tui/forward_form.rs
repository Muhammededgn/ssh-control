//! Adding or editing one port forward.
//!
//! Modelled on `server_form`: a `Field` enum, a non-text `Field::Kind` cycled
//! with ←/→, and `fields()` and the `lines` vec built in the same order —
//! `render_form` scrolls by an index into that list, so the two orders are one
//! order.
//!
//! `Dynamic` drops the destination rows from both. A SOCKS proxy's destination
//! is whatever each client asks for, so there is nothing to type; leaving two
//! greyed rows on screen would suggest otherwise.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use uuid::Uuid;

use super::widgets::render_form;
use crate::config::model::DEFAULT_BIND_ADDR;
use crate::config::{ForwardKind, ForwardRule};
use crate::i18n::Strings;
use crate::tui::chrome;
use crate::tui::theme;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FormMode {
    Add,
    Edit(Uuid),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Local,
    Remote,
    Dynamic,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Field {
    Kind,
    BindAddr,
    BindPort,
    DestHost,
    DestPort,
}

pub struct ForwardFormState {
    pub server_id: Uuid,
    pub mode: FormMode,
    kind: Kind,
    bind_addr: String,
    bind_port: String,
    dest_host: String,
    dest_port: String,
    focus: Field,
    pub error: Option<String>,
}

pub struct ForwardFormData {
    pub id: Option<Uuid>,
    pub kind: ForwardKind,
}

pub enum ForwardFormOutcome {
    None,
    Cancel,
    Submit(ForwardFormData),
}

impl ForwardFormState {
    pub fn new_add(server_id: Uuid) -> Self {
        Self {
            server_id,
            mode: FormMode::Add,
            kind: Kind::Local,
            // Loopback, never `0.0.0.0` — see `model::DEFAULT_BIND_ADDR`. It is
            // pre-filled rather than left blank so the safe answer is the one
            // that costs nothing, and widening it is a deliberate edit.
            bind_addr: DEFAULT_BIND_ADDR.to_string(),
            bind_port: String::new(),
            dest_host: String::new(),
            dest_port: String::new(),
            focus: Field::Kind,
            error: None,
        }
    }

    pub fn new_edit(server_id: Uuid, rule: &ForwardRule) -> Self {
        let (kind, bind_addr, bind_port, dest_host, dest_port) = match &rule.kind {
            ForwardKind::Local { bind_addr, bind_port, dest_host, dest_port } => {
                (Kind::Local, bind_addr.clone(), *bind_port, dest_host.clone(), *dest_port)
            }
            ForwardKind::Remote { bind_addr, bind_port, dest_host, dest_port } => {
                (Kind::Remote, bind_addr.clone(), *bind_port, dest_host.clone(), *dest_port)
            }
            ForwardKind::Dynamic { bind_addr, bind_port } => (Kind::Dynamic, bind_addr.clone(), *bind_port, String::new(), 0),
        };
        Self {
            server_id,
            mode: FormMode::Edit(rule.id),
            kind,
            bind_addr,
            bind_port: bind_port.to_string(),
            dest_host,
            // A `Dynamic` rule has no destination port, and `0` is not a value
            // the user typed — it must come back as an empty field, not a zero.
            dest_port: if kind == Kind::Dynamic { String::new() } else { dest_port.to_string() },
            focus: Field::Kind,
            error: None,
        }
    }

    fn fields(&self) -> Vec<Field> {
        let mut f = vec![Field::Kind, Field::BindAddr, Field::BindPort];
        if self.kind != Kind::Dynamic {
            f.push(Field::DestHost);
            f.push(Field::DestPort);
        }
        f
    }

    pub fn handle_key(&mut self, key: KeyEvent, strings: &Strings) -> ForwardFormOutcome {
        self.error = None;
        match key.code {
            KeyCode::Esc => return ForwardFormOutcome::Cancel,
            KeyCode::Tab => self.move_focus(1),
            KeyCode::BackTab => self.move_focus(-1),
            KeyCode::Left if self.focus == Field::Kind => self.cycle_kind(false),
            KeyCode::Right if self.focus == Field::Kind => self.cycle_kind(true),
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
            KeyCode::Char(c) if self.focus != Field::Kind => {
                if let Some(buf) = self.active_buffer_mut() {
                    buf.push(c);
                }
            }
            _ => {}
        }
        ForwardFormOutcome::None
    }

    fn move_focus(&mut self, delta: i32) {
        let fields = self.fields();
        let at = fields.iter().position(|f| *f == self.focus).unwrap_or(0) as i32;
        let next = (at + delta).rem_euclid(fields.len() as i32) as usize;
        self.focus = fields[next];
    }

    fn cycle_kind(&mut self, forward: bool) {
        self.kind = match (self.kind, forward) {
            (Kind::Local, true) => Kind::Remote,
            (Kind::Remote, true) => Kind::Dynamic,
            (Kind::Dynamic, true) => Kind::Local,
            (Kind::Local, false) => Kind::Dynamic,
            (Kind::Remote, false) => Kind::Local,
            (Kind::Dynamic, false) => Kind::Remote,
        };
        // Cycling to a kind that does not have the focused field would leave
        // focus on a row that is no longer drawn.
        if !self.fields().contains(&self.focus) {
            self.focus = Field::Kind;
        }
    }

    fn active_buffer_mut(&mut self) -> Option<&mut String> {
        match self.focus {
            Field::BindAddr => Some(&mut self.bind_addr),
            Field::BindPort => Some(&mut self.bind_port),
            Field::DestHost => Some(&mut self.dest_host),
            Field::DestPort => Some(&mut self.dest_port),
            Field::Kind => None,
        }
    }

    fn submit(&mut self, strings: &Strings) -> ForwardFormOutcome {
        // An empty bind address means "every interface" to the OS, so it is
        // filled back in rather than passed through: the default exists to be
        // hard to lose, not merely to be offered.
        let bind_addr = match self.bind_addr.trim() {
            "" => DEFAULT_BIND_ADDR.to_string(),
            typed => typed.to_string(),
        };
        let Some(bind_port) = port(&self.bind_port) else {
            self.error = Some(strings.err_forward_port_invalid.to_string());
            return ForwardFormOutcome::None;
        };

        let kind = if self.kind == Kind::Dynamic {
            ForwardKind::Dynamic { bind_addr, bind_port }
        } else {
            if self.dest_host.trim().is_empty() {
                self.error = Some(strings.err_forward_dest_empty.to_string());
                return ForwardFormOutcome::None;
            }
            let Some(dest_port) = port(&self.dest_port) else {
                self.error = Some(strings.err_forward_port_invalid.to_string());
                return ForwardFormOutcome::None;
            };
            let dest_host = self.dest_host.trim().to_string();
            match self.kind {
                Kind::Local => ForwardKind::Local { bind_addr, bind_port, dest_host, dest_port },
                _ => ForwardKind::Remote { bind_addr, bind_port, dest_host, dest_port },
            }
        };

        let id = match self.mode {
            FormMode::Add => None,
            FormMode::Edit(id) => Some(id),
        };
        ForwardFormOutcome::Submit(ForwardFormData { id, kind })
    }

    pub fn render(&self, frame: &mut Frame, area: Rect, strings: &Strings) {
        let title = match self.mode {
            FormMode::Add => strings.forward_form_title_add,
            FormMode::Edit(_) => strings.forward_form_title_edit,
        };

        let field_line = |label: &str, value: String, field: Field, this: &Self| {
            let cursor = if this.focus == field { "_" } else { "" };
            let style = if this.focus == field { Style::default().fg(theme::accent()) } else { Style::default() };
            Line::from(vec![Span::styled(format!("{label}: "), style), Span::raw(format!("{value}{cursor}"))])
        };

        let kind_label = match self.kind {
            Kind::Local => "-L (local)",
            Kind::Remote => "-R (remote)",
            Kind::Dynamic => "-D (dynamic / SOCKS5)",
        };

        let mut lines = vec![
            field_line(strings.field_forward_kind, kind_label.to_string(), Field::Kind, self),
            field_line(strings.field_bind_addr, self.bind_addr.clone(), Field::BindAddr, self),
            field_line(strings.field_bind_port, self.bind_port.clone(), Field::BindPort, self),
        ];
        if self.kind != Kind::Dynamic {
            lines.push(field_line(strings.field_dest_host, self.dest_host.clone(), Field::DestHost, self));
            lines.push(field_line(strings.field_dest_port, self.dest_port.clone(), Field::DestPort, self));
        }

        lines.push(Line::from(""));
        if let Some(err) = &self.error {
            lines.push(Line::from(Span::styled(err.clone(), Style::default().fg(theme::error()))));
        }

        let focus_row = self.fields().iter().position(|f| *f == self.focus).unwrap_or(0);
        let footer = vec![Line::from(Span::styled(strings.forward_form_hint, Style::default().fg(theme::hint())))];
        let body = chrome::render(frame, area, title, footer, strings);
        render_form(frame, body, title, lines, focus_row, strings.terminal_too_small);
    }
}

/// A port, or `None` for anything that is not one.
///
/// `0` is refused. The OS reads it as "pick one for me", and a rule whose port
/// changes every session is a rule the user cannot connect to.
fn port(text: &str) -> Option<u16> {
    text.trim().parse::<u16>().ok().filter(|p| *p > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::EN;

    fn submit(state: &mut ForwardFormState) -> ForwardFormOutcome {
        state.handle_key(KeyEvent::from(KeyCode::Enter).into_ctrl(), &EN)
    }

    trait Ctrl {
        fn into_ctrl(self) -> KeyEvent;
    }
    impl Ctrl for KeyEvent {
        fn into_ctrl(mut self) -> KeyEvent {
            self.modifiers = KeyModifiers::CONTROL;
            self
        }
    }

    fn typed(state: &mut ForwardFormState, field: Field, text: &str) {
        state.focus = field;
        for c in text.chars() {
            state.handle_key(KeyEvent::from(KeyCode::Char(c)), &EN);
        }
    }

    /// The one decision here that is a security property rather than a
    /// preference: a rule that binds every interface has to be typed, never
    /// arrived at by leaving a field alone.
    #[test]
    fn the_bind_address_defaults_to_loopback_and_an_emptied_field_goes_back_to_it() {
        let mut state = ForwardFormState::new_add(Uuid::new_v4());
        assert_eq!(state.bind_addr, "127.0.0.1");

        state.bind_addr.clear();
        typed(&mut state, Field::BindPort, "8080");
        typed(&mut state, Field::DestHost, "db.internal");
        typed(&mut state, Field::DestPort, "5432");
        match submit(&mut state) {
            ForwardFormOutcome::Submit(data) => match data.kind {
                ForwardKind::Local { bind_addr, .. } => assert_eq!(bind_addr, "127.0.0.1"),
                other => panic!("expected a local forward, got {other:?}"),
            },
            _ => panic!("expected a submit"),
        }
    }

    /// A SOCKS proxy's destination comes from each client, so there is nothing
    /// to type — and leaving the rows on screen would suggest otherwise.
    #[test]
    fn the_dynamic_kind_drops_the_destination_rows_and_submits_without_them() {
        let mut state = ForwardFormState::new_add(Uuid::new_v4());
        state.focus = Field::Kind;
        state.handle_key(KeyEvent::from(KeyCode::Right), &EN);
        state.handle_key(KeyEvent::from(KeyCode::Right), &EN);
        assert_eq!(state.kind, Kind::Dynamic);
        assert_eq!(state.fields(), vec![Field::Kind, Field::BindAddr, Field::BindPort]);

        typed(&mut state, Field::BindPort, "1080");
        match submit(&mut state) {
            ForwardFormOutcome::Submit(data) => assert!(matches!(data.kind, ForwardKind::Dynamic { bind_port: 1080, .. })),
            _ => panic!("expected a submit"),
        }
    }

    /// Cycling away from a kind must not leave focus on a row that is no
    /// longer drawn — `render_form` scrolls to `focus_row`, and there would be
    /// no row at that index.
    #[test]
    fn cycling_to_dynamic_moves_focus_off_a_row_that_is_gone() {
        let mut state = ForwardFormState::new_add(Uuid::new_v4());
        state.focus = Field::DestPort;
        state.focus = Field::Kind;
        state.handle_key(KeyEvent::from(KeyCode::Right), &EN);
        state.focus = Field::DestHost;
        state.focus = Field::Kind;
        state.handle_key(KeyEvent::from(KeyCode::Right), &EN);
        assert!(state.fields().contains(&state.focus));
    }

    /// `0` means "pick one for me" to the OS. A rule whose port changes every
    /// session is a rule nobody can connect to.
    #[test]
    fn port_zero_and_nonsense_are_both_refused() {
        for text in ["0", "", "http", "70000", "-1"] {
            let mut state = ForwardFormState::new_add(Uuid::new_v4());
            typed(&mut state, Field::BindPort, text);
            typed(&mut state, Field::DestHost, "db.internal");
            typed(&mut state, Field::DestPort, "5432");
            assert!(matches!(submit(&mut state), ForwardFormOutcome::None), "{text:?} must not pass");
            assert!(state.error.is_some());
        }
    }

    #[test]
    fn a_destination_is_required_for_a_local_forward() {
        let mut state = ForwardFormState::new_add(Uuid::new_v4());
        typed(&mut state, Field::BindPort, "8080");
        typed(&mut state, Field::DestPort, "5432");
        assert!(matches!(submit(&mut state), ForwardFormOutcome::None));
        assert_eq!(state.error.as_deref(), Some(EN.err_forward_dest_empty));
    }

    /// A dynamic rule has no destination port, and `0` is not something the
    /// user typed — it has to come back as an empty field.
    #[test]
    fn editing_a_dynamic_rule_shows_no_destination_port_rather_than_a_zero() {
        let rule = ForwardRule::new(ForwardKind::Dynamic { bind_addr: "127.0.0.1".into(), bind_port: 1080 });
        let state = ForwardFormState::new_edit(Uuid::new_v4(), &rule);
        assert_eq!(state.dest_port, "");
        assert_eq!(state.bind_port, "1080");
    }
}
