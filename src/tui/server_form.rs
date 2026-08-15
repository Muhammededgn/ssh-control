use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::widgets::{mask, render_form};
use crate::config::{AuthMethod, Secret, ServerEntry};
use crate::i18n::Strings;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FormMode {
    Add,
    Edit(Uuid),
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AuthKind {
    Password,
    SshKey,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Field {
    Name,
    Host,
    Port,
    Username,
    AuthType,
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
    pub auth: AuthMethod,
}

pub enum FormOutcome {
    None,
    Cancel,
    Submit(ServerFormData),
}

impl ServerFormState {
    pub fn new_add() -> Self {
        Self {
            mode: FormMode::Add,
            name: String::new(),
            host: String::new(),
            port: "22".to_string(),
            username: String::new(),
            auth_kind: AuthKind::Password,
            password: Zeroizing::new(String::new()),
            key_path: String::new(),
            key_passphrase: Zeroizing::new(String::new()),
            focus: Field::Name,
            error: None,
        }
    }

    pub fn new_edit(entry: &ServerEntry) -> Self {
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
        };

        Self {
            mode: FormMode::Edit(entry.id),
            name: entry.name.clone(),
            host: entry.host.clone(),
            port: entry.port.to_string(),
            username: entry.username.clone(),
            auth_kind,
            password,
            key_path,
            key_passphrase,
            focus: Field::Name,
            error: None,
        }
    }

    fn fields(&self) -> Vec<Field> {
        let mut f = vec![Field::Name, Field::Host, Field::Port, Field::Username, Field::AuthType];
        match self.auth_kind {
            AuthKind::Password => f.push(Field::Password),
            AuthKind::SshKey => {
                f.push(Field::KeyPath);
                f.push(Field::KeyPassphrase);
            }
        }
        f
    }

    pub fn handle_key(&mut self, key: KeyEvent, strings: &Strings) -> FormOutcome {
        self.error = None;
        match key.code {
            KeyCode::Esc => return FormOutcome::Cancel,
            KeyCode::Tab => self.move_focus(1),
            KeyCode::BackTab => self.move_focus(-1),
            KeyCode::Left if self.focus == Field::AuthType => self.toggle_auth_kind(),
            KeyCode::Right if self.focus == Field::AuthType => self.toggle_auth_kind(),
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
            KeyCode::Char(c) if self.focus != Field::AuthType => {
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

    fn toggle_auth_kind(&mut self) {
        self.auth_kind = match self.auth_kind {
            AuthKind::Password => AuthKind::SshKey,
            AuthKind::SshKey => AuthKind::Password,
        };
    }

    fn active_buffer_mut(&mut self) -> Option<&mut String> {
        match self.focus {
            Field::Name => Some(&mut self.name),
            Field::Host => Some(&mut self.host),
            Field::Port => Some(&mut self.port),
            Field::Username => Some(&mut self.username),
            Field::Password => Some(&mut self.password),
            Field::KeyPath => Some(&mut self.key_path),
            Field::KeyPassphrase => Some(&mut self.key_passphrase),
            Field::AuthType => None,
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
        };

        FormOutcome::Submit(ServerFormData {
            name: self.name.trim().to_string(),
            host: self.host.trim().to_string(),
            port,
            username: self.username.trim().to_string(),
            auth,
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
            field_line(strings.field_name, self.name.clone(), Field::Name, self),
            field_line(strings.field_host, self.host.clone(), Field::Host, self),
            field_line(strings.field_port, self.port.clone(), Field::Port, self),
            field_line(strings.field_username, self.username.clone(), Field::Username, self),
            field_line(
                strings.field_auth_type,
                match self.auth_kind {
                    AuthKind::Password => "password".to_string(),
                    AuthKind::SshKey => "ssh-key".to_string(),
                },
                Field::AuthType,
                self,
            ),
        ];

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
        }

        lines.push(Line::from(""));
        if let Some(err) = &self.error {
            lines.push(Line::from(Span::styled(err.clone(), Style::default().fg(Color::Red))));
        } else {
            lines.push(Line::from(Span::styled(
                strings.form_hint,
                Style::default().fg(Color::DarkGray),
            )));
        }

        // `fields()` and `lines` are built in the same order, so the focused
        // field's index is its row — that is what `render_form` scrolls to.
        let focus_row = self.fields().iter().position(|f| *f == self.focus).unwrap_or(0);
        render_form(frame, area, title, lines, focus_row, strings.terminal_too_small);
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
        let mut state = ServerFormState::new_add();
        tab_to(&mut state, Field::Password);

        // Seven rows: two for the border, five for eight lines of form.
        let rendered = render(&state, 60, 7);
        assert!(rendered.contains(EN.field_password), "the focused field must be visible");
        assert!(!rendered.contains(EN.field_name), "the top of the form has scrolled off");
    }

    /// Scrolled content is only honest if the frame says there is more.
    #[test]
    fn a_clamped_form_says_there_is_more_above() {
        let mut state = ServerFormState::new_add();
        tab_to(&mut state, Field::Password);
        assert!(render(&state, 60, 7).contains('↑'));

        let fits = ServerFormState::new_add();
        let full = render(&fits, 60, 20);
        assert!(!full.contains('↑') && !full.contains('↓'), "a form that fits gets no arrows");
    }

    /// Below the minimum there is no honest way to draw the form, so it says so
    /// rather than rendering a frame with nothing in it.
    #[test]
    fn a_frame_too_small_for_the_form_says_so() {
        let state = ServerFormState::new_add();
        let rendered = render(&state, 60, 4);
        assert!(rendered.contains("too small"));
        assert!(!rendered.contains(EN.field_name));
    }
}
