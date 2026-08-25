//! Picking which of `~/.ssh/config`'s hosts become vault entries.
//!
//! A checkbox list, the same shape `script_targets` is — but with one
//! difference that runs through the whole module: **this screen owns its
//! rows.** `script_targets` holds `Uuid`s rather than indices because its rows
//! live in `config.servers` and a filter or a re-sort can move them; nothing
//! moves here, because the rows were parsed once when the screen opened and
//! belong to it.
//!
//! Hosts already in the vault are **shown, dimmed and unselectable — never
//! filtered out.** A list that is quietly shorter than the file looks like a
//! parse failure, and there is no way for the user to tell the difference. A
//! greyed row saying "already added" answers the question on the row.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{ListItem, ListState};

use crate::config::ServerEntry;
use crate::i18n::Strings;
use crate::ssh_config::SshConfigHost;
use crate::tui::chrome;
use crate::tui::theme;
use crate::tui::widgets::{self, list_title_with_position, render_list_scrollbar};

pub struct SshImportState {
    rows: Vec<ImportRow>,
    selected: usize,
    list_state: ListState,
    /// Set when the file could not be read. The screen still opens — an error
    /// the user can read beats a screen that never appears.
    pub error: Option<String>,
}

struct ImportRow {
    host: SshConfigHost,
    checked: bool,
    already_present: bool,
}

pub enum SshImportOutcome {
    None,
    Cancel,
    /// The picked hosts, in the order they appear in the file.
    Import(Vec<SshConfigHost>),
    Help,
}

impl SshImportState {
    /// Builds the screen from parsed hosts and the vault as it stands.
    ///
    /// Everything importable starts checked: the overwhelmingly common case is
    /// "yes, all of them", and unchecking three is less work than checking
    /// forty.
    pub fn new(hosts: Vec<SshConfigHost>, servers: &[ServerEntry], error: Option<String>) -> Self {
        let rows = hosts
            .into_iter()
            .map(|host| {
                let already_present = servers.iter().any(|s| same_host(s, &host));
                ImportRow { host, checked: !already_present, already_present }
            })
            .collect();

        let mut list_state = ListState::default();
        list_state.select(Some(0));
        Self { rows, selected: 0, list_state, error }
    }

    /// The picked hosts, in file order.
    fn picked(&self) -> Vec<SshConfigHost> {
        self.rows.iter().filter(|r| r.checked).map(|r| r.host.clone()).collect()
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> SshImportOutcome {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                if self.selected > 0 {
                    self.selected -= 1;
                    self.list_state.select(Some(self.selected));
                }
                SshImportOutcome::None
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.selected + 1 < self.rows.len() {
                    self.selected += 1;
                    self.list_state.select(Some(self.selected));
                }
                SshImportOutcome::None
            }
            KeyCode::Char(' ') => {
                // A present host is not a choice. Silently ignoring the key is
                // right here: the row already says why.
                if let Some(row) = self.rows.get_mut(self.selected)
                    && !row.already_present
                {
                    row.checked = !row.checked;
                }
                SshImportOutcome::None
            }
            // All or none, from whichever it is not already — and "all" means
            // all the *importable* ones.
            KeyCode::Char('a') => {
                let importable = self.rows.iter().filter(|r| !r.already_present).count();
                let checked = self.rows.iter().filter(|r| r.checked).count();
                let want = checked != importable;
                for row in &mut self.rows {
                    row.checked = want && !row.already_present;
                }
                SshImportOutcome::None
            }
            KeyCode::Enter => {
                let picked = self.picked();
                // Nothing picked is a no-op rather than an error message, the
                // same as the target picker.
                if picked.is_empty() { SshImportOutcome::None } else { SshImportOutcome::Import(picked) }
            }
            KeyCode::Char('?') => SshImportOutcome::Help,
            KeyCode::Esc => SshImportOutcome::Cancel,
            _ => SshImportOutcome::None,
        }
    }

    pub fn render(&mut self, frame: &mut Frame, area: Rect, strings: &Strings) {
        let mut footer = vec![Line::from(Span::styled(strings.ssh_import_hint, Style::default().fg(theme::hint())))];
        if let Some(error) = &self.error {
            footer.push(Line::from(Span::styled(error.clone(), Style::default().fg(theme::error()))));
        }
        let body = chrome::render(frame, area, strings.ssh_import_title, footer, strings);

        let items: Vec<ListItem> = self
            .rows
            .iter()
            .map(|row| {
                let (box_, mark) = match (row.already_present, row.checked) {
                    (true, _) => ("[-]", theme::hint()),
                    (false, true) => ("[x]", theme::success()),
                    (false, false) => ("[ ]", theme::hint()),
                };
                // A present row is dim throughout, so it reads as unavailable
                // rather than merely unchecked.
                let name = if row.already_present {
                    Style::default().fg(theme::hint())
                } else {
                    Style::default().add_modifier(Modifier::BOLD)
                };
                let mut spans = vec![
                    Span::styled(format!("{box_} "), Style::default().fg(mark)),
                    Span::styled(row.host.alias.clone(), name),
                    Span::styled(format!("  {}", target_of(&row.host)), Style::default().fg(theme::hint())),
                ];
                if row.already_present {
                    spans.push(Span::styled(format!("  ({})", strings.ssh_import_already), Style::default().fg(theme::hint())));
                }
                ListItem::new(Line::from(spans))
            })
            .collect();

        let title = list_title_with_position(strings.ssh_import_title, self.selected, self.rows.len());
        widgets::render_list(frame, body, &title, items, &mut self.list_state, Some(strings.ssh_import_empty), None, true);
        render_list_scrollbar(frame, body, self.selected, self.rows.len());
    }
}

/// `user@host:port` as the file describes it, for the row.
fn target_of(host: &SshConfigHost) -> String {
    let port = host.port.unwrap_or(crate::config::model::DEFAULT_PORT);
    format!("{}@{}:{port}", host.username(), host.hostname)
}

/// Whether the vault already has this host.
///
/// Matched on where it connects — hostname, port and user — and **not** on the
/// alias. The alias is only a label; two aliases for one machine are exactly
/// the duplicate that re-running the import must not create. Hostnames fold
/// case because DNS does; the username does not, because unix accounts do not.
fn same_host(entry: &ServerEntry, host: &SshConfigHost) -> bool {
    entry.host.eq_ignore_ascii_case(&host.hostname)
        && entry.port == host.port.unwrap_or(crate::config::model::DEFAULT_PORT)
        && host.user.as_deref().is_none_or(|u| entry.username == u)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuthMethod;
    use crate::i18n::EN;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn host(alias: &str, hostname: &str, user: Option<&str>, port: Option<u16>) -> SshConfigHost {
        SshConfigHost {
            alias: alias.into(),
            hostname: hostname.into(),
            user: user.map(str::to_string),
            port,
            identity_file: None,
        }
    }

    fn vault(name: &str, hostname: &str, port: u16, user: &str) -> ServerEntry {
        ServerEntry::new(name.into(), hostname.into(), port, user.into(), AuthMethod::Agent)
    }

    fn press(state: &mut SshImportState, code: KeyCode) -> SshImportOutcome {
        state.handle_key(KeyEvent::from(code))
    }

    fn aliases(outcome: SshImportOutcome) -> Vec<String> {
        match outcome {
            SshImportOutcome::Import(hosts) => hosts.into_iter().map(|h| h.alias).collect(),
            _ => panic!("expected an import"),
        }
    }

    /// The whole no-duplicates requirement rests on this: a host already in
    /// the vault must be impossible to pick, however the user tries.
    #[test]
    fn a_host_already_in_the_vault_cannot_be_picked_by_space_or_by_a() {
        let hosts = vec![host("web", "web.example.com", Some("root"), None), host("db", "db.internal", Some("ops"), None)];
        let servers = vec![vault("already-here", "web.example.com", 22, "root")];
        let mut state = SshImportState::new(hosts, &servers, None);

        assert_eq!(aliases(press(&mut state, KeyCode::Enter)), ["db"], "a present host starts unchecked");

        press(&mut state, KeyCode::Char(' '));
        assert_eq!(aliases(press(&mut state, KeyCode::Enter)), ["db"], "Space must not check it either");

        // Everything importable is already checked, so `a` means "none" —
        // and `a` again means "all the importable ones", never the present one.
        press(&mut state, KeyCode::Char('a'));
        assert!(matches!(press(&mut state, KeyCode::Enter), SshImportOutcome::None));
        press(&mut state, KeyCode::Char('a'));
        assert_eq!(aliases(press(&mut state, KeyCode::Enter)), ["db"]);
    }

    /// It is still on screen, though — a shorter list with no explanation is
    /// indistinguishable from a parse that went wrong.
    #[test]
    fn a_present_host_is_shown_with_its_reason_rather_than_hidden() {
        let hosts = vec![host("web", "web.example.com", Some("root"), None)];
        let servers = vec![vault("already-here", "web.example.com", 22, "root")];
        let mut state = SshImportState::new(hosts, &servers, None);

        let mut terminal = Terminal::new(TestBackend::new(90, 12)).expect("test backend");
        terminal.draw(|frame| state.render(frame, frame.area(), &EN)).expect("render");
        let screen: String = terminal.backend().buffer().content().iter().map(|c| c.symbol()).collect();

        assert!(screen.contains("web"), "the row is still listed");
        assert!(screen.contains(EN.ssh_import_already), "and says why it cannot be picked");
    }

    /// The alias is a label, not an identity. Two names for one machine are
    /// exactly the duplicate re-running the import must not create.
    #[test]
    fn presence_is_decided_by_where_it_connects_not_by_what_it_is_called() {
        let hosts = vec![host("a-different-alias", "WEB.example.com", Some("root"), Some(22))];
        let servers = vec![vault("web", "web.example.com", 22, "root")];
        let state = SshImportState::new(hosts, &servers, None);
        assert!(state.rows[0].already_present, "the hostname folds case, as DNS does");
    }

    /// A different port or account is a different destination, so it is a new
    /// entry rather than a duplicate.
    #[test]
    fn a_different_port_or_user_is_not_the_same_host() {
        let servers = vec![vault("web", "web.example.com", 22, "root")];
        let other_port = SshImportState::new(vec![host("w", "web.example.com", Some("root"), Some(2222))], &servers, None);
        assert!(!other_port.rows[0].already_present);
        let other_user = SshImportState::new(vec![host("w", "web.example.com", Some("deploy"), None)], &servers, None);
        assert!(!other_user.rows[0].already_present);
    }

    #[test]
    fn picking_nothing_is_a_no_op_rather_than_an_empty_import() {
        let mut state = SshImportState::new(vec![host("web", "web.example.com", None, None)], &[], None);
        press(&mut state, KeyCode::Char(' '));
        assert!(matches!(press(&mut state, KeyCode::Enter), SshImportOutcome::None));
    }
}
