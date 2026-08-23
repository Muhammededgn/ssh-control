//! Which servers a script runs on.
//!
//! A script belongs to one `ServerEntry`, and it stays that way. What this
//! screen adds is a run-time answer to "and where else?", which is all a
//! fleet-wide patch/restart/check needs now that `ssh::script_runner::ScriptVars`
//! expands `{{host}}` and friends per entry.
//!
//! **Nothing here is persisted.** A stored target list would be a second thing
//! that can disagree with `config.servers` — deleting a server would leave a
//! dangling `Uuid` behind that nothing would ever clean up — and it would have
//! to be edited somewhere too. The set dies with the screen.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{ListItem, ListState};
use uuid::Uuid;

use crate::config::ServerEntry;
use crate::i18n::Strings;
use crate::tui::chrome;
use crate::tui::theme;
use crate::tui::widgets::{self, list_title_with_position, render_list_scrollbar};

pub struct ScriptTargetsState {
    /// The entry the script definition lives on. Kept so `Esc` knows which
    /// script list to go back to.
    pub origin_server_id: Uuid,
    pub script_id: Uuid,
    pub script_name: String,
    /// The checked servers, by id.
    ///
    /// Ids rather than indices for the same reason `MainMenuState::selected`
    /// indexes the visible list: a row number is only meaningful against the
    /// exact slice that drew it. Nothing here filters or sorts today, so the
    /// two happen to agree — storing ids is what keeps that from mattering.
    checked: Vec<Uuid>,
    selected: usize,
    list_state: ListState,
}

pub enum ScriptTargetsOutcome {
    None,
    Cancel,
    /// Run the script on these servers, in list order.
    Run(Vec<Uuid>),
    Help,
}

impl ScriptTargetsState {
    /// Opens with the script's own server already checked — "this one and
    /// these others" is what someone reaching for this screen means.
    pub fn new(origin_server_id: Uuid, script_id: Uuid, script_name: String) -> Self {
        let mut list_state = ListState::default();
        list_state.select(Some(0));
        Self { origin_server_id, script_id, script_name, checked: vec![origin_server_id], selected: 0, list_state }
    }

    fn is_checked(&self, id: Uuid) -> bool {
        self.checked.contains(&id)
    }

    fn toggle(&mut self, id: Uuid) {
        match self.checked.iter().position(|&c| c == id) {
            Some(at) => {
                self.checked.remove(at);
            }
            None => self.checked.push(id),
        }
    }

    /// The checked servers in the order they appear on screen, so the run log
    /// reads top to bottom rather than in the order the boxes were ticked.
    fn run_order(&self, servers: &[ServerEntry]) -> Vec<Uuid> {
        servers.iter().map(|s| s.id).filter(|id| self.is_checked(*id)).collect()
    }

    pub fn handle_key(&mut self, key: KeyEvent, servers: &[ServerEntry]) -> ScriptTargetsOutcome {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                if self.selected > 0 {
                    self.selected -= 1;
                    self.list_state.select(Some(self.selected));
                }
                ScriptTargetsOutcome::None
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.selected + 1 < servers.len() {
                    self.selected += 1;
                    self.list_state.select(Some(self.selected));
                }
                ScriptTargetsOutcome::None
            }
            KeyCode::Char(' ') => {
                if let Some(entry) = servers.get(self.selected) {
                    self.toggle(entry.id);
                }
                ScriptTargetsOutcome::None
            }
            // All or none, from whichever it is not already: the common uses
            // are "everything" and "start over", and one key covers both.
            KeyCode::Char('a') => {
                self.checked = if self.checked.len() == servers.len() { Vec::new() } else { servers.iter().map(|s| s.id).collect() };
                ScriptTargetsOutcome::None
            }
            KeyCode::Enter => {
                let targets = self.run_order(servers);
                // Nothing checked is a no-op rather than an error message: the
                // empty checkbox column already says everything an error could.
                if targets.is_empty() { ScriptTargetsOutcome::None } else { ScriptTargetsOutcome::Run(targets) }
            }
            KeyCode::Char('?') => ScriptTargetsOutcome::Help,
            KeyCode::Esc => ScriptTargetsOutcome::Cancel,
            _ => ScriptTargetsOutcome::None,
        }
    }

    pub fn render(&mut self, frame: &mut Frame, area: Rect, servers: &[ServerEntry], strings: &Strings) {
        let footer = vec![Line::from(Span::styled(strings.script_targets_hint, Style::default().fg(theme::hint())))];
        let body = chrome::render(frame, area, strings.script_targets_title, footer, strings);

        let items: Vec<ListItem> = servers
            .iter()
            .map(|s| {
                let box_ = if self.is_checked(s.id) { "[x]" } else { "[ ]" };
                let mark = Style::default().fg(if self.is_checked(s.id) { theme::success() } else { theme::hint() });
                ListItem::new(Line::from(vec![
                    Span::styled(format!("{box_} "), mark),
                    Span::styled(s.name.clone(), Style::default().add_modifier(Modifier::BOLD)),
                    Span::styled(format!("  {}@{}", s.username, s.host), Style::default().fg(theme::hint())),
                ]))
            })
            .collect();

        let title = list_title_with_position(
            &format!(" {} — {} ", strings.script_targets_title.trim(), self.script_name),
            self.selected,
            servers.len(),
        );
        widgets::render_list(frame, body, &title, items, &mut self.list_state, Some(strings.script_targets_empty), None, true);
        render_list_scrollbar(frame, body, self.selected, servers.len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuthMethod;

    fn servers() -> Vec<ServerEntry> {
        ["web-1", "web-2", "db-1"]
            .into_iter()
            .map(|n| ServerEntry::new(n.into(), format!("{n}.example.com"), 22, "root".into(), AuthMethod::password("x")))
            .collect()
    }

    fn state(servers: &[ServerEntry]) -> ScriptTargetsState {
        ScriptTargetsState::new(servers[0].id, Uuid::new_v4(), "deploy".into())
    }

    fn press(s: &mut ScriptTargetsState, servers: &[ServerEntry], code: KeyCode) -> ScriptTargetsOutcome {
        s.handle_key(KeyEvent::from(code), servers)
    }

    #[test]
    fn the_scripts_own_server_starts_checked() {
        let servers = servers();
        let s = state(&servers);
        assert_eq!(s.run_order(&servers), vec![servers[0].id]);
    }

    #[test]
    fn space_toggles_the_row_under_the_cursor() {
        let servers = servers();
        let mut s = state(&servers);

        press(&mut s, &servers, KeyCode::Down);
        press(&mut s, &servers, KeyCode::Char(' '));
        assert_eq!(s.run_order(&servers), vec![servers[0].id, servers[1].id]);

        press(&mut s, &servers, KeyCode::Char(' '));
        assert_eq!(s.run_order(&servers), vec![servers[0].id]);
    }

    #[test]
    fn a_flips_between_all_and_none() {
        let servers = servers();
        let mut s = state(&servers);

        press(&mut s, &servers, KeyCode::Char('a'));
        assert_eq!(s.run_order(&servers).len(), 3);

        press(&mut s, &servers, KeyCode::Char('a'));
        assert!(s.run_order(&servers).is_empty());
    }

    /// The run has to read top to bottom, not in the order the boxes happened
    /// to be ticked — a log whose sections are in neither order is unreadable.
    #[test]
    fn the_run_order_follows_the_list_not_the_clicks() {
        let servers = servers();
        let mut s = state(&servers);
        press(&mut s, &servers, KeyCode::Char('a'));
        press(&mut s, &servers, KeyCode::Char('a'));

        // Check them backwards: db-1, then web-1.
        s.selected = 2;
        press(&mut s, &servers, KeyCode::Char(' '));
        s.selected = 0;
        press(&mut s, &servers, KeyCode::Char(' '));

        match press(&mut s, &servers, KeyCode::Enter) {
            ScriptTargetsOutcome::Run(ids) => assert_eq!(ids, vec![servers[0].id, servers[2].id]),
            _ => panic!("expected a run"),
        }
    }

    /// A smoke test that the screen draws: the checkbox column is the whole
    /// interface, so a run of it that shows no boxes shows nothing.
    #[test]
    fn the_checkbox_column_reaches_the_screen() {
        use crate::i18n::EN;
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let servers = servers();
        let mut s = state(&servers);
        let mut terminal = Terminal::new(TestBackend::new(100, 20)).expect("test backend");
        terminal.draw(|frame| s.render(frame, frame.area(), &servers, &EN)).expect("render");
        let screen: String = terminal.backend().buffer().content().iter().map(|c| c.symbol()).collect();

        assert!(screen.contains("[x] web-1"), "the script's own server starts checked");
        assert!(screen.contains("[ ] web-2"));
        assert!(screen.contains("Space:"), "the hint must be on screen");
    }

    #[test]
    fn enter_with_nothing_checked_does_nothing() {
        let servers = servers();
        let mut s = state(&servers);
        press(&mut s, &servers, KeyCode::Char('a'));
        press(&mut s, &servers, KeyCode::Char('a'));

        assert!(matches!(press(&mut s, &servers, KeyCode::Enter), ScriptTargetsOutcome::None));
    }
}
