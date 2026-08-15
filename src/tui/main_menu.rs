use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};
use uuid::Uuid;

use crate::config::device::now_unix;
use crate::config::{ServerEntry, SystemInfo};
use crate::i18n::Strings;
use crate::tui::widgets::{list_title_with_position, render_list_scrollbar};

fn gib(bytes: u64) -> f64 {
    bytes as f64 / 1_073_741_824.0
}

/// Renders a compact "CPU: ... | RAM: used/total GiB | Disk: used/total GiB |
/// GPU: ..." line from whatever fields were actually fetched. Missing fields
/// are simply skipped rather than shown as errors — some remote shells lack
/// `lspci`/`free`/etc.
fn format_system_info(info: &SystemInfo, strings: &Strings) -> String {
    let mut parts = Vec::new();

    if info.cpu_model.is_some() || info.cpu_cores.is_some() {
        let mut cpu = String::new();
        if let Some(model) = &info.cpu_model {
            cpu.push_str(model);
        }
        if let Some(cores) = info.cpu_cores {
            if !cpu.is_empty() {
                cpu.push_str(" (");
                cpu.push_str(&cores.to_string());
                cpu.push_str(strings.sysinfo_cores_suffix);
                cpu.push(')');
            } else {
                cpu.push_str(&cores.to_string());
                cpu.push_str(strings.sysinfo_cores_suffix);
            }
        }
        parts.push(format!("{}: {cpu}", strings.sysinfo_cpu_label));
    }

    if let (Some(used), Some(total)) = (info.mem_used_bytes, info.mem_total_bytes) {
        parts.push(format!(
            "{}: {:.1}/{:.1} GiB",
            strings.sysinfo_ram_label,
            gib(used),
            gib(total)
        ));
    }

    if let (Some(used), Some(total)) = (info.disk_used_bytes, info.disk_total_bytes) {
        parts.push(format!(
            "{}: {:.1}/{:.1} GiB",
            strings.sysinfo_disk_label,
            gib(used),
            gib(total)
        ));
    }

    if let Some(gpu) = &info.gpu_model {
        parts.push(format!("{}: {gpu}", strings.sysinfo_gpu_label));
    }

    parts.join("  |  ")
}

/// "3m ago", "5h ago", "2d ago" — coarse on purpose. The question this answers
/// is "which of these do I actually use", and to the minute is more precision
/// than that needs.
///
/// A timestamp in the future (a clock corrected backwards, a vault carried
/// across timezones badly) reads as "just now" rather than a negative age.
fn format_relative_time(then_unix: u64, now_unix: u64, strings: &Strings) -> String {
    let seconds = now_unix.saturating_sub(then_unix);
    let minutes = seconds / 60;
    let hours = minutes / 60;
    let days = hours / 24;

    if days > 0 {
        format!("{days}{}", strings.time_days_suffix)
    } else if hours > 0 {
        format!("{hours}{}", strings.time_hours_suffix)
    } else if minutes > 0 {
        format!("{minutes}{}", strings.time_minutes_suffix)
    } else {
        strings.time_just_now.to_string()
    }
}

/// `selected` indexes the *visible* list, not `servers`. Everything that has to
/// name a server goes through `visible_indices` — resolving `servers[selected]`
/// directly is the bug this screen is shaped to prevent, because with a filter
/// on, the two disagree.
///
/// `typing` is the `/` mode: while it is set every character key is filter text,
/// so the single-letter shortcuts (a/e/d/s/l/q) are deliberately unreachable.
/// `Enter` leaves it — connecting to whatever is selected — and `Esc` leaves it
/// *and* clears the filter, so there is always a way back to the full list.
pub struct MainMenuState {
    selected: usize,
    list_state: ListState,
    filter: String,
    typing: bool,
}

/// Case-insensitive substring over the three fields the user would type: the
/// name they gave it, and the `user@host` they would otherwise have to remember.
/// Port and auth kind are deliberately not searched — nobody looks for "22".
fn matches(entry: &ServerEntry, needle: &str) -> bool {
    let needle = needle.to_lowercase();
    entry.name.to_lowercase().contains(&needle)
        || entry.host.to_lowercase().contains(&needle)
        || entry.username.to_lowercase().contains(&needle)
}

pub enum MainMenuAction {
    None,
    Connect(Uuid),
    Add,
    Edit(Uuid),
    Delete(Uuid),
    Scripts(Uuid),
    Lock,
    Settings,
    /// `?` only reaches here outside `/` mode — while the filter is taking
    /// keystrokes it is a character like any other.
    Help,
    Quit,
}

impl Default for MainMenuState {
    fn default() -> Self {
        Self::new()
    }
}

impl MainMenuState {
    pub fn new() -> Self {
        let mut list_state = ListState::default();
        list_state.select(Some(0));
        Self { selected: 0, list_state, filter: String::new(), typing: false }
    }

    /// The entries currently on screen, as indices into `servers`. The one
    /// mapping every key handler resolves through.
    fn visible_indices(&self, servers: &[ServerEntry]) -> Vec<usize> {
        if self.filter.is_empty() {
            return (0..servers.len()).collect();
        }
        servers
            .iter()
            .enumerate()
            .filter(|(_, s)| matches(s, &self.filter))
            .map(|(i, _)| i)
            .collect()
    }

    fn selected_entry<'a>(&self, servers: &'a [ServerEntry]) -> Option<&'a ServerEntry> {
        self.visible_indices(servers).get(self.selected).and_then(|&i| servers.get(i))
    }

    fn move_selection(&mut self, delta: isize, visible_len: usize) {
        if visible_len == 0 {
            self.selected = 0;
        } else if delta < 0 {
            self.selected = self.selected.saturating_sub(1);
        } else if self.selected + 1 < visible_len {
            self.selected += 1;
        }
        self.list_state.select(Some(self.selected));
    }

    pub fn handle_key(&mut self, key: KeyEvent, servers: &[ServerEntry]) -> MainMenuAction {
        if self.typing {
            return self.handle_filter_key(key, servers);
        }
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.move_selection(-1, self.visible_indices(servers).len());
                MainMenuAction::None
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.move_selection(1, self.visible_indices(servers).len());
                MainMenuAction::None
            }
            KeyCode::Enter => self
                .selected_entry(servers)
                .map(|s| MainMenuAction::Connect(s.id))
                .unwrap_or(MainMenuAction::None),
            KeyCode::Char('/') => {
                self.typing = true;
                MainMenuAction::None
            }
            KeyCode::Char('?') => MainMenuAction::Help,
            KeyCode::Char('a') => MainMenuAction::Add,
            KeyCode::Char('e') => self
                .selected_entry(servers)
                .map(|s| MainMenuAction::Edit(s.id))
                .unwrap_or(MainMenuAction::None),
            KeyCode::Char('d') => self
                .selected_entry(servers)
                .map(|s| MainMenuAction::Delete(s.id))
                .unwrap_or(MainMenuAction::None),
            KeyCode::Char('s') => self
                .selected_entry(servers)
                .map(|s| MainMenuAction::Scripts(s.id))
                .unwrap_or(MainMenuAction::None),
            KeyCode::Char('l') => MainMenuAction::Lock,
            KeyCode::F(1) => MainMenuAction::Settings,
            // With a filter applied, Esc is the way back to the whole list; it
            // only quits once there is nothing left to clear.
            KeyCode::Esc if !self.filter.is_empty() => {
                self.clear_filter(servers);
                MainMenuAction::None
            }
            KeyCode::Char('q') | KeyCode::Esc => MainMenuAction::Quit,
            _ => MainMenuAction::None,
        }
    }

    /// The `/` mode. Editing the filter re-anchors the selection on the entry
    /// that was selected before the keystroke where it survived the narrowing,
    /// and on the first match otherwise — so typing does not silently walk the
    /// selection down the list.
    fn handle_filter_key(&mut self, key: KeyEvent, servers: &[ServerEntry]) -> MainMenuAction {
        match key.code {
            KeyCode::Char(c) => {
                let anchor = self.selected_entry(servers).map(|s| s.id);
                self.filter.push(c);
                self.reanchor(servers, anchor);
                MainMenuAction::None
            }
            KeyCode::Backspace => {
                let anchor = self.selected_entry(servers).map(|s| s.id);
                self.filter.pop();
                self.reanchor(servers, anchor);
                MainMenuAction::None
            }
            KeyCode::Up => {
                self.move_selection(-1, self.visible_indices(servers).len());
                MainMenuAction::None
            }
            KeyCode::Down => {
                self.move_selection(1, self.visible_indices(servers).len());
                MainMenuAction::None
            }
            // Enter connects to what is visibly selected and leaves `/` mode
            // with the filter still applied, so the shortcuts come back.
            KeyCode::Enter => {
                self.typing = false;
                self.selected_entry(servers)
                    .map(|s| MainMenuAction::Connect(s.id))
                    .unwrap_or(MainMenuAction::None)
            }
            KeyCode::Esc => {
                self.typing = false;
                self.clear_filter(servers);
                MainMenuAction::None
            }
            _ => MainMenuAction::None,
        }
    }

    fn reanchor(&mut self, servers: &[ServerEntry], anchor: Option<Uuid>) {
        let visible = self.visible_indices(servers);
        self.selected = anchor
            .and_then(|id| visible.iter().position(|&i| servers[i].id == id))
            .unwrap_or(0);
        self.list_state.select(Some(self.selected));
    }

    /// Dropping the filter keeps the user where they were: the entry that was
    /// selected in the narrowed list stays selected in the full one.
    fn clear_filter(&mut self, servers: &[ServerEntry]) {
        let anchor = self.selected_entry(servers).map(|s| s.id);
        self.filter.clear();
        self.reanchor(servers, anchor);
    }

    /// Clamps the selection after the server list changes (add/delete).
    pub fn clamp_selection(&mut self, servers: &[ServerEntry]) {
        let visible = self.visible_indices(servers).len();
        if visible == 0 {
            self.selected = 0;
        } else if self.selected >= visible {
            self.selected = visible - 1;
        }
        self.list_state.select(Some(self.selected));
    }

    pub fn render(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        servers: &[ServerEntry],
        status: Option<&str>,
        strings: &Strings,
    ) {
        let visible = self.visible_indices(servers);
        let filter_shown = self.typing || !self.filter.is_empty();

        // The footer grows with what it has to say rather than reserving a
        // blank row: on a short terminal every row belongs to the list.
        let footer_lines = 1 + u16::from(status.is_some()) + u16::from(filter_shown);
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(3), Constraint::Length(footer_lines + 2)])
            .split(area);

        // Once per frame, not once per row: forty rows must not disagree about
        // what "now" is.
        let now = now_unix();

        let items: Vec<ListItem> = if servers.is_empty() {
            vec![ListItem::new(strings.main_menu_empty)]
        } else if visible.is_empty() {
            vec![ListItem::new(strings.main_menu_no_match)]
        } else {
            visible
                .iter()
                .map(|&i| &servers[i])
                .map(|s| {
                    let auth_label = match &s.auth {
                        crate::config::AuthMethod::Password { .. } => strings.auth_label_password,
                        crate::config::AuthMethod::SshKey { .. } => strings.auth_label_key,
                    };
                    let mut lines = vec![Line::from(format!(
                        "{}  ({}@{}:{}, {})",
                        s.name, s.username, s.host, s.port, auth_label
                    ))];
                    // One dim detail line carrying whatever is known. Built
                    // from parts rather than keyed off `system_info` alone: a
                    // host whose sysinfo probe never succeeds still has a
                    // last-connected time worth showing.
                    let mut details = Vec::new();
                    if let Some(ts) = s.last_connected_unix {
                        details.push(format!(
                            "{}: {}",
                            strings.last_connected_label,
                            format_relative_time(ts, now, strings)
                        ));
                    }
                    if let Some(info) = &s.system_info {
                        details.push(format_system_info(info, strings));
                    }
                    if !details.is_empty() {
                        lines.push(Line::from(Span::styled(
                            format!("    {}", details.join("  |  ")),
                            Style::default().fg(Color::DarkGray),
                        )));
                    }
                    ListItem::new(lines)
                })
                .collect()
        };

        let title = list_title_with_position(strings.main_menu_title, self.selected, visible.len());
        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title(title))
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
            .highlight_symbol("> ");

        frame.render_stateful_widget(list, chunks[0], &mut self.list_state);
        render_list_scrollbar(frame, chunks[0], self.selected, visible.len());

        let mut help_text = Vec::new();

        if filter_shown {
            // The block cursor is what says "this is taking your keystrokes";
            // a filter left applied after Enter shows the text without one.
            let caret = if self.typing { "█" } else { "" };
            help_text.push(Line::from(Span::styled(
                format!("{}{}{caret}", strings.main_menu_filter_label, self.filter),
                Style::default().fg(Color::Cyan),
            )));
        }

        if let Some(s) = status {
            help_text.push(Line::from(Span::styled(
                s.to_string(),
                Style::default().fg(Color::Yellow),
            )));
        }
        help_text.push(Line::from(if self.typing {
            strings.main_menu_filter_hint
        } else {
            strings.main_menu_hint
        }));

        let help = Paragraph::new(help_text).block(Block::default().borders(Borders::ALL));
        frame.render_widget(help, chunks[1]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuthMethod;
    use crate::i18n::EN;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn servers(n: usize) -> Vec<ServerEntry> {
        (0..n)
            .map(|i| ServerEntry {
                id: Uuid::new_v4(),
                name: format!("host-{i}"),
                host: format!("10.0.0.{i}"),
                port: 22,
                username: "root".to_string(),
                auth: AuthMethod::password("hunter2".to_string()),
                host_key_fingerprint: None,
                system_info: None,
                last_connected_unix: None,
                scripts: Vec::new(),
            })
            .collect()
    }

    fn render(state: &mut MainMenuState, servers: &[ServerEntry], height: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(80, height)).expect("test backend");
        terminal
            .draw(|frame| state.render(frame, frame.area(), servers, None, &EN))
            .expect("render");
        terminal.backend().buffer().content().iter().map(|c| c.symbol()).collect()
    }

    /// The issue's acceptance criterion: 40 servers on a 20-row terminal must
    /// make it visually clear that the list scrolls and where you are in it.
    #[test]
    fn a_long_list_shows_where_you_are_and_that_there_is_more() {
        let entries = servers(40);
        let mut state = MainMenuState::new();

        let top = render(&mut state, &entries, 20);
        assert!(top.contains("(1/40)"), "the title should say which entry is selected");

        for _ in 0..12 {
            state.handle_key(KeyEvent::from(KeyCode::Down), &entries);
        }
        let moved = render(&mut state, &entries, 20);
        assert!(moved.contains("(13/40)"), "the counter should follow the selection");
        // The scrollbar track ratatui draws for a list this long.
        assert!(moved.contains('█') || moved.contains('║'), "a scrollbar should be drawn");
    }

    /// A list that fits needs no scrollbar, but the counter still orients you.
    #[test]
    fn a_single_entry_gets_a_counter_but_no_scrollbar() {
        let entries = servers(1);
        let mut state = MainMenuState::new();

        let rendered = render(&mut state, &entries, 20);
        assert!(rendered.contains("(1/1)"));
        assert!(!rendered.contains('█'), "one item cannot scroll, so the track is just noise");
    }

    #[test]
    fn relative_times_are_coarse_and_read_left_to_right() {
        let m = 60;
        let h = 60 * m;
        let d = 24 * h;

        assert_eq!(format_relative_time(1_000, 1_000 + 30, &EN), "just now");
        assert_eq!(format_relative_time(1_000, 1_000 + 3 * m, &EN), "3m ago");
        assert_eq!(format_relative_time(1_000, 1_000 + 5 * h, &EN), "5h ago");
        assert_eq!(format_relative_time(1_000, 1_000 + 2 * d, &EN), "2d ago");
    }

    /// A clock corrected backwards must not produce a negative age or panic on
    /// the subtraction.
    #[test]
    fn a_future_timestamp_reads_as_just_now() {
        assert_eq!(format_relative_time(9_000, 1_000, &EN), "just now");
    }

    /// The issue's point: `fetched_at_unix` only moves when the sysinfo probe
    /// succeeds, so a host with a restricted shell would otherwise look like it
    /// had never been connected to.
    #[test]
    fn a_host_with_no_system_info_still_shows_when_it_was_last_reached() {
        let mut entries = servers(1);
        entries[0].last_connected_unix = Some(now_unix().saturating_sub(2 * 60 * 60));
        assert!(entries[0].system_info.is_none());

        let rendered = render(&mut MainMenuState::new(), &entries, 20);
        assert!(rendered.contains("2h ago"), "the detail line must appear without system info");
    }

    fn press(state: &mut MainMenuState, servers: &[ServerEntry], code: KeyCode) -> MainMenuAction {
        state.handle_key(KeyEvent::from(code), servers)
    }

    fn type_filter(state: &mut MainMenuState, servers: &[ServerEntry], text: &str) {
        press(state, servers, KeyCode::Char('/'));
        for c in text.chars() {
            press(state, servers, KeyCode::Char(c));
        }
    }

    /// The issue's acceptance criterion, and the whole reason the visible-index
    /// mapping exists: with a filter on, Enter must connect to the row the user
    /// can see, not to `servers[selected]`.
    #[test]
    fn enter_connects_to_the_visibly_selected_server() {
        let mut entries = servers(4);
        entries[2].name = "prod-db".to_string();
        let mut state = MainMenuState::new();

        type_filter(&mut state, &entries, "prod");
        match press(&mut state, &entries, KeyCode::Enter) {
            MainMenuAction::Connect(id) => assert_eq!(id, entries[2].id),
            _ => panic!("Enter should connect"),
        }
    }

    /// The other half of the same mapping: edit/delete/scripts resolve through
    /// it too, so a filtered list cannot delete the wrong server.
    #[test]
    fn the_single_letter_shortcuts_also_follow_the_filter() {
        let mut entries = servers(4);
        entries[3].host = "10.9.9.9".to_string();
        let mut state = MainMenuState::new();

        type_filter(&mut state, &entries, "10.9");
        // Enter leaves `/` mode with the filter still applied.
        press(&mut state, &entries, KeyCode::Enter);
        match press(&mut state, &entries, KeyCode::Char('d')) {
            MainMenuAction::Delete(id) => assert_eq!(id, entries[3].id),
            _ => panic!("d should delete the visible selection"),
        }
    }

    #[test]
    fn the_filter_matches_name_host_and_username() {
        let mut entries = servers(3);
        entries[0].name = "alpha".to_string();
        entries[1].host = "alpha.example.com".to_string();
        entries[2].username = "alpha-admin".to_string();
        let state = MainMenuState { selected: 0, list_state: ListState::default(), filter: "ALPHA".to_string(), typing: false };

        assert_eq!(state.visible_indices(&entries), vec![0, 1, 2]);
    }

    /// While `/` is held open every character is filter text — otherwise typing
    /// a server called "dashboard" would delete one.
    #[test]
    fn typing_a_shortcut_letter_while_filtering_does_not_fire_it() {
        let entries = servers(3);
        let mut state = MainMenuState::new();

        press(&mut state, &entries, KeyCode::Char('/'));
        assert!(matches!(press(&mut state, &entries, KeyCode::Char('d')), MainMenuAction::None));
        assert!(matches!(press(&mut state, &entries, KeyCode::Char('q')), MainMenuAction::None));
    }

    /// Esc clears before it quits, so a filter can never trap the user with a
    /// list that looks half-empty.
    #[test]
    fn esc_clears_the_filter_first_and_quits_second() {
        let entries = servers(3);
        let mut state = MainMenuState::new();

        type_filter(&mut state, &entries, "host-1");
        press(&mut state, &entries, KeyCode::Enter);
        assert!(matches!(press(&mut state, &entries, KeyCode::Esc), MainMenuAction::None));
        assert_eq!(state.visible_indices(&entries).len(), 3, "the whole list should be back");
        assert!(matches!(press(&mut state, &entries, KeyCode::Esc), MainMenuAction::Quit));
    }

    /// Clearing keeps you on the same server rather than snapping to the top.
    #[test]
    fn clearing_the_filter_keeps_the_selected_server_selected() {
        let entries = servers(5);
        let mut state = MainMenuState::new();

        type_filter(&mut state, &entries, "host-3");
        press(&mut state, &entries, KeyCode::Esc);
        assert_eq!(state.selected_entry(&entries).map(|s| s.id), Some(entries[3].id));
    }

    /// A filter that matches nothing must not leave the previous selection
    /// live: pressing Enter into an empty list has to be a no-op.
    #[test]
    fn a_filter_matching_nothing_selects_nothing() {
        let entries = servers(3);
        let mut state = MainMenuState::new();

        type_filter(&mut state, &entries, "nonexistent");
        assert!(state.selected_entry(&entries).is_none());
        assert!(matches!(press(&mut state, &entries, KeyCode::Enter), MainMenuAction::None));

        let rendered = render(&mut state, &entries, 20);
        assert!(rendered.contains("no server matches"));
    }

    /// The counter has to count the filtered list; "(1/40)" over three visible
    /// rows would be worse than no counter at all.
    #[test]
    fn the_counter_and_footer_reflect_the_filter() {
        let entries = servers(40);
        let mut state = MainMenuState::new();

        type_filter(&mut state, &entries, "host-1");
        let rendered = render(&mut state, &entries, 24);
        // host-1 and host-10..host-19.
        assert!(rendered.contains("(1/11)"), "the counter should count matches");
        assert!(rendered.contains("Filter: host-1"), "the filter text should be visible");
    }

    #[test]
    fn a_host_never_connected_to_gets_no_detail_line() {
        let entries = servers(1);
        let rendered = render(&mut MainMenuState::new(), &entries, 20);
        assert!(!rendered.contains(EN.last_connected_label));
    }
}
