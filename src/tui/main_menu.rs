use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};
use uuid::Uuid;

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

pub struct MainMenuState {
    selected: usize,
    list_state: ListState,
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
        Self { selected: 0, list_state }
    }

    pub fn handle_key(&mut self, key: KeyEvent, servers: &[ServerEntry]) -> MainMenuAction {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                if self.selected > 0 {
                    self.selected -= 1;
                    self.list_state.select(Some(self.selected));
                }
                MainMenuAction::None
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if !servers.is_empty() && self.selected + 1 < servers.len() {
                    self.selected += 1;
                    self.list_state.select(Some(self.selected));
                }
                MainMenuAction::None
            }
            KeyCode::Enter => servers
                .get(self.selected)
                .map(|s| MainMenuAction::Connect(s.id))
                .unwrap_or(MainMenuAction::None),
            KeyCode::Char('a') => MainMenuAction::Add,
            KeyCode::Char('e') => servers
                .get(self.selected)
                .map(|s| MainMenuAction::Edit(s.id))
                .unwrap_or(MainMenuAction::None),
            KeyCode::Char('d') => servers
                .get(self.selected)
                .map(|s| MainMenuAction::Delete(s.id))
                .unwrap_or(MainMenuAction::None),
            KeyCode::Char('s') => servers
                .get(self.selected)
                .map(|s| MainMenuAction::Scripts(s.id))
                .unwrap_or(MainMenuAction::None),
            KeyCode::Char('l') => MainMenuAction::Lock,
            KeyCode::F(1) => MainMenuAction::Settings,
            KeyCode::Char('q') | KeyCode::Esc => MainMenuAction::Quit,
            _ => MainMenuAction::None,
        }
    }

    /// Clamps the selection after the server list changes (add/delete).
    pub fn clamp_selection(&mut self, servers: &[ServerEntry]) {
        if servers.is_empty() {
            self.selected = 0;
        } else if self.selected >= servers.len() {
            self.selected = servers.len() - 1;
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
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(3), Constraint::Length(4)])
            .split(area);

        let items: Vec<ListItem> = if servers.is_empty() {
            vec![ListItem::new(strings.main_menu_empty)]
        } else {
            servers
                .iter()
                .map(|s| {
                    let auth_label = match &s.auth {
                        crate::config::AuthMethod::Password { .. } => strings.auth_label_password,
                        crate::config::AuthMethod::SshKey { .. } => strings.auth_label_key,
                    };
                    let mut lines = vec![Line::from(format!(
                        "{}  ({}@{}:{}, {})",
                        s.name, s.username, s.host, s.port, auth_label
                    ))];
                    if let Some(info) = &s.system_info {
                        lines.push(Line::from(Span::styled(
                            format!("    {}", format_system_info(info, strings)),
                            Style::default().fg(Color::DarkGray),
                        )));
                    }
                    ListItem::new(lines)
                })
                .collect()
        };

        let title = list_title_with_position(strings.main_menu_title, self.selected, servers.len());
        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title(title))
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
            .highlight_symbol("> ");

        frame.render_stateful_widget(list, chunks[0], &mut self.list_state);
        render_list_scrollbar(frame, chunks[0], self.selected, servers.len());

        let mut help_text = Vec::new();

        if let Some(s) = status {
            help_text.push(Line::from(Span::styled(
                s.to_string(),
                Style::default().fg(Color::Yellow),
            )));
        }
        help_text.push(Line::from(strings.main_menu_hint));
        
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
}
