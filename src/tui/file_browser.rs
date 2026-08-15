//! The two-pane file browser: local filesystem on the left, the server over
//! SFTP on the right.
//!
//! Everything local is done here and synchronously — `std::fs` is fast enough
//! that a directory listing does not need a flow. Everything remote leaves as
//! an outcome for `app.rs` to await, because that is the only place allowed to
//! hold a borrow across `.await` (see the `NextStep` pattern).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};
use uuid::Uuid;

use super::widgets::{format_size, render_if_too_small, render_list_scrollbar};
use crate::i18n::Strings;

/// Two bordered panes need more room than a single form: at 60 columns each
/// pane has ~28 usable, which is already tight for a name plus a size.
const MIN_BROWSER_WIDTH: u16 = 60;
const MIN_BROWSER_HEIGHT: u16 = 12;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Side {
    Local,
    Remote,
}

impl Side {
    fn other(self) -> Side {
        match self {
            Side::Local => Side::Remote,
            Side::Remote => Side::Local,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrowserEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
}

/// One side of the browser.
///
/// `marked` holds *names*, not indices. A refresh can add or remove entries,
/// and an index-keyed mark would then quietly point at a different file — which
/// on a transfer means moving something the user never selected.
pub struct PaneState {
    pub cwd: String,
    entries: Vec<BrowserEntry>,
    selected: usize,
    marked: BTreeSet<String>,
    list_state: ListState,
    /// Shown in place of the listing. Per pane on purpose: a denied directory
    /// on one side must leave the other side working.
    pub error: Option<String>,
}

impl PaneState {
    fn new(cwd: String) -> Self {
        Self {
            cwd,
            entries: Vec::new(),
            selected: 0,
            marked: BTreeSet::new(),
            list_state: ListState::default(),
            error: None,
        }
    }

    /// Replaces the listing, keeping the selection sensible and dropping marks
    /// for entries that are no longer there.
    pub fn set_entries(&mut self, entries: Vec<BrowserEntry>) {
        self.entries = entries;
        self.entries.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase())));
        self.marked.retain(|name| self.entries.iter().any(|e| &e.name == name));
        self.clamp();
        self.error = None;
    }

    fn clamp(&mut self) {
        if self.entries.is_empty() {
            self.selected = 0;
        } else if self.selected >= self.entries.len() {
            self.selected = self.entries.len() - 1;
        }
        self.list_state.select(Some(self.selected));
    }

    fn move_by(&mut self, delta: isize) {
        if self.entries.is_empty() {
            return;
        }
        if delta < 0 {
            self.selected = self.selected.saturating_sub(1);
        } else if self.selected + 1 < self.entries.len() {
            self.selected += 1;
        }
        self.list_state.select(Some(self.selected));
    }

    fn selected_entry(&self) -> Option<&BrowserEntry> {
        self.entries.get(self.selected)
    }

    fn toggle_mark(&mut self) {
        if let Some(entry) = self.entries.get(self.selected)
            && !self.marked.remove(&entry.name)
        {
            self.marked.insert(entry.name.clone());
        }
    }

    /// What a transfer would move: the marked names, or — when nothing is
    /// marked — whatever the cursor is on. "Nothing marked" is the common case
    /// and it should not need two keystrokes.
    pub fn transfer_selection(&self) -> Vec<BrowserEntry> {
        if !self.marked.is_empty() {
            return self.entries.iter().filter(|e| self.marked.contains(&e.name)).cloned().collect();
        }
        self.selected_entry().cloned().into_iter().collect()
    }

    /// Marks do not survive a change of directory: they name entries of the
    /// directory they were made in.
    fn enter(&mut self, cwd: String) {
        self.cwd = cwd;
        self.marked.clear();
        self.selected = 0;
        self.list_state.select(Some(0));
        self.entries.clear();
    }
}

/// What the transfer flow is doing right now, drawn over the panes.
///
/// Rendered from inside this screen's `render` rather than as a second draw
/// call — the frame is cleared each time, so anything drawn separately would
/// land on an empty screen or be wiped by the next redraw.
pub struct TransferProgress {
    pub title: String,
    pub name: String,
    pub file_index: usize,
    pub file_count: usize,
    pub done_bytes: u64,
    pub total_bytes: u64,
    /// The walk runs before any byte moves and has no denominator yet.
    pub scanning: bool,
}

impl TransferProgress {
    /// Percent complete, clamped, and defined when there is nothing to do —
    /// an empty transfer is finished, not a division by zero.
    pub fn percent(&self) -> u16 {
        if self.total_bytes == 0 {
            return 100;
        }
        ((self.done_bytes.min(self.total_bytes) as f64 / self.total_bytes as f64) * 100.0) as u16
    }
}

pub struct FileBrowserState {
    pub server_id: Uuid,
    pub server_name: String,
    pub local: PaneState,
    pub remote: PaneState,
    pub focus: Side,
    show_hidden: bool,
    pub status: Option<String>,
    pub progress: Option<TransferProgress>,
}

pub enum FileBrowserOutcome {
    None,
    Help,
    Back,
    /// An absolute remote path to list.
    OpenRemote(String),
    RefreshRemote,
    Transfer,
}

impl FileBrowserState {
    pub fn new(server_id: Uuid, server_name: String, local_cwd: PathBuf, remote_cwd: String) -> Self {
        let mut state = Self {
            server_id,
            server_name,
            local: PaneState::new(local_cwd.to_string_lossy().into_owned()),
            remote: PaneState::new(remote_cwd),
            focus: Side::Local,
            show_hidden: false,
            status: None,
            progress: None,
        };
        state.reload_local();
        state
    }

    pub fn pane(&self, side: Side) -> &PaneState {
        match side {
            Side::Local => &self.local,
            Side::Remote => &self.remote,
        }
    }

    fn pane_mut(&mut self, side: Side) -> &mut PaneState {
        match side {
            Side::Local => &mut self.local,
            Side::Remote => &mut self.remote,
        }
    }

    /// The focused pane is the source and the other pane's directory is the
    /// destination. Deriving it from focus means there is no direction to set
    /// and no mode to get wrong.
    pub fn direction(&self) -> (Side, String) {
        (self.focus, self.pane(self.focus.other()).cwd.clone())
    }

    /// Re-reads the local directory. Synchronous by design — `std::fs` needs no
    /// flow, and a local listing that fails should show on the pane rather than
    /// tear the screen down.
    pub fn reload_local(&mut self) {
        let path = PathBuf::from(&self.local.cwd);
        match read_local_dir(&path, self.show_hidden) {
            Ok(entries) => self.local.set_entries(entries),
            Err(e) => {
                self.local.entries.clear();
                self.local.error = Some(e.to_string());
            }
        }
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> FileBrowserOutcome {
        match key.code {
            KeyCode::Tab | KeyCode::BackTab => {
                self.focus = self.focus.other();
                FileBrowserOutcome::None
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.pane_mut(self.focus).move_by(-1);
                FileBrowserOutcome::None
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.pane_mut(self.focus).move_by(1);
                FileBrowserOutcome::None
            }
            KeyCode::Char(' ') => {
                self.pane_mut(self.focus).toggle_mark();
                FileBrowserOutcome::None
            }
            KeyCode::Enter => self.open_selected(),
            KeyCode::Backspace => self.go_up(),
            // Both panes hide dotfiles together, so the toggle reloads the
            // local side here and asks the flow for the remote one.
            KeyCode::Char('.') => {
                self.show_hidden = !self.show_hidden;
                self.reload_local();
                FileBrowserOutcome::RefreshRemote
            }
            KeyCode::Char('r') => {
                self.reload_local();
                FileBrowserOutcome::RefreshRemote
            }
            KeyCode::Char('t') | KeyCode::F(5) => FileBrowserOutcome::Transfer,
            KeyCode::Char('?') => FileBrowserOutcome::Help,
            KeyCode::Esc | KeyCode::Char('q') => FileBrowserOutcome::Back,
            _ => FileBrowserOutcome::None,
        }
    }

    /// `Enter` only ever means "open a directory", on both sides — which is why
    /// transfer has its own key rather than overloading this one.
    fn open_selected(&mut self) -> FileBrowserOutcome {
        let Some(entry) = self.pane(self.focus).selected_entry() else {
            return FileBrowserOutcome::None;
        };
        if !entry.is_dir {
            return FileBrowserOutcome::None;
        }
        let name = entry.name.clone();
        match self.focus {
            Side::Local => {
                let next = Path::new(&self.local.cwd).join(&name);
                self.local.enter(next.to_string_lossy().into_owned());
                self.reload_local();
                FileBrowserOutcome::None
            }
            Side::Remote => FileBrowserOutcome::OpenRemote(remote_join(&self.remote.cwd, &name)),
        }
    }

    fn go_up(&mut self) -> FileBrowserOutcome {
        match self.focus {
            Side::Local => {
                let current = PathBuf::from(&self.local.cwd);
                let Some(parent) = current.parent() else {
                    return FileBrowserOutcome::None;
                };
                self.local.enter(parent.to_string_lossy().into_owned());
                self.reload_local();
                FileBrowserOutcome::None
            }
            Side::Remote => {
                let parent = remote_parent(&self.remote.cwd);
                if parent == self.remote.cwd {
                    return FileBrowserOutcome::None;
                }
                FileBrowserOutcome::OpenRemote(parent)
            }
        }
    }

    /// Called by the flow once the server has answered.
    pub fn set_remote(&mut self, cwd: String, entries: Vec<BrowserEntry>) {
        if cwd != self.remote.cwd {
            self.remote.enter(cwd);
        }
        self.remote.set_entries(entries);
    }

    pub fn set_remote_error(&mut self, message: String) {
        self.remote.error = Some(message);
    }

    pub fn show_hidden(&self) -> bool {
        self.show_hidden
    }

    pub fn render(&mut self, frame: &mut Frame, area: Rect, strings: &Strings) {
        if render_if_too_small(frame, area, MIN_BROWSER_WIDTH, MIN_BROWSER_HEIGHT, strings.terminal_too_small) {
            return;
        }

        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(3), Constraint::Length(if self.status.is_some() { 4 } else { 3 })])
            .split(area);
        let panes = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(rows[0]);

        let focus = self.focus;
        render_pane(frame, panes[0], &mut self.local, strings.file_browser_local_label, focus == Side::Local, strings);
        render_pane(frame, panes[1], &mut self.remote, strings.file_browser_remote_label, focus == Side::Remote, strings);

        let mut footer = Vec::new();
        if let Some(status) = &self.status {
            footer.push(Line::from(Span::styled(status.clone(), Style::default().fg(Color::Yellow))));
        }
        footer.push(Line::from(strings.file_browser_hint));
        frame.render_widget(Paragraph::new(footer).block(Block::default().borders(Borders::ALL)), rows[1]);

        if let Some(progress) = &self.progress {
            render_progress(frame, area, progress, strings);
        }
    }
}

fn render_progress(frame: &mut Frame, area: Rect, progress: &TransferProgress, strings: &Strings) {
    let mut lines = vec![Line::from(Span::styled(
        ellipsize_middle(&progress.name, 54),
        Style::default().add_modifier(Modifier::BOLD),
    ))];

    if progress.scanning {
        lines.push(Line::from(format!(
            "{}{} · {}",
            strings.transfer_scanning_prefix,
            progress.file_count,
            format_size(progress.total_bytes)
        )));
    } else {
        // A bar drawn from block characters rather than ratatui's Gauge: the
        // same information, and it stays legible on a terminal with no colour.
        let filled = (progress.percent() as usize * 40) / 100;
        lines.push(Line::from(format!("[{}{}] {:>3}%", "█".repeat(filled), "░".repeat(40 - filled), progress.percent())));
        lines.push(Line::from(format!(
            "{}/{}  ·  {} / {}",
            progress.file_index,
            progress.file_count,
            format_size(progress.done_bytes),
            format_size(progress.total_bytes)
        )));
    }
    lines.push(Line::from(Span::styled(strings.transfer_hint, Style::default().fg(Color::DarkGray))));

    let box_area = super::widgets::centered_rect(60, lines.len() as u16 + 2, area);
    frame.render_widget(ratatui::widgets::Clear, box_area);
    frame.render_widget(
        Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(progress.title.clone())),
        box_area,
    );
}

fn render_pane(frame: &mut Frame, area: Rect, pane: &mut PaneState, label: &str, focused: bool, strings: &Strings) {
    let items: Vec<ListItem> = if let Some(error) = &pane.error {
        vec![ListItem::new(Line::from(Span::styled(error.clone(), Style::default().fg(Color::Red))))]
    } else if pane.entries.is_empty() {
        vec![ListItem::new(strings.file_browser_empty)]
    } else {
        pane.entries
            .iter()
            .map(|entry| {
                let marked = pane.marked.contains(&entry.name);
                let name = if entry.is_dir { format!("{}/", entry.name) } else { entry.name.clone() };
                let size = if entry.is_dir { String::new() } else { format_size(entry.size) };
                let mut style = Style::default();
                if entry.is_dir {
                    style = style.fg(Color::Cyan);
                }
                if marked {
                    style = style.fg(Color::Yellow).add_modifier(Modifier::BOLD);
                }
                ListItem::new(Line::from(vec![
                    Span::styled(if marked { "*" } else { " " }, style),
                    Span::styled(name, style),
                    Span::styled(format!("  {size}"), Style::default().fg(Color::DarkGray)),
                ]))
            })
            .collect()
    };

    // The path matters more than its middle: the leading directories and the
    // final component are what tell you where you are, so a long path loses
    // the middle rather than either end.
    let width = area.width.saturating_sub(label.len() as u16 + 6) as usize;
    let title = format!(" {label}: {} ", ellipsize_middle(&pane.cwd, width.max(8)));
    let border = if focused { Style::default().fg(Color::Cyan) } else { Style::default().fg(Color::DarkGray) };

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).border_style(border).title(title))
        .highlight_style(if focused {
            Style::default().add_modifier(Modifier::REVERSED)
        } else {
            Style::default().add_modifier(Modifier::DIM)
        })
        .highlight_symbol("> ");

    frame.render_stateful_widget(list, area, &mut pane.list_state);
    render_list_scrollbar(frame, area, pane.selected, pane.entries.len());
}

/// Reads one local directory into browser entries.
///
/// A name whose lossy UTF-8 conversion does not round-trip is skipped rather
/// than shown: it could not be transferred without corrupting it, and a row
/// that cannot be acted on is worse than an absent one.
fn read_local_dir(path: &Path, show_hidden: bool) -> std::io::Result<Vec<BrowserEntry>> {
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let raw = entry.file_name();
        let Some(name) = raw.to_str().map(|s| s.to_string()) else {
            continue;
        };
        if !show_hidden && name.starts_with('.') {
            continue;
        }
        // `metadata` follows symlinks, which is what makes a symlinked
        // directory navigable; the walk uses `symlink_metadata` separately to
        // decide what it will not recurse into.
        let meta = match entry.metadata() {
            Ok(meta) => meta,
            // A dangling symlink or a file that vanished mid-listing is still
            // worth a row; it just has no size.
            Err(_) => {
                entries.push(BrowserEntry { name, is_dir: false, size: 0 });
                continue;
            }
        };
        entries.push(BrowserEntry { name, is_dir: meta.is_dir(), size: meta.len() });
    }
    Ok(entries)
}

/// Joins a name from a listing onto a remote directory.
///
/// There is deliberately no `..` handling: the server owns that namespace, and
/// navigation is only ever "a name the server just gave us" or a REALPATH.
pub fn remote_join(cwd: &str, name: &str) -> String {
    if cwd.ends_with('/') {
        format!("{cwd}{name}")
    } else {
        format!("{cwd}/{name}")
    }
}

pub fn remote_parent(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    match trimmed.rfind('/') {
        // A child of the root keeps the root's slash: the parent of "/etc" is
        // "/", not "".
        Some(0) | None => "/".to_string(),
        Some(pos) => trimmed[..pos].to_string(),
    }
}

/// Keeps both ends of a path visible, dropping the middle.
pub fn ellipsize_middle(text: &str, width: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= width {
        return text.to_string();
    }
    if width <= 1 {
        return "…".to_string();
    }
    let keep = width - 1;
    let head = keep.div_ceil(2);
    let tail = keep - head;
    let mut out: String = chars[..head].iter().collect();
    out.push('…');
    out.extend(chars[chars.len() - tail..].iter());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::EN;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn entry(name: &str, is_dir: bool) -> BrowserEntry {
        BrowserEntry { name: name.to_string(), is_dir, size: 10 }
    }

    fn browser() -> FileBrowserState {
        let mut state = FileBrowserState::new(Uuid::new_v4(), "box".into(), PathBuf::from("/"), "/srv".into());
        state.local.set_entries(vec![entry("alpha", false), entry("beta", true)]);
        state.remote.set_entries(vec![entry("remote-a", false), entry("remote-dir", true)]);
        state
    }

    fn press(state: &mut FileBrowserState, code: KeyCode) -> FileBrowserOutcome {
        state.handle_key(KeyEvent::from(code))
    }

    #[test]
    fn paths_join_without_doubling_the_separator() {
        assert_eq!(remote_join("/", "etc"), "/etc");
        assert_eq!(remote_join("/srv", "www"), "/srv/www");
        assert_eq!(remote_join("/srv/", "www"), "/srv/www");
    }

    /// The parent of a child of the root is the root itself — an empty string
    /// would send the next listing somewhere undefined.
    #[test]
    fn the_parent_of_a_top_level_directory_is_the_root() {
        assert_eq!(remote_parent("/etc"), "/");
        assert_eq!(remote_parent("/srv/www/html"), "/srv/www");
        assert_eq!(remote_parent("/srv/www/"), "/srv");
        assert_eq!(remote_parent("/"), "/");
    }

    /// Backspace at the remote root has nothing to do, and must not fire a
    /// listing of a path that does not exist.
    #[test]
    fn going_up_from_the_remote_root_does_nothing() {
        let mut state = browser();
        state.focus = Side::Remote;
        state.remote.cwd = "/".to_string();
        assert!(matches!(press(&mut state, KeyCode::Backspace), FileBrowserOutcome::None));
    }

    /// Direction is read off the focus, and the destination is the other
    /// pane's directory. This is the whole of the transfer's "which way".
    #[test]
    fn the_direction_follows_the_focused_pane() {
        let mut state = browser();
        assert_eq!(state.direction(), (Side::Local, "/srv".to_string()));
        press(&mut state, KeyCode::Tab);
        assert_eq!(state.direction(), (Side::Remote, "/".to_string()));
    }

    /// Directories first, then names case-insensitively — the order the panes
    /// are read in, and what the index-based tests below rely on.
    #[test]
    fn directories_sort_above_files() {
        let state = browser();
        let names: Vec<&str> = state.local.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["beta", "alpha"]);
    }

    /// Marks are names: a refresh that reorders or removes entries must not
    /// silently move a mark onto a different file.
    #[test]
    fn a_mark_follows_the_name_through_a_refresh() {
        let mut state = browser();
        // Row 0 is the directory "beta"; row 1 is "alpha".
        press(&mut state, KeyCode::Down);
        press(&mut state, KeyCode::Char(' '));
        assert_eq!(state.local.transfer_selection().len(), 1);
        assert_eq!(state.local.transfer_selection()[0].name, "alpha");

        // The same entries arrive with a new one among them.
        state.local.set_entries(vec![entry("beta", true), entry("zeta", false), entry("alpha", false)]);
        assert_eq!(state.local.transfer_selection()[0].name, "alpha", "the mark still names alpha");
    }

    #[test]
    fn a_mark_for_an_entry_that_vanished_is_dropped() {
        let mut state = browser();
        press(&mut state, KeyCode::Down);
        press(&mut state, KeyCode::Char(' '));
        state.local.set_entries(vec![entry("beta", true)]);
        assert_eq!(state.local.transfer_selection()[0].name, "beta", "falls back to the cursor, not the stale mark");
    }

    /// Marks belong to the directory they were made in.
    #[test]
    fn changing_directory_clears_the_marks() {
        let mut state = browser();
        state.focus = Side::Remote;
        // Row 0 is the directory, row 1 the file: mark both, then open the
        // directory from row 0.
        press(&mut state, KeyCode::Char(' '));
        press(&mut state, KeyCode::Down);
        press(&mut state, KeyCode::Char(' '));
        press(&mut state, KeyCode::Up);

        let FileBrowserOutcome::OpenRemote(path) = press(&mut state, KeyCode::Enter) else {
            panic!("Enter on a directory should open it");
        };
        assert_eq!(path, "/srv/remote-dir");
        state.set_remote(path, vec![entry("inner", false)]);
        assert_eq!(state.remote.transfer_selection()[0].name, "inner", "no mark survived the move");
    }

    /// With nothing marked, the cursor is the selection — the common case
    /// should not need an extra keystroke.
    #[test]
    fn with_nothing_marked_the_cursor_is_what_transfers() {
        let mut state = browser();
        press(&mut state, KeyCode::Down);
        let selection = state.local.transfer_selection();
        assert_eq!(selection.len(), 1);
        assert_eq!(selection[0].name, "alpha");
    }

    /// Enter means "open a directory" and nothing else, which is why transfer
    /// has its own key.
    #[test]
    fn enter_on_a_file_does_nothing_and_t_transfers() {
        let mut state = browser();
        press(&mut state, KeyCode::Down);
        assert!(matches!(press(&mut state, KeyCode::Enter), FileBrowserOutcome::None));
        assert!(matches!(press(&mut state, KeyCode::Char('t')), FileBrowserOutcome::Transfer));
    }

    /// A denied listing on one side must leave the other side usable.
    #[test]
    fn an_error_on_one_pane_leaves_the_other_alone() {
        let mut state = browser();
        state.set_remote_error("permission denied".into());

        let rendered = render(&mut state, 100, 20);
        assert!(rendered.contains("permission denied"));
        assert!(rendered.contains("alpha"), "the local pane still lists its entries");
    }

    fn render(state: &mut FileBrowserState, width: u16, height: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("test backend");
        terminal
            .draw(|frame| state.render(frame, frame.area(), &EN))
            .expect("render");
        terminal.backend().buffer().content().iter().map(|c| c.symbol()).collect()
    }

    #[test]
    fn both_panes_and_their_paths_are_drawn() {
        let mut state = browser();
        let rendered = render(&mut state, 100, 20);
        assert!(rendered.contains(EN.file_browser_local_label));
        assert!(rendered.contains(EN.file_browser_remote_label));
        assert!(rendered.contains("remote-dir/"), "directories are marked with a trailing slash");
    }

    /// Two panes need more room than one form, so this screen has its own
    /// minimum rather than borrowing the form one.
    #[test]
    fn a_terminal_too_narrow_for_two_panes_says_so() {
        let mut state = browser();
        let rendered = render(&mut state, 40, 20);
        assert!(rendered.contains("too small"));
    }

    /// A transfer of nothing is complete, not a division by zero, and a
    /// counter that overshoots must not print 103%.
    #[test]
    fn progress_percentages_are_defined_at_both_ends() {
        let progress = |done, total| TransferProgress {
            title: String::new(),
            name: String::new(),
            file_index: 0,
            file_count: 0,
            done_bytes: done,
            total_bytes: total,
            scanning: false,
        };
        assert_eq!(progress(0, 0).percent(), 100);
        assert_eq!(progress(0, 100).percent(), 0);
        assert_eq!(progress(50, 100).percent(), 50);
        assert_eq!(progress(150, 100).percent(), 100);
    }

    #[test]
    fn a_long_path_keeps_both_ends() {
        let path = "/home/emin/projects/ssh-control/src/tui";
        let short = ellipsize_middle(path, 20);
        assert_eq!(short.chars().count(), 20);
        assert!(short.starts_with("/home/emin"));
        assert!(short.ends_with("tui"));
        assert_eq!(ellipsize_middle("/etc", 20), "/etc", "a path that fits is untouched");
    }
}
