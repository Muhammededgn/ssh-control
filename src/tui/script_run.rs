use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use uuid::Uuid;

use crate::i18n::Strings;

/// Live-updating log for one script run. `app.rs`'s async execution loop
/// pushes lines into this as `ssh::script_runner::run_script`'s `on_event`
/// callback fires, redrawing the frame after each push — nothing here runs
/// on its own, it's a plain data sink rendered by the normal draw loop too
/// once the run finishes (waiting for the user to close it).
pub struct ScriptRunState {
    pub server_id: Uuid,
    pub script_id: Uuid,
    pub server_name: String,
    pub script_name: String,
    log: Vec<Line<'static>>,
    partial: String,
    pub finished: bool,
    /// `None` means "follow the tail" — the default, and what a live run wants.
    /// Any manual scroll pins an offset here; `End` (or scrolling back to the
    /// bottom) drops it again so incoming output resumes following.
    scroll: Option<u16>,
    /// What the last frame actually had room for. Paging and the bottom clamp
    /// need the viewport, and only `render` knows it — the key handler runs
    /// with no `Rect` in sight.
    viewport: (u16, u16),
}

/// Rows one logical line occupies once `Wrap { trim: false }` has had it.
///
/// Greedy word wrapping, matching what ratatui does closely enough that the
/// scrollbar and the `End` clamp land on the same row the user sees. A word
/// longer than the width is broken rather than allowed to overflow.
fn wrapped_rows(text: &str, width: u16) -> usize {
    let width = width.max(1) as usize;
    let mut rows = 1;
    let mut col = 0;

    for word in text.split_inclusive(' ') {
        let len = word.chars().count();
        if col + len > width && col > 0 {
            rows += 1;
            col = 0;
        }
        // A single word wider than the viewport wraps within itself.
        if len > width {
            rows += (len - 1) / width;
            col = len % width;
        } else {
            col += len;
        }
    }
    rows
}

pub enum ScriptRunOutcome {
    None,
    Close,
}

impl ScriptRunState {
    pub fn new(server_id: Uuid, script_id: Uuid, server_name: String, script_name: String) -> Self {
        Self {
            server_id,
            script_id,
            server_name,
            script_name,
            log: Vec::new(),
            partial: String::new(),
            finished: false,
            scroll: None,
            viewport: (0, 0),
        }
    }

    pub fn step_started(&mut self, command: &str) {
        self.log.push(Line::from(Span::styled(
            format!("$ {command}"),
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )));
    }

    pub fn output(&mut self, chunk: &[u8]) {
        self.partial.push_str(&String::from_utf8_lossy(chunk));
        while let Some(pos) = self.partial.find('\n') {
            let line: String = self.partial.drain(..=pos).collect();
            self.log.push(Line::from(line.trim_end_matches(['\r', '\n']).to_string()));
        }
    }

    fn flush_partial(&mut self) {
        if !self.partial.is_empty() {
            let line = std::mem::take(&mut self.partial);
            self.log.push(Line::from(line));
        }
    }

    pub fn step_finished(&mut self, exit_code: i32, strings: &Strings) {
        self.flush_partial();
        let color = if exit_code == 0 { Color::Green } else { Color::Red };
        self.log.push(Line::from(Span::styled(
            format!("[{}{exit_code}]", strings.log_exit_prefix),
            Style::default().fg(color),
        )));
    }

    pub fn step_skipped(&mut self, strings: &Strings) {
        self.log.push(Line::from(Span::styled(strings.log_skipped, Style::default().fg(Color::DarkGray))));
    }

    pub fn step_error(&mut self, message: &str, strings: &Strings) {
        self.flush_partial();
        self.log.push(Line::from(Span::styled(
            format!("{}{message}", strings.log_error_prefix),
            Style::default().fg(Color::Red),
        )));
    }

    pub fn connect_error(&mut self, message: &str, strings: &Strings) {
        self.log.push(Line::from(Span::styled(
            format!("{}{message}", strings.log_error_prefix),
            Style::default().fg(Color::Red),
        )));
        self.finished = true;
    }

    pub fn mark_finished(&mut self) {
        self.flush_partial();
        self.finished = true;
    }

    /// Total rows the log occupies at the width of the last frame.
    fn total_rows(&self) -> usize {
        let (width, _) = self.viewport;
        self.log.iter().map(|line| wrapped_rows(&line.to_string(), width)).sum()
    }

    /// The offset that puts the last row on the bottom edge — the tail.
    fn max_scroll(&self) -> u16 {
        let (_, height) = self.viewport;
        self.total_rows().saturating_sub(height as usize).min(u16::MAX as usize) as u16
    }

    /// Moving back down onto the tail re-attaches rather than pinning an offset
    /// that the next line of output would immediately make stale.
    fn scroll_by(&mut self, delta: i32) {
        let max = self.max_scroll();
        let current = self.scroll.unwrap_or(max) as i32;
        let next = current.saturating_add(delta).clamp(0, max as i32) as u16;
        self.scroll = if next >= max { None } else { Some(next) };
    }

    /// Whether the view is pinned above the tail. Live output must not drag the
    /// screen out from under someone reading back through it.
    pub fn is_scrolled_back(&self) -> bool {
        self.scroll.is_some()
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> ScriptRunOutcome {
        // Scrolling works during the run too — that is the point, a long build
        // is exactly when you want to look back at what already scrolled past.
        let page = self.viewport.1.saturating_sub(1).max(1) as i32;
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.scroll_by(-1);
                return ScriptRunOutcome::None;
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.scroll_by(1);
                return ScriptRunOutcome::None;
            }
            KeyCode::PageUp => {
                self.scroll_by(-page);
                return ScriptRunOutcome::None;
            }
            KeyCode::PageDown => {
                self.scroll_by(page);
                return ScriptRunOutcome::None;
            }
            KeyCode::Home => {
                self.scroll = Some(0);
                return ScriptRunOutcome::None;
            }
            KeyCode::End => {
                self.scroll = None;
                return ScriptRunOutcome::None;
            }
            _ => {}
        }
        if !self.finished {
            return ScriptRunOutcome::None;
        }
        match key.code {
            KeyCode::Enter | KeyCode::Esc | KeyCode::Char('q') => ScriptRunOutcome::Close,
            _ => ScriptRunOutcome::None,
        }
    }

    pub fn render(&mut self, frame: &mut Frame, area: Rect, strings: &Strings) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(3), Constraint::Length(3)])
            .split(area);

        // Stashed before anything reads it: `total_rows` and the paging keys
        // both measure against the frame the user is actually looking at.
        self.viewport = (chunks[0].width.saturating_sub(2), chunks[0].height.saturating_sub(2));

        let title = format!("{}— {} / {} ", strings.script_run_title, self.server_name, self.script_name);
        let scroll = self.scroll.unwrap_or_else(|| self.max_scroll()).min(self.max_scroll());

        let paragraph = Paragraph::new(self.log.clone())
            .wrap(Wrap { trim: false })
            .scroll((scroll, 0))
            .block(Block::default().borders(Borders::ALL).title(title));
        frame.render_widget(paragraph, chunks[0]);

        let hint = if self.is_scrolled_back() {
            strings.script_run_hint_scrolled
        } else if self.finished {
            strings.script_run_hint_done
        } else {
            strings.script_run_hint_running
        };
        let style = if self.is_scrolled_back() { Style::default().fg(Color::Yellow) } else { Style::default().fg(Color::DarkGray) };
        let footer = Paragraph::new(Line::from(Span::styled(hint, style)))
            .block(Block::default().borders(Borders::ALL));
        frame.render_widget(footer, chunks[1]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::EN;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn run_with(lines: usize) -> ScriptRunState {
        let mut state = ScriptRunState::new(Uuid::new_v4(), Uuid::new_v4(), "host".into(), "deploy".into());
        for i in 0..lines {
            state.output(format!("line-{i}\n").as_bytes());
        }
        state
    }

    /// Renders at a fixed size and returns the screen as one string. The
    /// viewport the key handler pages against is only known after a frame, so
    /// every scrolling test has to draw first.
    fn render(state: &mut ScriptRunState, width: u16, height: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("test backend");
        terminal
            .draw(|frame| state.render(frame, frame.area(), &EN))
            .expect("render");
        terminal.backend().buffer().content().iter().map(|c| c.symbol()).collect()
    }

    fn press(state: &mut ScriptRunState, code: KeyCode) -> ScriptRunOutcome {
        state.handle_key(KeyEvent::from(code))
    }

    /// The issue's acceptance criterion: a long run has to be readable from the
    /// top, which before this was simply unreachable.
    #[test]
    fn a_long_run_can_be_read_from_the_top() {
        let mut state = run_with(500);
        state.mark_finished();

        let tail = render(&mut state, 40, 12);
        assert!(tail.contains("line-499"), "the default view is the tail");
        assert!(!tail.contains("line-0 "), "the top is off screen");

        press(&mut state, KeyCode::Home);
        let top = render(&mut state, 40, 12);
        assert!(top.contains("line-0"), "Home should reach the first line");
        assert!(!top.contains("line-499"));
    }

    /// Live output must not drag the screen out from under someone reading
    /// back — but only while they are actually scrolled back.
    #[test]
    fn new_output_follows_the_tail_only_while_attached() {
        let mut state = run_with(50);
        render(&mut state, 40, 12);

        press(&mut state, KeyCode::PageUp);
        assert!(state.is_scrolled_back());
        let pinned = state.scroll;
        state.output(b"fresh\n");
        assert_eq!(state.scroll, pinned, "output should not move a detached view");

        press(&mut state, KeyCode::End);
        assert!(!state.is_scrolled_back());
        let following = render(&mut state, 40, 12);
        assert!(following.contains("fresh"), "the tail should follow again");
    }

    /// Scrolling back down onto the last row re-attaches rather than pinning an
    /// offset the next line of output would make stale.
    #[test]
    fn scrolling_back_down_to_the_bottom_re_attaches() {
        let mut state = run_with(50);
        render(&mut state, 40, 12);

        press(&mut state, KeyCode::Up);
        assert!(state.is_scrolled_back());
        press(&mut state, KeyCode::Down);
        assert!(!state.is_scrolled_back(), "the bottom is the tail, not offset max");
    }

    /// Scrolling is not gated on `finished` — a long build is exactly when you
    /// want to look back — while closing still is.
    #[test]
    fn scrolling_works_during_the_run_but_closing_does_not() {
        let mut state = run_with(50);
        render(&mut state, 40, 12);
        assert!(!state.finished);

        press(&mut state, KeyCode::PageUp);
        assert!(state.is_scrolled_back(), "a running script can still be scrolled");
        assert!(matches!(press(&mut state, KeyCode::Enter), ScriptRunOutcome::None));

        state.mark_finished();
        assert!(matches!(press(&mut state, KeyCode::Enter), ScriptRunOutcome::Close));
    }

    /// `Wrap { trim: false }` is on, so a logical line can be several rows and
    /// the offsets have to be counted in rows or the clamp lands in the wrong
    /// place on wide output.
    #[test]
    fn row_counting_accounts_for_wrapping() {
        assert_eq!(wrapped_rows("short", 20), 1);
        assert_eq!(wrapped_rows("", 20), 1);
        // "aaaa bbbb cccc" at width 10 breaks after the second word.
        assert_eq!(wrapped_rows("aaaa bbbb cccc", 10), 2);
        // A single unbroken token wider than the viewport wraps within itself.
        assert_eq!(wrapped_rows(&"x".repeat(25), 10), 3);
    }

    /// One wrapped line is still worth scrolling through; counting it as one
    /// row would make `Home` stop short of the real top.
    #[test]
    fn a_single_very_long_line_is_scrollable() {
        let mut state = ScriptRunState::new(Uuid::new_v4(), Uuid::new_v4(), "host".into(), "deploy".into());
        state.output("start ".as_bytes());
        state.output("filler ".repeat(200).as_bytes());
        state.output(b"end\n");
        state.mark_finished();

        render(&mut state, 40, 12);
        assert!(state.max_scroll() > 0, "a wrapped line has rows to scroll through");
        press(&mut state, KeyCode::Home);
        let top = render(&mut state, 40, 12);
        assert!(top.contains("start"), "the beginning of the wrapped line is reachable");
    }
}
