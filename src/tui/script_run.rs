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

    pub fn handle_key(&self, key: KeyEvent) -> ScriptRunOutcome {
        if !self.finished {
            return ScriptRunOutcome::None;
        }
        match key.code {
            KeyCode::Enter | KeyCode::Esc | KeyCode::Char('q') => ScriptRunOutcome::Close,
            _ => ScriptRunOutcome::None,
        }
    }

    pub fn render(&self, frame: &mut Frame, area: Rect, strings: &Strings) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(3), Constraint::Length(3)])
            .split(area);

        let title = format!("{}— {} / {} ", strings.script_run_title, self.server_name, self.script_name);
        let visible_height = chunks[0].height.saturating_sub(2) as usize;
        let scroll = self.log.len().saturating_sub(visible_height) as u16;

        let paragraph = Paragraph::new(self.log.clone())
            .wrap(Wrap { trim: false })
            .scroll((scroll, 0))
            .block(Block::default().borders(Borders::ALL).title(title));
        frame.render_widget(paragraph, chunks[0]);

        let hint = if self.finished { strings.script_run_hint_done } else { strings.script_run_hint_running };
        let footer = Paragraph::new(Line::from(Span::styled(hint, Style::default().fg(Color::DarkGray))))
            .block(Block::default().borders(Borders::ALL));
        frame.render_widget(footer, chunks[1]);
    }
}
