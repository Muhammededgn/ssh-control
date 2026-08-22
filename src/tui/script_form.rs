use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};
use uuid::Uuid;

use super::widgets::{MIN_FORM_WIDTH, render_form, render_if_too_small};
use crate::config::{ScriptStep, StepCondition};
use crate::i18n::Strings;
use crate::tui::theme;
use crate::ssh::script_runner::STEP_TIMEOUT;

const CONDITION_COUNT: usize = 4;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FormMode {
    Add,
    Edit(Uuid),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Focus {
    Name,
    RunOnConnect,
    Steps,
    /// A focusable "button" row so the whole script can always be saved with
    /// plain Enter — Ctrl+Enter is offered as a shortcut too, but many
    /// terminals can't report Ctrl+Enter as distinct from Enter at all, so it
    /// must never be the *only* way to submit.
    Save,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum StepFocus {
    Command,
    Condition,
    OutputText,
    Timeout,
}

struct StepEditState {
    /// `None` means a brand new step appended at the end; `Some(i)` means
    /// editing the existing step at index `i`.
    editing_index: Option<usize>,
    command: String,
    condition_kind: usize,
    output_contains_text: String,
    /// Free text rather than a number, because the field has to be able to be
    /// empty — empty is what "use the default" looks like on screen, and a
    /// `u64` has no way to say it.
    timeout: String,
    focus: StepFocus,
}

pub struct ScriptFormState {
    pub server_id: Uuid,
    pub server_name: String,
    pub mode: FormMode,
    name: String,
    run_on_connect: bool,
    steps: Vec<ScriptStep>,
    focus: Focus,
    list_state: ListState,
    selected_step: usize,
    step_edit: Option<StepEditState>,
    pub error: Option<String>,
}

pub struct ScriptFormData {
    pub name: String,
    pub run_on_connect: bool,
    pub steps: Vec<ScriptStep>,
}

pub enum ScriptFormOutcome {
    None,
    Cancel,
    Submit(ScriptFormData),
}

impl ScriptFormState {
    pub fn new_add(server_id: Uuid, server_name: String) -> Self {
        Self {
            server_id,
            server_name,
            mode: FormMode::Add,
            name: String::new(),
            run_on_connect: false,
            steps: Vec::new(),
            focus: Focus::Name,
            list_state: ListState::default(),
            selected_step: 0,
            step_edit: None,
            error: None,
        }
    }

    pub fn new_edit(server_id: Uuid, server_name: String, script: &crate::config::Script) -> Self {
        Self {
            server_id,
            server_name,
            mode: FormMode::Edit(script.id),
            name: script.name.clone(),
            run_on_connect: script.run_on_connect,
            steps: script.steps.clone(),
            focus: Focus::Name,
            list_state: ListState::default(),
            selected_step: 0,
            step_edit: None,
            error: None,
        }
    }

    pub fn handle_key(&mut self, key: KeyEvent, strings: &Strings) -> ScriptFormOutcome {
        if self.step_edit.is_some() {
            self.handle_step_edit_key(key, strings);
            return ScriptFormOutcome::None;
        }

        self.error = None;
        match key.code {
            KeyCode::Esc => return ScriptFormOutcome::Cancel,
            KeyCode::Tab => self.move_focus(1),
            KeyCode::BackTab => self.move_focus(-1),
            KeyCode::Enter if key.modifiers.contains(KeyModifiers::CONTROL) => return self.submit(strings),
            KeyCode::Backspace if self.focus == Focus::Name => {
                self.name.pop();
            }
            KeyCode::Char(c) if self.focus == Focus::Name => self.name.push(c),
            KeyCode::Left | KeyCode::Right if self.focus == Focus::RunOnConnect => {
                self.run_on_connect = !self.run_on_connect;
            }
            KeyCode::Enter if self.focus == Focus::RunOnConnect => {
                self.run_on_connect = !self.run_on_connect;
            }
            KeyCode::Enter if self.focus == Focus::Save => return self.submit(strings),
            _ if self.focus == Focus::Steps => self.handle_steps_key(key),
            _ => {}
        }
        ScriptFormOutcome::None
    }

    fn move_focus(&mut self, delta: i32) {
        const ORDER: [Focus; 4] = [Focus::Name, Focus::RunOnConnect, Focus::Steps, Focus::Save];
        let idx = ORDER.iter().position(|f| *f == self.focus).unwrap_or(0);
        let len = ORDER.len() as i32;
        let next = (idx as i32 + delta).rem_euclid(len) as usize;
        self.focus = ORDER[next];
    }

    fn handle_steps_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up if key.modifiers.contains(KeyModifiers::CONTROL) => {
                if self.selected_step > 0 {
                    self.steps.swap(self.selected_step, self.selected_step - 1);
                    self.selected_step -= 1;
                }
            }
            KeyCode::Down if key.modifiers.contains(KeyModifiers::CONTROL) => {
                if self.selected_step + 1 < self.steps.len() {
                    self.steps.swap(self.selected_step, self.selected_step + 1);
                    self.selected_step += 1;
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if self.selected_step > 0 {
                    self.selected_step -= 1;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.selected_step + 1 < self.steps.len() {
                    self.selected_step += 1;
                }
            }
            KeyCode::Char('a') => self.begin_step_edit(None),
            KeyCode::Char('e') | KeyCode::Enter => {
                if !self.steps.is_empty() {
                    self.begin_step_edit(Some(self.selected_step));
                }
            }
            KeyCode::Char('d')
                if !self.steps.is_empty() => {
                    self.steps.remove(self.selected_step);
                    if self.selected_step >= self.steps.len() && self.selected_step > 0 {
                        self.selected_step -= 1;
                    }
                }
            _ => {}
        }
    }

    fn begin_step_edit(&mut self, editing_index: Option<usize>) {
        let existing = editing_index.and_then(|i| self.steps.get(i));
        let (command, condition_kind, output_contains_text, timeout) = match existing {
            Some(step) => {
                let (kind, text) = condition_to_kind(&step.condition);
                let timeout = step.timeout_secs.map(|s| s.to_string()).unwrap_or_default();
                (step.command.clone(), kind, text, timeout)
            }
            None => (String::new(), 0, String::new(), String::new()),
        };
        self.step_edit = Some(StepEditState {
            editing_index,
            command,
            condition_kind,
            output_contains_text,
            timeout,
            focus: StepFocus::Command,
        });
    }

    fn is_editing_first_step(&self) -> bool {
        self.step_edit
            .as_ref()
            .map(|se| se.editing_index.unwrap_or(self.steps.len()) == 0)
            .unwrap_or(false)
    }

    fn handle_step_edit_key(&mut self, key: KeyEvent, strings: &Strings) {
        self.error = None;
        let is_first = self.is_editing_first_step();
        let se = self.step_edit.as_mut().expect("checked by caller");

        match key.code {
            KeyCode::Esc => {
                self.step_edit = None;
            }
            KeyCode::Tab => {
                se.focus = next_step_focus(se.focus, is_first, se.condition_kind, 1);
            }
            KeyCode::BackTab => {
                se.focus = next_step_focus(se.focus, is_first, se.condition_kind, -1);
            }
            KeyCode::Left | KeyCode::Right if se.focus == StepFocus::Condition && !is_first => {
                let delta: i32 = if key.code == KeyCode::Left { -1 } else { 1 };
                se.condition_kind = (se.condition_kind as i32 + delta).rem_euclid(CONDITION_COUNT as i32) as usize;
            }
            KeyCode::Backspace => match se.focus {
                StepFocus::Command => {
                    se.command.pop();
                }
                StepFocus::OutputText => {
                    se.output_contains_text.pop();
                }
                StepFocus::Timeout => {
                    se.timeout.pop();
                }
                StepFocus::Condition => {}
            },
            KeyCode::Char(c) => match se.focus {
                StepFocus::Command => se.command.push(c),
                StepFocus::OutputText => se.output_contains_text.push(c),
                StepFocus::Timeout => se.timeout.push(c),
                StepFocus::Condition => {}
            },
            KeyCode::Enter if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.commit_step_edit(strings);
            }
            KeyCode::Enter => {
                let order = step_focus_order(is_first, se.condition_kind);
                if order.last() == Some(&se.focus) {
                    self.commit_step_edit(strings);
                } else {
                    se.focus = next_step_focus(se.focus, is_first, se.condition_kind, 1);
                }
            }
            _ => {}
        }
    }

    fn commit_step_edit(&mut self, strings: &Strings) {
        let se = self.step_edit.as_ref().expect("checked by caller");
        if se.command.trim().is_empty() {
            self.error = Some(strings.err_step_command_empty.to_string());
            return;
        }
        let is_first = se.editing_index.unwrap_or(self.steps.len()) == 0;
        let condition = if is_first {
            StepCondition::Always
        } else {
            match se.condition_kind {
                0 => StepCondition::Always,
                1 => StepCondition::OnSuccess,
                2 => StepCondition::OnFailure,
                _ => {
                    if se.output_contains_text.trim().is_empty() {
                        self.error = Some(strings.err_output_contains_empty.to_string());
                        return;
                    }
                    StepCondition::OutputContains(se.output_contains_text.trim().to_string())
                }
            }
        };

        // Empty means "use the default", which is also what every step written
        // before this field existed deserialises to.
        let timeout_secs = match se.timeout.trim() {
            "" => None,
            text => match text.parse::<u64>() {
                Ok(secs) if secs > 0 => Some(secs),
                _ => {
                    self.error = Some(strings.err_step_timeout_invalid.to_string());
                    return;
                }
            },
        };

        let step = ScriptStep { command: se.command.trim().to_string(), condition, timeout_secs };
        match se.editing_index {
            Some(i) => self.steps[i] = step,
            None => {
                self.steps.push(step);
                self.selected_step = self.steps.len() - 1;
            }
        }
        self.step_edit = None;
    }

    fn submit(&mut self, strings: &Strings) -> ScriptFormOutcome {
        if self.name.trim().is_empty() {
            self.error = Some(strings.err_script_name_empty.to_string());
            return ScriptFormOutcome::None;
        }
        if self.steps.is_empty() {
            self.error = Some(strings.err_need_at_least_one_step.to_string());
            return ScriptFormOutcome::None;
        }

        ScriptFormOutcome::Submit(ScriptFormData {
            name: self.name.trim().to_string(),
            run_on_connect: self.run_on_connect,
            steps: self.steps.clone(),
        })
    }

    pub fn render(&mut self, frame: &mut Frame, area: Rect, strings: &Strings) {
        if self.step_edit.is_some() {
            self.render_step_edit(frame, area, strings);
        } else {
            self.render_main(frame, area, strings);
        }
    }

    fn render_main(&mut self, frame: &mut Frame, area: Rect, strings: &Strings) {
        // 4 + 3 + 4, the three constraints below. Any shorter and ratatui
        // shrinks the step list to nothing rather than the screen saying why.
        const MIN_MAIN_HEIGHT: u16 = 11;
        if render_if_too_small(frame, area, MIN_FORM_WIDTH, MIN_MAIN_HEIGHT, strings.terminal_too_small) {
            return;
        }

        let title = match self.mode {
            FormMode::Add => strings.script_form_title_add,
            FormMode::Edit(_) => strings.script_form_title_edit,
        };

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(4), Constraint::Min(3), Constraint::Length(4)])
            .split(area);

        let field_line = |label: &str, value: String, focused: bool| {
            let cursor = if focused { "_" } else { "" };
            let style = if focused { Style::default().fg(theme::accent()) } else { Style::default() };
            Line::from(vec![
                Span::styled(format!("{label}: "), style),
                Span::raw(format!("{value}{cursor}")),
            ])
        };

        let run_on_connect_label = if self.run_on_connect { strings.label_yes } else { strings.label_no };
        let top_lines = vec![
            field_line(strings.field_script_name, self.name.clone(), self.focus == Focus::Name),
            field_line(
                strings.field_run_on_connect,
                run_on_connect_label.to_string(),
                self.focus == Focus::RunOnConnect,
            ),
        ];
        frame.render_widget(Paragraph::new(top_lines).block(Block::default().borders(Borders::ALL).title(title)), chunks[0]);

        let items: Vec<ListItem> = self
            .steps
            .iter()
            .enumerate()
            .map(|(i, step)| ListItem::new(format!("{}. {}  [{}]", i + 1, step.command, condition_label(&step.condition, strings))))
            .collect();
        let mut list_state = self.list_state;
        list_state.select(if self.steps.is_empty() { None } else { Some(self.selected_step) });
        let highlight_style = if self.focus == Focus::Steps {
            Style::default().add_modifier(Modifier::REVERSED)
        } else {
            Style::default().fg(theme::accent())
        };
        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title(strings.steps_list_title))
            .highlight_style(highlight_style)
            .highlight_symbol("> ");
        frame.render_stateful_widget(list, chunks[1], &mut list_state);
        self.list_state = list_state;

        let save_style = if self.focus == Focus::Save {
            Style::default().add_modifier(Modifier::REVERSED)
        } else {
            Style::default().fg(theme::accent())
        };
        let save_line = Line::from(Span::styled(format!("[ {} ]", strings.field_save_script), save_style));
        let hint_line = if let Some(err) = &self.error {
            Line::from(Span::styled(err.clone(), Style::default().fg(theme::error())))
        } else {
            Line::from(Span::styled(strings.steps_list_hint, Style::default().fg(theme::hint())))
        };
        frame.render_widget(
            Paragraph::new(vec![save_line, hint_line]).block(Block::default().borders(Borders::ALL)),
            chunks[2],
        );
    }

    fn render_step_edit(&self, frame: &mut Frame, area: Rect, strings: &Strings) {
        let se = self.step_edit.as_ref().expect("checked by caller");
        let is_first = self.is_editing_first_step();

        let field_line = |label: &str, value: String, focused: bool| {
            let cursor = if focused { "_" } else { "" };
            let style = if focused { Style::default().fg(theme::accent()) } else { Style::default() };
            Line::from(vec![
                Span::styled(format!("{label}: "), style),
                Span::raw(format!("{value}{cursor}")),
            ])
        };

        let mut lines = vec![field_line(strings.step_field_command, se.command.clone(), se.focus == StepFocus::Command)];

        if !is_first {
            let label = condition_kind_label(se.condition_kind, strings);
            lines.push(field_line(strings.step_field_condition, label, se.focus == StepFocus::Condition));
            if se.condition_kind == 3 {
                lines.push(field_line(
                    strings.step_field_output_contains_text,
                    se.output_contains_text.clone(),
                    se.focus == StepFocus::OutputText,
                ));
            }
        }
        // Blank shows the default it would fall back to rather than an empty
        // field, so the number in force is always on screen.
        let timeout_value = if se.timeout.is_empty() {
            format!(
                "{}{}{}",
                strings.step_timeout_default_prefix,
                STEP_TIMEOUT.as_secs(),
                strings.step_timeout_seconds_suffix
            )
        } else {
            format!("{}{}", se.timeout, strings.step_timeout_seconds_suffix)
        };
        lines.push(field_line(strings.step_field_timeout, timeout_value, se.focus == StepFocus::Timeout));

        lines.push(Line::from(""));
        // Its own line rather than part of `step_edit_hint`: that string is
        // what the help overlay splits into keybinding rows, and this is not a
        // key.
        lines.push(Line::from(Span::styled(strings.step_vars_hint, Style::default().fg(theme::hint()))));
        if let Some(err) = &self.error {
            lines.push(Line::from(Span::styled(err.clone(), Style::default().fg(theme::error()))));
        } else {
            lines.push(Line::from(Span::styled(strings.step_edit_hint, Style::default().fg(theme::hint()))));
        }

        // Same order as `step_focus_order`, so the focus index is the row.
        let focus_row = step_focus_order(is_first, se.condition_kind)
            .iter()
            .position(|f| *f == se.focus)
            .unwrap_or(0);
        render_form(frame, area, strings.steps_list_title, lines, focus_row, strings.terminal_too_small);
    }
}

fn condition_to_kind(condition: &StepCondition) -> (usize, String) {
    match condition {
        StepCondition::Always => (0, String::new()),
        StepCondition::OnSuccess => (1, String::new()),
        StepCondition::OnFailure => (2, String::new()),
        StepCondition::OutputContains(text) => (3, text.clone()),
    }
}

fn condition_kind_label(kind: usize, strings: &Strings) -> String {
    match kind {
        0 => strings.condition_always.to_string(),
        1 => strings.condition_on_success.to_string(),
        2 => strings.condition_on_failure.to_string(),
        _ => strings.condition_output_contains.to_string(),
    }
}

fn condition_label(condition: &StepCondition, strings: &Strings) -> String {
    match condition {
        StepCondition::Always => strings.condition_always.to_string(),
        StepCondition::OnSuccess => strings.condition_on_success.to_string(),
        StepCondition::OnFailure => strings.condition_on_failure.to_string(),
        StepCondition::OutputContains(text) => format!("{}: {text}", strings.condition_output_contains),
    }
}

/// Fields actually shown for this step (fewer when it's the first step,
/// since condition editing is hidden there — always `Always`).
fn step_focus_order(is_first: bool, condition_kind: usize) -> Vec<StepFocus> {
    let mut order = vec![StepFocus::Command];
    if !is_first {
        order.push(StepFocus::Condition);
        if condition_kind == 3 {
            order.push(StepFocus::OutputText);
        }
    }
    order.push(StepFocus::Timeout);
    order
}

fn next_step_focus(current: StepFocus, is_first: bool, condition_kind: usize, delta: i32) -> StepFocus {
    let order = step_focus_order(is_first, condition_kind);
    let idx = order.iter().position(|f| *f == current).unwrap_or(0);
    let len = order.len() as i32;
    let next = (idx as i32 + delta).rem_euclid(len) as usize;
    order[next]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::EN;

    fn form_with_a_step_open() -> ScriptFormState {
        let mut form = ScriptFormState::new_add(Uuid::new_v4(), "box".into());
        form.focus = Focus::Steps;
        form.handle_key(KeyEvent::from(KeyCode::Char('a')), &EN);
        form
    }

    fn type_text(form: &mut ScriptFormState, text: &str) {
        for c in text.chars() {
            form.handle_key(KeyEvent::from(KeyCode::Char(c)), &EN);
        }
    }

    fn focus_timeout(form: &mut ScriptFormState) {
        for _ in 0..4 {
            let se = form.step_edit.as_ref().expect("step editor open");
            if se.focus == StepFocus::Timeout {
                return;
            }
            form.handle_key(KeyEvent::from(KeyCode::Tab), &EN);
        }
        panic!("the timeout field is not in the focus order");
    }

    #[test]
    fn a_step_with_no_timeout_entered_keeps_the_default() {
        let mut form = form_with_a_step_open();
        type_text(&mut form, "uptime");
        form.handle_key(KeyEvent::from(KeyCode::Enter), &EN);
        // Enter walks to the timeout field, then commits from the last one.
        form.handle_key(KeyEvent::from(KeyCode::Enter), &EN);

        assert_eq!(form.steps.len(), 1);
        assert_eq!(form.steps[0].timeout_secs, None, "blank means the built-in default");
    }

    #[test]
    fn a_timeout_typed_into_the_step_is_stored() {
        let mut form = form_with_a_step_open();
        type_text(&mut form, "sleep 300");
        focus_timeout(&mut form);
        type_text(&mut form, "5");
        form.handle_key(KeyEvent::from(KeyCode::Enter), &EN);

        assert_eq!(form.steps[0].timeout_secs, Some(5));
    }

    /// A step editor that swallowed "abc" as a timeout would produce a step
    /// that silently ran on the default instead of what was typed.
    #[test]
    fn a_timeout_that_is_not_a_number_is_refused() {
        let mut form = form_with_a_step_open();
        type_text(&mut form, "uptime");
        focus_timeout(&mut form);
        type_text(&mut form, "abc");
        form.handle_key(KeyEvent::from(KeyCode::Enter), &EN);

        assert!(form.steps.is_empty(), "the step must not be committed");
        assert_eq!(form.error.as_deref(), Some(EN.err_step_timeout_invalid));
        assert!(form.step_edit.is_some(), "the editor stays open on the bad value");
    }

    /// Zero seconds is not "no timeout", it is a step that can never finish —
    /// blank is how the default is asked for.
    #[test]
    fn a_zero_timeout_is_refused() {
        let mut form = form_with_a_step_open();
        type_text(&mut form, "uptime");
        focus_timeout(&mut form);
        type_text(&mut form, "0");
        form.handle_key(KeyEvent::from(KeyCode::Enter), &EN);

        assert!(form.steps.is_empty());
        assert_eq!(form.error.as_deref(), Some(EN.err_step_timeout_invalid));
    }

    /// Editing an existing step shows the timeout it was saved with, so the
    /// number does not quietly reset to the default on every edit.
    #[test]
    fn editing_a_step_shows_the_timeout_it_was_saved_with() {
        let mut form = ScriptFormState::new_add(Uuid::new_v4(), "box".into());
        form.steps.push(ScriptStep { command: "uptime".into(), condition: StepCondition::Always, timeout_secs: Some(30) });
        form.focus = Focus::Steps;
        form.handle_key(KeyEvent::from(KeyCode::Char('e')), &EN);

        assert_eq!(form.step_edit.as_ref().expect("editor open").timeout.as_str(), "30");
    }
}
