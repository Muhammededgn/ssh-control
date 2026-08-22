use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};

use super::widgets::centered_rect;
use crate::i18n::Strings;
use crate::tui::theme;

/// Which screen's keys the overlay is showing. Deliberately coarser than
/// `Screen`: the two confirm screens and the two forms answer the same
/// question, and a topic per screen would only be more to keep in step.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HelpTopic {
    ServerList,
    ServerForm,
    Confirm,
    Settings,
    TotpPrompt,
    ScriptList,
    ScriptForm,
    ScriptRun,
    FileBrowser,
}

impl HelpTopic {
    /// The hint strings this screen already shows along its bottom edge.
    ///
    /// Reusing them rather than writing the overlay's own copy is the whole
    /// point: a keybinding can never be listed here and missing from the hint,
    /// or the other way round, because there is only one text. The overlay's
    /// job is that the hint is *readable* — it is one line, truncated on narrow
    /// terminals, and on the list screens a status message takes its place.
    fn hints(self, strings: &'static Strings) -> Vec<&'static str> {
        match self {
            HelpTopic::ServerList => vec![strings.main_menu_hint, strings.main_menu_filter_hint],
            HelpTopic::ServerForm => vec![strings.form_hint],
            HelpTopic::Confirm => vec![strings.confirm_hint],
            HelpTopic::Settings => {
                vec![strings.settings_lang_hint, strings.settings_password_hint, strings.settings_auto_lock_hint]
            }
            HelpTopic::TotpPrompt => vec![strings.totp_prompt_hint],
            HelpTopic::ScriptList => vec![strings.scripts_list_hint],
            HelpTopic::ScriptForm => vec![strings.steps_list_hint, strings.step_edit_hint],
            HelpTopic::ScriptRun => vec![strings.script_run_hint_done],
            HelpTopic::FileBrowser => vec![strings.file_browser_hint],
        }
    }
}

/// One binding per row, split back out of the hint line.
///
/// The hints join their bindings with two spaces (and sometimes a bullet), so
/// that is what splits them apart again. A hint that has never been split this
/// way still yields one row — worse formatting than a real list, never a
/// missing key.
fn bindings(hint: &str) -> Vec<String> {
    hint.split("  ")
        .map(|part| part.trim().trim_start_matches('•').trim().to_string())
        .filter(|part| !part.is_empty())
        .collect()
}

/// Draws the keybinding overlay for `topic` over whatever is already on screen.
///
/// Sized to its content and clamped by `centered_rect`, so a terminal too small
/// for the whole list shows as much of it as fits rather than nothing.
pub fn render(frame: &mut Frame, area: Rect, topic: HelpTopic, strings: &'static Strings) {
    let mut rows: Vec<Line> = Vec::new();
    for (i, hint) in topic.hints(strings).iter().enumerate() {
        if i > 0 {
            rows.push(Line::from(""));
        }
        for binding in bindings(hint) {
            rows.push(Line::from(binding));
        }
    }
    rows.push(Line::from(""));
    rows.push(Line::from(Span::styled(strings.help_hint, Style::default().fg(theme::hint()))));

    let width = rows.iter().map(|l| l.width()).max().unwrap_or(0).saturating_add(4) as u16;
    let height = rows.len().saturating_add(2) as u16;
    let popup = centered_rect(width, height, area);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(strings.help_title, Style::default().add_modifier(Modifier::BOLD)));
    frame.render_widget(Clear, popup);
    frame.render_widget(Paragraph::new(rows).block(block), popup);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::{EN, ES, RU, TR};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn render_topic(topic: HelpTopic, width: u16, height: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("test backend");
        terminal
            .draw(|frame| render(frame, frame.area(), topic, &EN))
            .expect("render");
        terminal.backend().buffer().content().iter().map(|c| c.symbol()).collect()
    }

    #[test]
    fn a_hint_becomes_one_row_per_binding() {
        assert_eq!(bindings("Enter: run  a: add  Esc: back"), vec!["Enter: run", "a: add", "Esc: back"]);
    }

    /// Some hints separate with a bullet; the overlay lists keys, not bullets.
    #[test]
    fn bullets_are_stripped_from_the_separator() {
        assert_eq!(bindings("Enter: confirm  •  Esc: quit"), vec!["Enter: confirm", "Esc: quit"]);
    }

    /// The overlay is built from the hints, so it must not be able to end up
    /// empty for a screen — that would be a screen documenting nothing.
    #[test]
    fn every_topic_lists_at_least_one_binding_in_every_language() {
        let topics = [
            HelpTopic::ServerList,
            HelpTopic::ServerForm,
            HelpTopic::Confirm,
            HelpTopic::Settings,
            HelpTopic::TotpPrompt,
            HelpTopic::ScriptList,
            HelpTopic::ScriptForm,
            HelpTopic::ScriptRun,
            HelpTopic::FileBrowser,
        ];
        for strings in [&EN, &TR, &ES, &RU] {
            for topic in topics {
                let count: usize = topic.hints(strings).iter().map(|h| bindings(h).len()).sum();
                assert!(count > 0, "{topic:?} lists nothing");
            }
        }
    }

    #[test]
    fn the_overlay_lists_the_screens_keys() {
        let rendered = render_topic(HelpTopic::ScriptList, 80, 24);
        assert!(rendered.contains("Enter: run"));
        assert!(rendered.contains("d: delete"));
        assert!(rendered.contains(EN.help_title.trim()));
    }

    /// A terminal smaller than the overlay shows what fits rather than nothing
    /// — `centered_rect` clamps, and the overlay must not assume it did not.
    #[test]
    fn a_small_terminal_still_gets_an_overlay() {
        let rendered = render_topic(HelpTopic::ServerList, 30, 6);
        assert!(rendered.contains("Enter: connect"));
    }
}
