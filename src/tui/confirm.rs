use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};

use super::widgets;
use crate::i18n::Strings;
use crate::tui::theme;

/// Generic reusable yes/no confirmation overlay.
pub struct ConfirmState {
    pub message: String,
}

pub enum ConfirmOutcome {
    None,
    Yes,
    No,
}

impl ConfirmState {
    pub fn new(message: String) -> Self {
        Self { message }
    }

    pub fn handle_key(&self, key: KeyEvent) -> ConfirmOutcome {
        match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => ConfirmOutcome::Yes,
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => ConfirmOutcome::No,
            _ => ConfirmOutcome::None,
        }
    }

    pub fn render(&self, frame: &mut Frame, area: Rect, strings: &Strings) {
        let hint = Span::styled(strings.confirm_hint, Style::default().fg(theme::hint()));
        let lines = vec![Line::from(self.message.clone()), Line::from(""), Line::from(hint)];
        let focus_row = lines.len() - 1;
        // Through `render_panel` rather than a fixed 50x5 box, because the
        // message is a prefix, a *server name* and a suffix: a long name wraps
        // to two or three rows and used to push the y/n prompt straight off the
        // bottom of a box that had been sized as if it were one line. The one
        // thing a confirm dialog cannot afford to lose is the confirm.
        //
        // The border carries the alarm and the message stays body text. A whole
        // box in `error()` made the name being deleted harder to read, which is
        // the one thing the dialog exists to show.
        widgets::render_panel_with(
            frame,
            area,
            56,
            strings.confirm_title,
            lines,
            // The *hint* is the focused row, not the message. When the message
            // is longer than the box the scroll has to keep the answer keys on
            // screen and let the name scroll instead — a question whose answer
            // keys are off screen is not a question.
            focus_row,
            strings.terminal_too_small,
            |block| block.border_style(Style::default().fg(theme::error())),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::EN;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn draw(message: &str, width: u16, height: u16) -> String {
        let state = ConfirmState::new(message.to_string());
        let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("test backend");
        terminal.draw(|frame| state.render(frame, frame.area(), &EN)).expect("render");
        terminal.backend().buffer().content().iter().map(|c| c.symbol()).collect()
    }

    /// A dialog that asks a question and then hides the answer keys is worse
    /// than no dialog. The message length is user data — a server name — so
    /// the box has to be sized from the wrapped text, not from the line count.
    #[test]
    fn a_long_name_cannot_push_the_answer_keys_off_the_box() {
        let long = format!("Delete server \"{}\"? This cannot be undone.", "extremely-long-server-name".repeat(40));
        for (width, height) in [(80, 24), (60, 12), (100, 30), (46, 10)] {
            let rendered = draw(&long, width, height);
            // A single word, not the phrase: the buffer is row-major over the
            // whole terminal, so a wrapped hint is interleaved with the padding
            // either side of the centred box.
            let first_word = EN.confirm_hint.split_whitespace().next().expect("the hint says something");
            assert!(rendered.contains(first_word), "{width}x{height}: the y/n prompt has to survive a long name");
        }
    }
}
