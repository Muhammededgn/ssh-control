//! The app-level frame: the background every screen is drawn on, and (from
//! here on) the bands above and below it.
//!
//! Not a helper in `widgets`, which is documented as free helpers a screen
//! calls for itself. This is the opposite — composition that knows which
//! screen is on top and what the app as a whole is — so it gets its own file.

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph, Wrap};

use crate::i18n::Strings;
use crate::tui::theme;

/// Paints the frame's canvas. Must be the first widget of every draw closure.
///
/// A widget rather than a terminal-level background (`SetBackgroundColor`, or
/// OSC 11), and that is the whole decision: `TerminalGuard::suspend` leaves
/// the alternate screen so a real SSH session takes over the *primary* buffer,
/// and a terminal-level colour would repaint the user's own shell and their
/// entire remote session in the app's theme. Worse, `Drop for TerminalGuard`
/// calls `ratatui::restore()`, which knows nothing about it — so a panic would
/// leave the terminal permanently recoloured.
///
/// Painted into ratatui's buffer, the colour lives entirely inside the
/// alternate screen: `suspend` takes it away with the screen, `resume`'s
/// `clear()` forces the redraw that puts it back, and `restore()` has nothing
/// to undo. It costs nothing per frame either — ratatui diffs, so a background
/// that did not change is never re-emitted.
///
/// Under `Theme::Auto` and `NO_COLOR` every role is the terminal's own
/// default, so this paints the terminal's colours over the terminal's colours.
pub fn paint_background(frame: &mut Frame, area: Rect) {
    frame.render_widget(Block::default().style(theme::root()), area);
}

/// Rows the header takes. One: bands are for orientation, and this overhaul is
/// trying to give rows back to the lists, not spend them on decoration.
const HEADER_HEIGHT: u16 = 1;

/// Below this there is no room for bands at all and the screen gets everything
/// — a zero-height body is worse than no header.
const MIN_CHROME_HEIGHT: u16 = 8;

/// Draws the header and the footer, and returns the rect the screen should
/// render into.
///
/// The footer lines come from the screen because they are the screen's: a
/// filter box, a sort order, a transient status, the keybinding hint. What
/// moves here is only the arithmetic, which nine screens were each doing
/// slightly differently. The hint strings themselves are untouched `&'static
/// str`s out of `Strings`, so the help overlay is still splitting the same
/// text the footer shows — there is still exactly one copy of every binding.
pub fn render(frame: &mut Frame, area: Rect, title: &str, footer: Vec<Line<'static>>, strings: &Strings) -> Rect {
    if area.height < MIN_CHROME_HEIGHT {
        return area;
    }

    let footer_height = footer.len() as u16;
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(HEADER_HEIGHT), Constraint::Min(3), Constraint::Length(footer_height)])
        .split(area);

    render_header(frame, rows[0], title, strings);
    if footer_height > 0 {
        frame.render_widget(
            Paragraph::new(footer).wrap(Wrap { trim: false }).style(theme::band()),
            rows[2],
        );
    }
    rows[1]
}

/// The app on the left, the screen on the right.
///
/// The name comes from `Strings` and the version straight from Cargo, so
/// neither costs a translation — which is the whole reason the app could go
/// this long without ever telling the user which version they were running.
fn render_header(frame: &mut Frame, area: Rect, title: &str, strings: &Strings) {
    let left = Line::from(vec![
        Span::styled(strings.app_name, Style::default().fg(theme::accent()).add_modifier(Modifier::BOLD)),
        Span::raw(" "),
        Span::styled(env!("CARGO_PKG_VERSION"), Style::default().fg(theme::hint())),
    ]);
    let right = Line::from(Span::styled(title.trim(), Style::default().fg(theme::hint())));

    frame.render_widget(Block::default().style(theme::band()), area);
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(0), Constraint::Length(right.width() as u16 + 1)])
        .split(Rect { x: area.x + 1, width: area.width.saturating_sub(2), ..area });
    frame.render_widget(Paragraph::new(left).style(theme::band()), columns[0]);
    frame.render_widget(Paragraph::new(right).alignment(Alignment::Right).style(theme::band()), columns[1]);
}

/// The app, its version, where it came from and who wrote it, centred.
///
/// Only the pre-unlock screens draw this: inside the app the header already
/// says which app this is, and a repository URL on every frame is a row spent
/// on something nobody is reading. Here it is the difference between a small
/// box floating in an empty frame and a program introducing itself.
///
/// Everything comes from Cargo, so none of it needs translating.
pub fn brand(frame: &mut Frame, area: Rect, strings: &Strings) {
    let author = env!("CARGO_PKG_AUTHORS").split(':').next().unwrap_or("");
    let lines = vec![
        Line::from(Span::styled(strings.app_name, Style::default().fg(theme::accent()).add_modifier(Modifier::BOLD))),
        Line::from(Span::styled(
            format!("v{}  ·  {}", env!("CARGO_PKG_VERSION"), env!("CARGO_PKG_REPOSITORY")),
            Style::default().fg(theme::hint()),
        )),
        Line::from(Span::styled(author.to_string(), Style::default().fg(theme::hint()))),
    ];
    frame.render_widget(Paragraph::new(lines).alignment(Alignment::Center), area);
}

/// Rows `brand` needs, so a caller can split for it before drawing.
pub const BRAND_HEIGHT: u16 = 3;

/// The frame a pre-unlock screen sits in: header, brand block, and the rect
/// left for the panel itself.
///
/// These are the screens that used to be a 50x8 box in the middle of an
/// otherwise empty terminal, with nothing anywhere naming the program the
/// password was for. The brand block is not decoration — it is the only place
/// the app has ever said its own version, and on the two dead-end screens the
/// repository URL is the single most useful thing on the frame.
pub fn locked_body(frame: &mut Frame, area: Rect, title: &str, hint: Option<&str>, strings: &Strings) -> Rect {
    let footer = match hint {
        Some(hint) => vec![Line::from(Span::styled(hint.to_string(), Style::default().fg(theme::hint())))],
        None => Vec::new(),
    };
    let body = render(frame, area, title, footer, strings);
    // The brand is a nicety and the screen is not. Below this the rows it
    // wants are rows the panel needs to show all of its content, so it is
    // dropped rather than allowed to squeeze what the user came here for.
    const ROOM_FOR_BOTH: u16 = BRAND_HEIGHT + 14;
    if body.height < ROOM_FOR_BOTH {
        return body;
    }

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(BRAND_HEIGHT + 1), Constraint::Min(0)])
        .split(body);
    brand(frame, rows[0], strings);
    rows[1]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::EN;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn draw(f: impl FnOnce(&mut Frame, Rect), width: u16, height: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("test backend");
        terminal.draw(|frame| f(frame, frame.area())).expect("render");
        terminal.backend().buffer().content().iter().map(|c| c.symbol()).collect()
    }

    /// The app never told the user which version they were running: it was in
    /// `--version` and nowhere else, so from inside the TUI there was no way
    /// to find out. The header is where that stops being true.
    #[test]
    fn the_header_names_the_app_and_its_version() {
        let rendered = draw(|frame, area| {
            render(frame, area, EN.main_menu_title, Vec::new(), &EN);
        }, 100, 20);
        assert!(rendered.contains(EN.app_name));
        assert!(rendered.contains(env!("CARGO_PKG_VERSION")));
    }

    /// And the pre-unlock screens say where it came from and who wrote it —
    /// the two dead-end screens especially, where a repository URL is the most
    /// useful thing on the frame.
    #[test]
    fn the_locked_screens_introduce_the_program() {
        let rendered = draw(|frame, area| {
            locked_body(frame, area, EN.unlock_title_unlock, Some(EN.unlock_hint), &EN);
        }, 100, 30);
        assert!(rendered.contains(env!("CARGO_PKG_VERSION")));
        // A single path segment, not the whole URL: the buffer is row-major
        // over the terminal, so a centred line is interleaved with the padding
        // either side of it only when it wraps — and this one must not.
        assert!(rendered.contains("github.com"), "the repository has to be readable");
    }

    /// A frame with no room for bands gives the whole thing to the screen. A
    /// header over a zero-height body helps nobody.
    #[test]
    fn a_tiny_frame_keeps_all_of_itself_for_the_screen() {
        let area = Rect { x: 0, y: 0, width: 40, height: 4 };
        let mut terminal = Terminal::new(TestBackend::new(40, 4)).expect("test backend");
        let mut body = area;
        terminal.draw(|frame| body = render(frame, area, EN.main_menu_title, Vec::new(), &EN)).expect("render");
        assert_eq!(body, area);
    }
}
