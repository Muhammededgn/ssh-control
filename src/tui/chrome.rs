//! The app-level frame: the background every screen is drawn on, and (from
//! here on) the bands above and below it.
//!
//! Not a helper in `widgets`, which is documented as free helpers a screen
//! calls for itself. This is the opposite — composition that knows which
//! screen is on top and what the app as a whole is — so it gets its own file.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::widgets::Block;

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
