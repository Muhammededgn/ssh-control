//! The screen half of the second connect mode: a terminal emulator drawn
//! inside the app's own frame.
//!
//! `ssh::pty_bridge` hands the whole terminal over and copies bytes through
//! it, which is what makes "interactive programs behave exactly as they would
//! under plain `ssh`" true. Drawing a session into a `Rect` means parsing all
//! of it instead, so the two modes are different things and both are kept —
//! this one is for the small operations that are not worth losing the app for.
//!
//! Everything here is synchronous: a `vt100::Parser`, the key-prefix state
//! machine, and the rendering. Nothing awaits and nothing touches russh, the
//! same layering `ssh::sftp::wire` has under `ssh::sftp::client` — the channel
//! and the select loop live in `App::pane_connect_flow`.
//!
//! **The pane's interior is not themed, and cannot be.** `tui-term` sets every
//! cell, blanks included, to the colours the remote asked for, with a default
//! cell coming out as the terminal's own default. That is correct: a terminal
//! emulator's job is to show what the remote sent, and repainting `htop` in
//! the app's palette would be the bug. The border, the title and the footer
//! are the app's, so the pane still reads as part of it.

use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use tui_term::vt100;
use tui_term::widget::{Cursor, PseudoTerminal};

use crate::i18n::Strings;
use crate::tui::{theme, vt_input, widgets};

/// Rows the parser keeps above the visible screen.
///
/// Retained from the first version even though nothing can scroll back to
/// them yet: the forward report and the `run_on_connect` output are fed in
/// ahead of the shell, and a long script would otherwise push its own start
/// somewhere unreachable. In the full-screen mode that text survives in the
/// terminal's own scrollback, which is why `TerminalGuard`'s `Drop` clears
/// with `ClearType::All` and never `Purge`.
const SCROLLBACK: usize = 1000;

/// How long the first `Esc` is held while waiting to see whether a second one
/// follows.
const ESC_DETACH_WINDOW: Duration = Duration::from_millis(300);

/// Below this there is not enough of a terminal left to run a shell in.
const MIN_PANE_COLS: u16 = 20;
const MIN_PANE_ROWS: u16 = 4;

/// The prefix key, `Ctrl+B`. Chosen for the reason tmux chose it: it is not a
/// key a shell uses for anything a user would miss, and everything behind it
/// is reachable without stealing a plain keystroke from the remote.
const PREFIX: u8 = 0x02;

/// What the pane wants the flow to do with a key.
pub enum PaneOutcome {
    Nothing,
    /// Bytes for the remote, already encoded.
    Send(Vec<u8>),
    /// End the session and go back to the list.
    Detach,
}

/// Where the keyboard is between one key and the next.
enum Prefix {
    /// Every key goes to the remote.
    Idle,
    /// `Ctrl+B` was pressed and the next key is a command.
    Armed,
    /// An `Esc` is being held to see whether a second one follows it.
    EscHeld(Instant),
}

pub struct SessionPaneState {
    server_name: String,
    parser: vt100::Parser,
    prefix: Prefix,
    dirty: bool,
}

impl SessionPaneState {
    pub fn new(server_name: String, cols: u16, rows: u16) -> Self {
        Self { server_name, parser: vt100::Parser::new(rows, cols, SCROLLBACK), prefix: Prefix::Idle, dirty: true }
    }

    /// Bytes from the remote, straight into the parser.
    pub fn feed(&mut self, bytes: &[u8]) {
        self.parser.process(bytes);
        self.dirty = true;
    }

    /// Lines the app produced itself — the forward report, the on-connect
    /// script output — as though the remote had written them.
    ///
    /// `\r\n`, not `\n`: this is a terminal, and a bare line feed moves down a
    /// row without returning to column zero, which stair-steps.
    pub fn feed_line(&mut self, line: &str) {
        self.feed(line.as_bytes());
        self.feed(b"\r\n");
    }

    /// Follows the pane, and tells the parser before the remote is told.
    ///
    /// **Narrowing loses the tail of every line already on the grid, and
    /// widening does not bring it back.** `vt100::Grid::set_size` resizes each
    /// row with `Cell::new()` padding, which truncates rather than reflows —
    /// there is no rewrap in the crate to reach for. That is what a plain
    /// xterm does too, but most terminals people actually use (VTE, kitty,
    /// alacritty, wezterm) reflow, so it reads as a regression against the
    /// terminal the app is running in. `narrowing_truncates_what_is_already_on
    /// _the_grid` pins it so a later backend change is a deliberate one.
    ///
    /// The grid's width has to stay equal to the width the remote was told:
    /// autowrap happens at the grid edge, so a grid wider than the remote's
    /// idea of the window would let a long line run past the visible area
    /// instead of wrapping into it. That rules out the obvious workaround of
    /// only ever growing.
    pub fn resize(&mut self, cols: u16, rows: u16) {
        self.parser.screen_mut().set_size(rows, cols);
        self.dirty = true;
    }

    /// Whether the remote is on the alternate screen — vim, less, htop.
    ///
    /// The `Esc Esc` hatch is off while it is, because mashing `Esc` is the
    /// ordinary idiom in exactly those programs and a detach closes the
    /// session. `Ctrl+B d` still works everywhere.
    pub fn alt_screen(&self) -> bool {
        self.parser.screen().alternate_screen()
    }

    pub fn prefix_armed(&self) -> bool {
        matches!(self.prefix, Prefix::Armed)
    }

    /// True once, for each change since the last frame — the flow redraws on
    /// it rather than on every packet.
    pub fn take_dirty(&mut self) -> bool {
        std::mem::take(&mut self.dirty)
    }

    /// Lets a held `Esc` expire. Called on the flow's tick, so a lone `Esc`
    /// reaches the remote even when nothing else is typed after it.
    pub fn tick(&mut self, now: Instant) -> PaneOutcome {
        match self.prefix {
            Prefix::EscHeld(at) if now.duration_since(at) >= ESC_DETACH_WINDOW => {
                self.prefix = Prefix::Idle;
                self.dirty = true;
                PaneOutcome::Send(vec![0x1b])
            }
            _ => PaneOutcome::Nothing,
        }
    }

    /// One key, resolved against the prefix state.
    ///
    /// `now` is a parameter rather than an `Instant::now()` inside, so the
    /// window is testable without sleeping — the same discipline that keeps
    /// `ServerSort` threaded per call.
    pub fn handle_key(&mut self, key: KeyEvent, now: Instant) -> PaneOutcome {
        match std::mem::replace(&mut self.prefix, Prefix::Idle) {
            Prefix::Armed => {
                self.dirty = true;
                self.prefix_command(key)
            }
            // The first `Esc` was held rather than sent, so it goes out in
            // front of whatever followed it, in one write. Order is what makes
            // `Esc :wq` work.
            Prefix::EscHeld(at) if now.duration_since(at) < ESC_DETACH_WINDOW => {
                self.dirty = true;
                if key.code == KeyCode::Esc && key.modifiers.is_empty() {
                    // Held rather than sent-then-detached on purpose: a detach
                    // closes the session, and a stray `Esc` delivered to a
                    // shell whose PTY then died is the one outcome nobody can
                    // reason about afterwards.
                    return PaneOutcome::Detach;
                }
                match self.encode(key) {
                    Some(mut bytes) => {
                        bytes.insert(0, 0x1b);
                        PaneOutcome::Send(bytes)
                    }
                    None => PaneOutcome::Send(vec![0x1b]),
                }
            }
            // An expired hold that a key arrived on the same tick as: the
            // `Esc` still goes first, it is simply no longer a detach.
            Prefix::EscHeld(_) => {
                self.dirty = true;
                let mut bytes = vec![0x1b];
                bytes.extend(self.encode(key).unwrap_or_default());
                PaneOutcome::Send(bytes)
            }
            Prefix::Idle => self.idle_key(key, now),
        }
    }

    fn idle_key(&mut self, key: KeyEvent, now: Instant) -> PaneOutcome {
        if key.code == KeyCode::Char('b') && key.modifiers == KeyModifiers::CONTROL {
            self.prefix = Prefix::Armed;
            self.dirty = true;
            return PaneOutcome::Nothing;
        }
        // On the alternate screen `Esc` is not held at all: it is the key vim
        // and less are waiting for, and a third of a second of latency on it
        // is the most noticeable delay the pane could introduce.
        if key.code == KeyCode::Esc && key.modifiers.is_empty() && !self.alt_screen() {
            self.prefix = Prefix::EscHeld(now);
            self.dirty = true;
            return PaneOutcome::Nothing;
        }
        match self.encode(key) {
            Some(bytes) => PaneOutcome::Send(bytes),
            None => PaneOutcome::Nothing,
        }
    }

    /// The key after `Ctrl+B`.
    ///
    /// Anything unrecognised is **swallowed**, not forwarded: a prefix key is
    /// a command word, and passing an unknown one through would run it at the
    /// remote's shell prompt — `Ctrl+B q` should do nothing, not quit.
    fn prefix_command(&mut self, key: KeyEvent) -> PaneOutcome {
        match (key.code, key.modifiers) {
            (KeyCode::Char('d'), KeyModifiers::NONE) => PaneOutcome::Detach,
            (KeyCode::Char('b'), KeyModifiers::CONTROL) => PaneOutcome::Send(vec![PREFIX]),
            _ => PaneOutcome::Nothing,
        }
    }

    /// DECCKM comes off the live screen, so the arrows are whatever the
    /// program currently running asked for rather than a guess.
    fn encode(&self, key: KeyEvent) -> Option<Vec<u8>> {
        vt_input::encode(key, self.parser.screen().application_cursor())
    }

    pub fn render(&mut self, frame: &mut Frame, area: Rect, strings: &Strings) {
        // The style rides on the block and not on the widget: `PseudoTerminal`
        // renders a `Clear` before anything else, which resets cells to the
        // terminal's own default, and `Block::render` paints its style over
        // the whole area afterwards. That is `widgets::clear_surface`'s rule
        // honoured through the only hook the widget offers — its own `style`
        // is stored and never read.
        let block = widgets::panel(&format!("{}{}", strings.session_pane_title_prefix, self.server_name)).style(theme::root());
        let cursor = Cursor::default().style(Style::default().fg(theme::accent()));
        frame.render_widget(PseudoTerminal::new(self.parser.screen()).block(block).cursor(cursor), area);
    }
}

/// The pane's own footer, which is also what sizes it — the frame's body rect
/// depends on how many rows the footer wraps to.
///
/// Free rather than a method because `viewport` has to be answerable before
/// there is a `SessionPaneState`: the remote PTY is sized during the connect.
pub fn footer(prefix_armed: bool, alt_screen: bool, strings: &Strings) -> Vec<Line<'static>> {
    let hint = match (prefix_armed, alt_screen) {
        (true, _) => strings.session_pane_prefix_hint,
        // Never promises `Esc Esc` where it does not apply.
        (false, true) => strings.session_pane_hint_alt_screen,
        (false, false) => strings.session_pane_hint,
    };
    vec![Line::from(Span::styled(hint, Style::default().fg(theme::hint())))]
}

/// The size the remote PTY should be, for a frame of `area`.
///
/// `None` when the frame leaves too little to run a shell in — the flow says
/// so and returns *before* connecting, so there is nothing to undo.
///
/// Goes through `chrome::body` and `widgets::panel(..).inner(..)` rather than
/// subtracting borders by hand, and `render` derives its own rect the same
/// way, so the two cannot disagree about what fits. A remote whose idea of the
/// window is wrong is not something the user can see or correct.
pub fn viewport(area: Rect, footer: &[Line<'_>]) -> Option<(u16, u16)> {
    let inner = widgets::panel("").inner(crate::tui::chrome::body(area, footer));
    (inner.width >= MIN_PANE_COLS && inner.height >= MIN_PANE_ROWS).then_some((inner.width, inner.height))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::EN;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn pane() -> SessionPaneState {
        SessionPaneState::new("web-1".into(), 40, 10)
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn ctrl(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
    }

    fn sent(outcome: PaneOutcome) -> Option<Vec<u8>> {
        match outcome {
            PaneOutcome::Send(bytes) => Some(bytes),
            PaneOutcome::Nothing => None,
            PaneOutcome::Detach => panic!("expected bytes, got a detach"),
        }
    }

    fn is_detach(outcome: PaneOutcome) -> bool {
        matches!(outcome, PaneOutcome::Detach)
    }

    #[test]
    fn an_ordinary_key_goes_straight_to_the_remote() {
        let mut pane = pane();
        let now = Instant::now();
        assert_eq!(sent(pane.handle_key(key(KeyCode::Char('l')), now)), Some(b"l".to_vec()));
        // The one that would be intercepted by a lesser design: an interrupt
        // is the remote's, not the app's.
        assert_eq!(sent(pane.handle_key(ctrl('c'), now)), Some(vec![0x03]));
    }

    #[test]
    fn the_prefix_swallows_itself_and_sends_on_a_double_press() {
        let mut pane = pane();
        let now = Instant::now();
        assert_eq!(sent(pane.handle_key(ctrl('b'), now)), None, "the prefix is never forwarded on its own");
        assert!(pane.prefix_armed());
        assert_eq!(sent(pane.handle_key(ctrl('b'), now)), Some(vec![PREFIX]));
        assert!(!pane.prefix_armed());
    }

    #[test]
    fn the_prefix_detaches_on_d() {
        let mut pane = pane();
        let now = Instant::now();
        pane.handle_key(ctrl('b'), now);
        assert!(is_detach(pane.handle_key(key(KeyCode::Char('d')), now)));
    }

    /// A prefix key is a command word. Forwarding an unrecognised one would
    /// run it at the remote's shell prompt.
    #[test]
    fn an_unknown_prefix_command_is_swallowed_rather_than_forwarded() {
        let mut pane = pane();
        let now = Instant::now();
        for c in ['q', 'x', 'j'] {
            pane.handle_key(ctrl('b'), now);
            assert_eq!(sent(pane.handle_key(key(KeyCode::Char(c)), now)), None, "Ctrl+B {c}");
            assert!(!pane.prefix_armed(), "and the prefix is spent either way");
        }
    }

    #[test]
    fn esc_cancels_the_prefix() {
        let mut pane = pane();
        let now = Instant::now();
        pane.handle_key(ctrl('b'), now);
        assert_eq!(sent(pane.handle_key(key(KeyCode::Esc), now)), None);
        assert!(!pane.prefix_armed());
    }

    /// A lone `Esc` still has to reach the remote, or the pane would be
    /// useless for vi — it is just late by up to the detach window.
    #[test]
    fn a_lone_escape_is_held_and_then_released() {
        let mut pane = pane();
        let now = Instant::now();
        assert_eq!(sent(pane.handle_key(key(KeyCode::Esc), now)), None);
        assert_eq!(sent(pane.tick(now + Duration::from_millis(100))), None, "still inside the window");
        assert_eq!(sent(pane.tick(now + Duration::from_millis(301))), Some(vec![0x1b]));
        assert_eq!(sent(pane.tick(now + Duration::from_millis(600))), None, "and only once");
    }

    /// The held byte goes out in front of what followed it, in one write, so
    /// `Esc :wq` arrives in the order it was typed.
    #[test]
    fn a_key_after_a_held_escape_flushes_it_first() {
        let mut pane = pane();
        let now = Instant::now();
        pane.handle_key(key(KeyCode::Esc), now);
        assert_eq!(sent(pane.handle_key(key(KeyCode::Char(':')), now + Duration::from_millis(50))), Some(vec![0x1b, b':']));
    }

    #[test]
    fn two_quick_escapes_detach() {
        let mut pane = pane();
        let now = Instant::now();
        pane.handle_key(key(KeyCode::Esc), now);
        assert!(is_detach(pane.handle_key(key(KeyCode::Esc), now + Duration::from_millis(120))));
    }

    #[test]
    fn two_slow_escapes_are_two_escapes() {
        let mut pane = pane();
        let now = Instant::now();
        pane.handle_key(key(KeyCode::Esc), now);
        let late = now + Duration::from_millis(400);
        assert_eq!(sent(pane.handle_key(key(KeyCode::Esc), late)), Some(vec![0x1b, 0x1b]));
    }

    /// Mashing `Esc` is the ordinary idiom in vim, less and htop, and a detach
    /// closes the session. So the hatch is off there — and `Esc` is not
    /// delayed either, which is where the delay would be most felt.
    #[test]
    fn the_escape_hatch_is_off_on_the_alternate_screen() {
        let mut pane = pane();
        pane.feed(b"\x1b[?1049h");
        assert!(pane.alt_screen());

        let now = Instant::now();
        assert_eq!(sent(pane.handle_key(key(KeyCode::Esc), now)), Some(vec![0x1b]), "sent at once, not held");
        assert_eq!(sent(pane.handle_key(key(KeyCode::Esc), now + Duration::from_millis(50))), Some(vec![0x1b]));

        // The documented detach still works from inside a full-screen program.
        pane.handle_key(ctrl('b'), now);
        assert!(is_detach(pane.handle_key(key(KeyCode::Char('d')), now)));
    }

    /// The reason `vt_input::encode` takes DECCKM as a parameter: the pane
    /// reads it off the live screen, so a program that turned it on gets the
    /// sequences it is waiting for.
    #[test]
    fn the_arrows_follow_what_the_remote_asked_for() {
        let mut pane = pane();
        let now = Instant::now();
        assert_eq!(sent(pane.handle_key(key(KeyCode::Up), now)), Some(b"\x1b[A".to_vec()));
        pane.feed(b"\x1b[?1h");
        assert_eq!(sent(pane.handle_key(key(KeyCode::Up), now)), Some(b"\x1bOA".to_vec()));
    }

    #[test]
    fn a_frame_with_no_room_for_a_shell_reports_none() {
        let footer = footer(false, false, &EN);
        assert!(viewport(Rect { x: 0, y: 0, width: 100, height: 30 }, &footer).is_some());
        assert!(viewport(Rect { x: 0, y: 0, width: 18, height: 30 }, &footer).is_none(), "too narrow");
        assert!(viewport(Rect { x: 0, y: 0, width: 100, height: 5 }, &footer).is_none(), "too short");
    }

    /// The test that stops the two arithmetics drifting. `viewport` sizes the
    /// remote PTY and `render` draws the result; if they disagree the remote
    /// wraps its own output somewhere the user cannot see or correct.
    #[test]
    fn the_reported_viewport_is_what_render_actually_draws_into() {
        let (width, height) = (80u16, 24u16);
        let area = Rect { x: 0, y: 0, width, height };
        let strings = &EN;
        let hint = footer(false, false, strings);
        let (cols, rows) = viewport(area, &hint).expect("80x24 has room");

        let mut pane = SessionPaneState::new("web-1".into(), cols, rows);
        // Exactly as wide as the pane says it is, on its last row: one column
        // more and the parser would have wrapped it onto a row that does not
        // exist.
        for _ in 0..rows.saturating_sub(1) {
            pane.feed(b"\r\n");
        }
        pane.feed(&vec![b'#'; cols as usize]);

        let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("test backend");
        terminal
            .draw(|frame| {
                // `render` draws the panel itself, so it takes the body rect
                // — the same one `viewport` measured the inside of.
                let body = crate::tui::chrome::render(frame, area, strings.session_pane_title_prefix, hint.clone(), strings);
                pane.render(frame, body, strings);
            })
            .expect("render");

        let buffer = terminal.backend().buffer();
        let full_rows = (0..height).filter(|y| (0..width).filter(|x| buffer[(*x, *y)].symbol() == "#").count() == cols as usize).count();
        assert_eq!(full_rows, 1, "the row fits on exactly one line of the pane");
    }

    #[test]
    fn the_pane_draws_the_remote_output_and_names_the_server() {
        let mut pane = SessionPaneState::new("web-1".into(), 56, 16);
        pane.feed(b"hello");
        let mut terminal = Terminal::new(TestBackend::new(60, 20)).expect("test backend");
        terminal.draw(|frame| pane.render(frame, frame.area(), &EN)).expect("render");
        let rendered: String = terminal.backend().buffer().content().iter().map(|c| c.symbol()).collect();
        assert!(rendered.contains("hello"));
        assert!(rendered.contains("web-1"));
    }

    /// Narrowing the pane truncates every line already on the grid, and
    /// widening it back does not restore them — `vt100` pads and truncates
    /// rather than reflowing. Pinned rather than fixed: the grid's width must
    /// equal the width the remote was told, or autowrap happens in the wrong
    /// column, so "only ever grow the grid" is not available. Replacing the
    /// backend with one that reflows is the real fix, and it should be a
    /// deliberate change rather than something this test starts passing by
    /// accident.
    #[test]
    fn narrowing_truncates_what_is_already_on_the_grid() {
        let mut pane = SessionPaneState::new("web-1".into(), 70, 10);
        pane.feed(b"Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.8.0-generic x86_64)");
        assert_eq!(pane.parser.screen().contents(), "Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.8.0-generic x86_64)");

        pane.resize(36, 10);
        assert_eq!(pane.parser.screen().contents(), "Welcome to Ubuntu 24.04.4 LTS (GNU/L");

        pane.resize(70, 10);
        assert_eq!(pane.parser.screen().contents(), "Welcome to Ubuntu 24.04.4 LTS (GNU/L", "widening cannot undo it");
    }

    /// Widening alone never loses anything, which is worth stating next to the
    /// test above: the damage needs a narrowing, not any resize at all.
    #[test]
    fn widening_keeps_everything_and_wraps_stay_wrapped() {
        let mut pane = SessionPaneState::new("web-1".into(), 36, 10);
        pane.feed(b"Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.8.0-generic x86_64)");
        pane.resize(70, 20);

        assert_eq!(pane.parser.screen().size(), (20, 70));
        let contents = pane.parser.screen().contents();
        assert!(contents.starts_with("Welcome to Ubuntu 24.04.4 LTS (GNU/L"));
        assert!(contents.contains("x86_64)"), "nothing is lost, it stays wrapped where it landed");
    }

    /// The app's own lines have to arrive as a terminal expects them: a bare
    /// line feed moves down without returning to column zero and stair-steps.
    #[test]
    fn an_app_line_returns_to_the_first_column() {
        let mut pane = pane();
        pane.feed_line("-L 8080 -> localhost:80");
        pane.feed_line("second");
        let contents = pane.parser.screen().contents();
        assert!(contents.starts_with("-L 8080 -> localhost:80\nsecond"), "got {contents:?}");
    }
}
