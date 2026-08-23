use std::io::{self, Stdout};

use crossterm::cursor::MoveTo;
use crossterm::execute;
use crossterm::terminal::{Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

use crate::error::Result;

pub type Tui = Terminal<CrosstermBackend<Stdout>>;

/// Owns the terminal for the whole process lifetime. Raw mode is enabled once at
/// startup and never toggled off until final teardown (also on `Drop`/panic) — this
/// keeps Ctrl+C passthrough to the remote shell working correctly during SSH
/// sessions, since toggling raw mode on/off around each session would be a race.
pub struct TerminalGuard {
    pub terminal: Tui,
    /// Set the first time `suspend` hands the primary buffer over, and never
    /// cleared. It answers "does the primary screen still hold a remote
    /// session's tail?", which is the only reason `Drop` clears it — a run that
    /// never connected must leave the user's own shell exactly where it was.
    primary_dirty: bool,
}

impl TerminalGuard {
    pub fn init() -> Result<Self> {
        let terminal = ratatui::try_init()?;
        Ok(Self { terminal, primary_dirty: false })
    }

    /// Leave the alternate screen so a real interactive SSH session can take over
    /// the primary screen buffer, exactly like a normal `ssh` invocation would.
    ///
    /// The primary buffer still holds whatever was on screen before the app
    /// started — the user's own shell — so it is wiped and the cursor homed
    /// before handing over. `ClearType::All` only erases the visible screen;
    /// the terminal's scrollback is deliberately left alone (`Purge` would
    /// throw away history the app never owned).
    pub fn suspend(&mut self) -> Result<()> {
        execute!(io::stdout(), LeaveAlternateScreen, Clear(ClearType::All), MoveTo(0, 0))?;
        self.primary_dirty = true;
        Ok(())
    }

    /// Re-enter the alternate screen after an SSH session ends and force a full
    /// redraw, since the remote shell may have left arbitrary content on the
    /// primary screen buffer.
    pub fn resume(&mut self) -> Result<()> {
        execute!(io::stdout(), EnterAlternateScreen)?;
        self.terminal.clear()?;
        Ok(())
    }
}

impl Drop for TerminalGuard {
    /// `restore()` leaves the alternate screen, which uncovers the primary
    /// buffer — and after an SSH session that buffer holds the tail of the
    /// remote shell, with the user's own screen long gone. The clear therefore
    /// comes *after* `restore()`, never before, or it would wipe the alternate
    /// screen instead. `ClearType::All` again: the session stays reachable in
    /// scrollback, which is where the output of a `run_on_connect` script is.
    ///
    /// Skipped while unwinding. `ratatui::try_init` installs a panic hook that
    /// restores and *then* runs the previous hook, so by the time this drop
    /// runs the panic message is already printed on the primary buffer — the
    /// one thing clearing must not erase.
    ///
    /// Untested by design: this needs a real tty, and `suspend` writes escape
    /// codes to the stdout the test harness is printing to.
    fn drop(&mut self) {
        ratatui::restore();
        if self.primary_dirty && !std::thread::panicking() {
            let _ = execute!(io::stdout(), Clear(ClearType::All), MoveTo(0, 0));
        }
    }
}
