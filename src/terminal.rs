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
}

impl TerminalGuard {
    pub fn init() -> Result<Self> {
        let terminal = ratatui::try_init()?;
        Ok(Self { terminal })
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
    fn drop(&mut self) {
        ratatui::restore();
    }
}
