use std::io::{self, Stdout};

use crossterm::execute;
use crossterm::terminal::{EnterAlternateScreen, LeaveAlternateScreen};
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
    pub fn suspend(&mut self) -> Result<()> {
        execute!(io::stdout(), LeaveAlternateScreen)?;
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
