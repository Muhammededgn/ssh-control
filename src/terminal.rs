use std::io::{self, Stdout};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crossterm::cursor::MoveTo;
use crossterm::execute;
use crossterm::terminal::{Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use tokio::signal::unix::{SignalKind, signal};

use crate::error::{AppError, Result};

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
    ///
    /// Shared rather than a plain `bool` because `Drop` is not the only
    /// teardown any more: the fatal-signal handler reads the same answer, and
    /// it runs on another task while this guard is still alive.
    primary_dirty: Arc<AtomicBool>,
}

impl TerminalGuard {
    pub fn init() -> Result<Self> {
        let terminal = ratatui::try_init()?;
        Ok(Self { terminal, primary_dirty: Arc::new(AtomicBool::new(false)) })
    }

    /// Routes `SIGTERM` and `SIGHUP` into the same teardown `Drop` performs,
    /// then re-raises so the exit status still reports the signal.
    ///
    /// Both are fatal by default, so the process dies without unwinding: no
    /// `Drop`, no atexit, and the terminal is left on the alternate screen in
    /// raw mode — `kill`, a closed window, a logout or a `systemctl stop` all
    /// left the user blind-typing `stty sane` (#63). Terminal modes live on the
    /// tty and outlive the process that set them, so nothing else cleans this
    /// up.
    ///
    /// The panic path is untouched and must stay that way: `ratatui::try_init`
    /// installs a hook that restores before the previous hook prints.
    ///
    /// Must be called from inside the runtime — registration goes through
    /// tokio's signal driver.
    pub fn restore_on_fatal_signal(&self) -> Result<()> {
        let mut term = signal(SignalKind::terminate()).map_err(AppError::Io)?;
        let mut hup = signal(SignalKind::hangup()).map_err(AppError::Io)?;
        let primary_dirty = Arc::clone(&self.primary_dirty);
        tokio::spawn(async move {
            let signum = tokio::select! {
                _ = term.recv() => libc::SIGTERM,
                _ = hup.recv() => libc::SIGHUP,
            };
            // Deliberately the same restore a suspended terminal gets: the
            // child owns the screen during a PTY session, but raw mode is this
            // process's doing and dies with it either way.
            restore(&primary_dirty);
            // SAFETY: `signal` and `raise` are the two calls this needs and
            // both are async-signal-safe. Putting the default disposition back
            // is what makes the re-raise fatal rather than a second trip
            // through tokio's handler, and by here the terminal is already
            // restored, so there is nothing left to unwind for.
            unsafe {
                libc::signal(signum, libc::SIG_DFL);
                libc::raise(signum);
            }
        });
        Ok(())
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
        self.primary_dirty.store(true, Ordering::SeqCst);
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
        if std::thread::panicking() {
            ratatui::restore();
            return;
        }
        restore(&self.primary_dirty);
    }
}

/// Leaves the alternate screen and, if a session was ever handed the primary
/// buffer, clears what it left there.
///
/// Free rather than a method because the signal handler has no guard to call
/// it on — and it is one function so the two teardowns cannot come to differ
/// about what restoring means. The order is load-bearing: `ratatui::restore()`
/// is what leaves the alternate screen, so clearing before it would wipe the
/// alternate buffer and leave the primary one untouched, the exact opposite of
/// the fix.
fn restore(primary_dirty: &AtomicBool) {
    ratatui::restore();
    if primary_dirty.load(Ordering::SeqCst) {
        let _ = execute!(io::stdout(), Clear(ClearType::All), MoveTo(0, 0));
    }
}
