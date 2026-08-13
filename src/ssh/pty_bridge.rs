use std::os::fd::AsFd;

use russh::ChannelMsg;
use russh::client;
use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
use tokio::io::AsyncWriteExt;
use tokio::io::unix::AsyncFd;
use tokio::signal::unix::{SignalKind, signal};

use super::client::Handler;
use crate::error::{AppError, Result};

/// Puts stdin into non-blocking mode for the life of the bridge, restoring the
/// original flags on the way out — including on an error path, hence `Drop`.
///
/// This is what makes it safe to read stdin here at all. `tokio::io::stdin()`
/// does its reads on a blocking thread and **a blocking read cannot be
/// cancelled**: when the remote shell exits, the loop below breaks while a read
/// is still parked in `read(0, …)`, and that orphaned thread outlives the
/// session. It then steals the next thing written to stdin — including the
/// terminal's reply to the `ESC[6n` cursor-position query that
/// `Terminal::clear` issues from `TerminalGuard::resume`, which times out and
/// takes the whole app down with it. With `O_NONBLOCK` plus `AsyncFd` no read
/// is ever parked, so nothing survives the session to eat that reply.
struct NonBlockingStdin {
    original: OFlags,
}

impl NonBlockingStdin {
    fn enable() -> Result<Self> {
        let stdin = std::io::stdin();
        let original = fcntl_getfl(stdin.as_fd()).map_err(|e| AppError::Io(e.into()))?;
        fcntl_setfl(stdin.as_fd(), original | OFlags::NONBLOCK).map_err(|e| AppError::Io(e.into()))?;
        Ok(Self { original })
    }
}

impl Drop for NonBlockingStdin {
    fn drop(&mut self) {
        // Best-effort: the flags belong to the open file description, which is
        // shared with whatever launched us, so leaving stdin non-blocking would
        // follow the user back out to their shell.
        let _ = fcntl_setfl(std::io::stdin().as_fd(), self.original);
    }
}

/// Opens a PTY + shell on `handle` and bridges it with the local terminal's
/// stdin/stdout until the remote shell exits. Byte-for-byte passthrough only —
/// never routed through `String`/UTF-8 conversion, so box-drawing/ANSI-heavy
/// output from tools like vim/htop isn't corrupted. Ctrl+C is not intercepted:
/// raw mode already disables `ISIG`, so it arrives as a plain `0x03` byte and
/// is forwarded to the remote shell like any real ssh client would.
pub async fn run_interactive(handle: &mut client::Handle<Handler>) -> Result<()> {
    let mut channel = handle.channel_open_session().await?;

    let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));
    let term = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".into());

    channel
        .request_pty(false, &term, cols as u32, rows as u32, 0, 0, &[])
        .await?;
    channel.request_shell(false).await?;

    let _stdin_mode = NonBlockingStdin::enable()?;
    // A dup of fd 0, so dropping the `AsyncFd` deregisters it from the reactor
    // without closing the real stdin the TUI goes back to using.
    let stdin_dup = std::io::stdin().as_fd().try_clone_to_owned().map_err(AppError::Io)?;
    let stdin = AsyncFd::new(stdin_dup).map_err(AppError::Io)?;
    let mut stdout = tokio::io::stdout();
    let mut resize = signal(SignalKind::window_change()).map_err(AppError::Io)?;
    let mut buf = [0u8; 4096];
    // Once local stdin hits EOF it stays at EOF, returning 0 bytes instantly
    // forever. Disabling the branch after sending channel EOF keeps the
    // select loop from spinning on it while the remote shell drains.
    let mut stdin_open = true;

    loop {
        tokio::select! {
            readable = stdin.readable(), if stdin_open => {
                let mut guard = readable.map_err(AppError::Io)?;
                // `Err` here is `WouldBlock`: the readiness was spurious and
                // the guard has already cleared it, so just go round again.
                let Ok(read) = guard.try_io(|fd| rustix::io::read(fd.get_ref(), &mut buf).map_err(std::io::Error::from)) else {
                    continue;
                };
                let n = read.map_err(AppError::Io)?;
                if n == 0 {
                    stdin_open = false;
                    channel.eof().await?;
                    continue;
                }
                channel.data(&buf[..n]).await?;
            }
            msg = channel.wait() => {
                match msg {
                    Some(ChannelMsg::Data { data }) => {
                        stdout.write_all(&data).await.map_err(AppError::Io)?;
                        stdout.flush().await.map_err(AppError::Io)?;
                    }
                    Some(ChannelMsg::ExtendedData { data, .. }) => {
                        stdout.write_all(&data).await.map_err(AppError::Io)?;
                        stdout.flush().await.map_err(AppError::Io)?;
                    }
                    Some(ChannelMsg::ExitStatus { .. }) | Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => {
                        break;
                    }
                    _ => {}
                }
            }
            _ = resize.recv() => {
                if let Ok((cols, rows)) = crossterm::terminal::size() {
                    let _ = channel.window_change(cols as u32, rows as u32, 0, 0).await;
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The flags belong to the open file description, which outlives this
    /// process — leaving stdin non-blocking would follow the user out to their
    /// shell, so the `Drop` restore is not optional.
    #[test]
    fn stdin_flags_are_restored_on_drop() {
        let before = fcntl_getfl(std::io::stdin().as_fd()).expect("stdin should accept fcntl");
        {
            let _guard = NonBlockingStdin::enable().expect("enabling non-blocking stdin should work");
            let during = fcntl_getfl(std::io::stdin().as_fd()).unwrap();
            assert!(during.contains(OFlags::NONBLOCK));
        }
        assert_eq!(fcntl_getfl(std::io::stdin().as_fd()).unwrap(), before);
    }
}
