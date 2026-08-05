use russh::ChannelMsg;
use russh::client;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::signal::unix::{SignalKind, signal};

use super::client::Handler;
use crate::error::{AppError, Result};

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

    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut resize = signal(SignalKind::window_change()).map_err(AppError::Io)?;
    let mut buf = [0u8; 4096];
    // Once local stdin hits EOF it stays at EOF, returning 0 bytes instantly
    // forever. Disabling the branch after sending channel EOF keeps the
    // select loop from spinning on it while the remote shell drains.
    let mut stdin_open = true;

    loop {
        tokio::select! {
            n = stdin.read(&mut buf), if stdin_open => {
                let n = n.map_err(AppError::Io)?;
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
