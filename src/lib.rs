//! ssh-control is unix-only.
//!
//! Not a temporary limitation: `ssh::pty_bridge` is built on `AsyncFd` and
//! `SIGWINCH` from `tokio::signal::unix`, and the packaging is deb/rpm/Arch.
//! Rather than fail deep inside tokio with an error that says nothing about
//! why, say so here. See issue #22 for what supporting Windows would take.
#[cfg(not(unix))]
compile_error!(
    "ssh-control only builds on unix (Linux, macOS, BSD). \
     The PTY bridge depends on unix signals and non-blocking fds."
);

pub mod app;
pub mod config;
pub mod crypto;
pub mod error;
pub mod i18n;
pub mod ssh;
pub mod terminal;
pub mod totp;
pub mod tui;
