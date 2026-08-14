use std::io::IsTerminal;

use ssh_control::app::App;
use ssh_control::config::ConfigStore;
use ssh_control::error::Result;
use ssh_control::terminal::TerminalGuard;

const USAGE: &str = "\
ssh-control — local, encrypted SSH connection manager with an interactive TUI

Usage:
  ssh-control            Launch the TUI
  ssh-control --help     Show this message
  ssh-control --version  Show the version

The TUI needs a terminal; there is no non-interactive mode yet.
Everything else — servers, credentials, scripts, the security mode — is
configured from inside the app.
";

/// Deliberately hand-rolled rather than pulled from a CLI crate: this is two
/// flags handled before anything else starts, and the app has no subcommands
/// yet (see issue #11, which is where a real parser belongs).
///
/// Kept in English on purpose. `--version` and `--help` are shell conventions
/// read by packaging tooling and scripts as much as by people, and the language
/// preference lives in the config directory this runs before touching.
enum Invocation {
    Tui,
    /// Printed and exited from immediately, with the given exit code.
    Print(String, i32),
}

fn parse_args() -> Invocation {
    let mut args = std::env::args().skip(1);
    let Some(first) = args.next() else {
        return Invocation::Tui;
    };

    match first.as_str() {
        "-h" | "--help" => Invocation::Print(USAGE.to_string(), 0),
        "-V" | "--version" => {
            Invocation::Print(format!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")), 0)
        }
        other => Invocation::Print(
            format!("ssh-control: unrecognized argument '{other}'\n\n{USAGE}"),
            2,
        ),
    }
}

fn main() {
    match parse_args() {
        Invocation::Print(message, 0) => {
            println!("{message}");
            return;
        }
        Invocation::Print(message, code) => {
            eprintln!("{message}");
            std::process::exit(code);
        }
        Invocation::Tui => {}
    }

    // Checked here rather than inside `run` so it reads as the usage error it
    // is, with no `AppError` variant prefix in front of it. Without the check
    // the failure surfaces from deep inside crossterm as
    // `Io(Os { code: 6 })`, which says nothing about what went wrong — and
    // anyone piping the output or starting this from a service manager lands
    // there.
    if !std::io::stdout().is_terminal() || !std::io::stdin().is_terminal() {
        eprintln!("ssh-control: needs a terminal on both stdin and stdout — this is an interactive TUI");
        std::process::exit(1);
    }

    // `Display`, not `Debug`. Returning `Result` from `main` would print the
    // `{:?}` form, so every carefully worded `#[error(...)]` in `error.rs` —
    // including the one telling the user to install a newer build — would reach
    // them as a struct dump.
    if let Err(e) = run() {
        eprintln!("ssh-control: {e}");
        std::process::exit(1);
    }
}

#[tokio::main]
async fn run() -> Result<()> {
    let path = ConfigStore::resolve_default_path()?;
    let store = ConfigStore::new(path);

    let mut terminal = TerminalGuard::init()?;
    let mut app = App::new(store);
    let result = app.run(&mut terminal).await;
    drop(terminal);

    result
}
