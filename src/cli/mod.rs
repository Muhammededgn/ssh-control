//! The command line.
//!
//! In the library rather than in `main.rs` because `main.rs` is a separate
//! crate and can only see `pub` API, while the headless unlock has to drive
//! `App`'s `pub(crate)` internals — see `cli::unlock` for why that reuse
//! matters.
//!
//! **Everything here is English, and adds no `Strings` fields.** `--help` and
//! `--version` already were, by the same reasoning: this surface is read by
//! shell scripts, packaging tooling and `cut` as much as by people, so it is
//! held stable rather than translated. The parts shared with the TUI — the
//! `run_on_connect` script printer, the disconnect message — still speak the
//! user's language, because those strings already exist in all four.

pub mod list;
pub mod unlock;

use std::io::IsTerminal;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::app::{App, AppState};
use crate::config::{ConfigStore, ServerEntry};
use crate::error::{AppError, Result};
use crate::i18n::Lang;
use crate::session;
use crate::ssh::{self, script_runner::ScriptVars};
use crate::terminal::TerminalGuard;

#[derive(Parser)]
#[command(
    name = "ssh-control",
    version,
    about = "Local, encrypted SSH connection manager with an interactive TUI",
    long_about = "Local, encrypted SSH connection manager.\n\nWith no subcommand it launches the interactive TUI, where servers, \
                  credentials, scripts and the security mode are configured. The subcommands exist so a vault built there is \
                  reachable from a shell alias or a script."
)]
struct Cli {
    /// Use the vault at this path instead of the default.
    ///
    /// Everything beside it moves too — the language and theme preferences,
    /// the credential-store id, the lock — because all of them are derived
    /// from the vault's own path.
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// List the servers in the vault. Never prints credentials.
    ///
    /// Columns when stdout is a terminal, tab-separated fields when it is
    /// piped, so `ssh-control list | cut -f2` gives user@host:port.
    List,
    /// Connect straight to a server, by the name it has in the vault.
    Connect {
        /// The server's name. Matched exactly, ignoring case.
        name: String,
    },
}

pub fn main() {
    let cli = Cli::parse();
    // `Display`, not `Debug`. Returning `Result` from `main` prints the `{:?}`
    // form, so every carefully worded `#[error(...)]` in `error.rs` — including
    // the one telling the user to install a newer build — would reach them as a
    // struct dump.
    if let Err(e) = dispatch(cli) {
        eprintln!("ssh-control: {e}");
        std::process::exit(1);
    }
}

fn dispatch(cli: Cli) -> Result<()> {
    let path = match cli.config {
        Some(path) => path,
        None => ConfigStore::resolve_default_path()?,
    };

    match cli.command {
        None => run_tui(path),
        Some(Command::List) => run_list(path),
        Some(Command::Connect { name }) => run_connect(path, &name),
    }
}

fn run_tui(path: PathBuf) -> Result<()> {
    // Checked here rather than inside the run loop so it reads as the usage
    // error it is, with no `AppError` variant prefix in front of it. Without
    // the check the failure surfaces from deep inside crossterm as
    // `Io(Os { code: 6 })`, which says nothing about what went wrong — and
    // anyone piping the output or starting this from a service manager lands
    // there. The subcommands are deliberately outside it: `list` in a pipe is
    // the whole point of `list`.
    if !std::io::stdout().is_terminal() || !std::io::stdin().is_terminal() {
        return Err(AppError::Cli(
            "the TUI needs a terminal on both stdin and stdout — try `ssh-control list` or `ssh-control connect <name>`".into(),
        ));
    }

    tokio_main(async move {
        let mut terminal = TerminalGuard::init()?;
        let mut app = App::new(ConfigStore::new(path));
        let result = app.run(&mut terminal).await;
        drop(terminal);
        result
    })
}

fn run_list(path: PathBuf) -> Result<()> {
    let mut app = App::new(ConfigStore::new(path));
    unlock::unlock(&mut app, &mut unlock::TerminalPrompt)?;

    let AppState::Unlocked(u) = &app.state else {
        // `unlock` returns `Ok` only once the vault is open and past any second
        // factor, so this is unreachable rather than a case to handle.
        return Err(AppError::Cli("the vault did not open".into()));
    };
    print!("{}", list::render(&u.config.servers, u.config.server_sort, std::io::stdout().is_terminal()));
    Ok(())
}

/// The one server `name` refers to.
///
/// Case-insensitive, and exact — no prefix matching. A prefix that grew
/// ambiguous when a server was added would silently start connecting somewhere
/// else, which is the one failure mode not worth the keystrokes. More than one
/// match is reported rather than resolved, for the same reason.
fn resolve<'a>(servers: &'a [ServerEntry], name: &str) -> Result<&'a ServerEntry> {
    let needle = name.to_lowercase();
    let matches: Vec<&ServerEntry> = servers.iter().filter(|s| s.name.to_lowercase() == needle).collect();
    match matches.as_slice() {
        [one] => Ok(one),
        [] => Err(AppError::Cli(format!("no server named '{name}' — `ssh-control list` shows them"))),
        many => {
            let names: Vec<&str> = many.iter().map(|s| s.name.as_str()).collect();
            Err(AppError::Cli(format!("'{name}' matches more than one server: {}", names.join(", "))))
        }
    }
}

fn run_connect(path: PathBuf, name: &str) -> Result<()> {
    if !std::io::stdin().is_terminal() {
        return Err(AppError::Cli("connect needs a terminal on stdin — it hands it to a remote shell".into()));
    }

    let store = ConfigStore::new(path);
    let strings = Lang::load_from_file(&store.prefs_path()).strings();
    let mut app = App::new(store);
    unlock::unlock(&mut app, &mut unlock::TerminalPrompt)?;

    // Built while the entry is still borrowed, exactly as `connect_flow` does:
    // what crosses the await owns its credential and its already-expanded
    // commands, never the whole entry.
    let AppState::Unlocked(u) = &app.state else {
        return Err(AppError::Cli("the vault did not open".into()));
    };
    let entry = resolve(&u.config.servers, name)?;
    let id = entry.id;
    let target = ssh::Target::from_entry(entry);
    let vars = ScriptVars::from_entry(entry);
    let on_connect: Vec<_> = entry.scripts.iter().filter(|s| s.run_on_connect).map(|s| vars.expand_script(s)).collect();

    tokio_main(async move {
        // `run_interactive` assumes raw mode — Ctrl+C has to arrive at the
        // remote shell as a plain 0x03 byte rather than raising SIGINT here.
        // The TUI gets that from `TerminalGuard`; with no guard in the way this
        // path has to enable it, and restore it however the scope is left.
        let _raw = unlock::RawMode::enable()?;

        let mut connected = ssh::connect(&target).await?;

        // The same three beats as the TUI's connect, through the same policy
        // (`crate::session`), so a CLI connect records what a TUI one would:
        // the host key on a first connect, the timestamp, the sysinfo probe.
        let record = session::observe(&connected).await;
        if let AppState::Unlocked(u) = &mut app.state {
            if let Some(e) = u.config.servers.iter_mut().find(|s| s.id == id) {
                record.apply_to(e);
            }
            // Best-effort, like the TUI's: a read-only config directory must
            // not stand between the user and the shell they asked for.
            let _ = app.store.save(&u.config, &u.master_key, &u.slots);
        }

        for script in &on_connect {
            let mut partial = String::new();
            script_runner_run(&mut connected.handle, script, strings, &mut partial).await;
        }

        ssh::pty_bridge::run_interactive(&connected.handle).await
    })
}

async fn script_runner_run(
    handle: &mut russh::client::Handle<ssh::client::Handler>,
    script: &crate::config::Script,
    strings: &'static crate::i18n::Strings,
    partial: &mut String,
) {
    crate::ssh::script_runner::run_script(handle, script, |event| {
        session::print_script_event_plain(event, strings, partial);
    })
    .await;
}

/// One place that builds the runtime, so `main` stays sync and the three
/// commands do not each grow a `#[tokio::main]` of their own.
fn tokio_main<F: std::future::Future<Output = Result<()>>>(future: F) -> Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(AppError::Io)?
        .block_on(future)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuthMethod;
    use clap::CommandFactory;

    fn entry(name: &str) -> ServerEntry {
        ServerEntry::new(name.into(), format!("{name}.example.com"), 22, "root".into(), AuthMethod::password("x"))
    }

    /// clap's own consistency check — duplicate flags, a bad `long_about`, an
    /// argument that can never be reached.
    #[test]
    fn the_command_definition_is_well_formed() {
        Cli::command().debug_assert();
    }

    /// The acceptance criterion: adding subcommands must not change what
    /// happens when there are none.
    #[test]
    fn no_arguments_still_means_the_tui() {
        let cli = Cli::try_parse_from(["ssh-control"]).expect("no arguments is valid");
        assert!(cli.command.is_none());
        assert!(cli.config.is_none());
    }

    #[test]
    fn the_subcommands_parse() {
        assert!(matches!(Cli::try_parse_from(["ssh-control", "list"]).unwrap().command, Some(Command::List)));

        let cli = Cli::try_parse_from(["ssh-control", "connect", "web-1"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Connect { name }) if name == "web-1"));
    }

    /// `global = true` is what lets `--config` sit on either side of the
    /// subcommand; without it only one of these two parses.
    #[test]
    fn config_is_accepted_before_and_after_the_subcommand() {
        for args in [["ssh-control", "--config", "/tmp/v.enc", "list"], ["ssh-control", "list", "--config", "/tmp/v.enc"]] {
            let cli = Cli::try_parse_from(args).expect("--config is global");
            assert_eq!(cli.config.as_deref(), Some(std::path::Path::new("/tmp/v.enc")));
        }
    }

    #[test]
    fn a_typo_is_rejected_rather_than_treated_as_a_server_name() {
        assert!(Cli::try_parse_from(["ssh-control", "conect", "web-1"]).is_err());
        assert!(Cli::try_parse_from(["ssh-control", "connect"]).is_err(), "connect needs a name");
    }

    #[test]
    fn a_name_resolves_whatever_case_it_is_typed_in() {
        let servers = vec![entry("web-1"), entry("DB-1")];
        assert_eq!(resolve(&servers, "WEB-1").unwrap().name, "web-1");
        assert_eq!(resolve(&servers, "db-1").unwrap().name, "DB-1");
    }

    #[test]
    fn an_unknown_name_says_so_and_points_at_list() {
        let servers = vec![entry("web-1")];
        let error = resolve(&servers, "web-2").expect_err("there is no web-2").to_string();
        assert!(error.contains("web-2"));
        assert!(error.contains("list"));
    }

    /// Two entries that differ only by case would otherwise be resolved
    /// arbitrarily by whichever came first — connecting somewhere the user did
    /// not mean is worse than refusing.
    #[test]
    fn an_ambiguous_name_is_refused_rather_than_guessed() {
        let servers = vec![entry("web"), entry("WEB")];
        let error = resolve(&servers, "web").expect_err("ambiguous").to_string();
        assert!(error.contains("more than one"));
        assert!(error.contains("web") && error.contains("WEB"), "it should list them: {error}");
    }

    /// Exact, never prefix: a prefix that grew ambiguous when a server was
    /// added would silently start connecting somewhere else.
    #[test]
    fn a_prefix_is_not_a_match() {
        let servers = vec![entry("web-1")];
        assert!(resolve(&servers, "web").is_err());
    }
}
