//! Opening the vault with no TUI.
//!
//! **This drives the real `App` rather than reaching for `ConfigStore`.** Which
//! screen a vault belongs on, the TOTP failure counter, the periodic password
//! check, `reconcile_device_state`, the vault `flock` and the refusal to touch
//! a leftover TOTP-only vault are all decisions `App` already makes, and a
//! second implementation of them here would be a second implementation to get
//! wrong. All this module adds is a way to answer the questions on a plain
//! terminal instead of in a form.

use std::io::{BufRead, IsTerminal, Write};

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use zeroize::Zeroizing;

use crate::app::{App, AppState, Screen};
use crate::error::{AppError, Result};
use crate::tui::unlock::UnlockMode;

/// How many times a wrong password is re-asked before giving up. Bounded so a
/// piped or otherwise non-interactive invocation cannot spin forever.
const MAX_TRIES: usize = 3;

/// Where the answers come from. A trait, not a function, so the tests can hand
/// the loop a script instead of a keyboard.
pub trait Prompt {
    /// Reads one secret with echo off. `Ok(None)` means the user cancelled.
    fn secret(&mut self, label: &str) -> Result<Option<Zeroizing<String>>>;
}

/// Restores cooked mode however the scope is left, including on an error or a
/// panic — the same reasoning as `ssh::pty_bridge::NonBlockingStdin`. Leaving
/// the terminal raw would follow the user back out to their shell.
pub struct RawMode;

impl RawMode {
    pub fn enable() -> Result<Self> {
        crossterm::terminal::enable_raw_mode().map_err(AppError::Io)?;
        Ok(Self)
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        let _ = crossterm::terminal::disable_raw_mode();
    }
}

/// Reads secrets from the terminal, echoing nothing.
///
/// With no terminal on stdin it reads a line from stdin instead. That is what
/// makes `ssh-control list < password-file` work from cron or a script — and
/// without it the crossterm read fails with `os error 6`, which is exactly the
/// unreadable failure the TUI's own tty check exists to prevent. The prompt is
/// still written, since something reading a pipe cannot be surprised by it and
/// a half-interactive run is helped by it.
pub struct TerminalPrompt;

impl Prompt for TerminalPrompt {
    fn secret(&mut self, label: &str) -> Result<Option<Zeroizing<String>>> {
        let mut out = std::io::stderr();
        // stderr, so `ssh-control list > file` still shows the prompt and the
        // file still gets only the list.
        let _ = write!(out, "{label}: ");
        let _ = out.flush();

        if !std::io::stdin().is_terminal() {
            // Straight into the `Zeroizing` buffer — a plain `String` read
            // first would leave a copy of the password behind on the heap.
            let mut line = Zeroizing::new(String::new());
            let read = std::io::stdin().lock().read_line(&mut line).map_err(AppError::Io)?;
            let _ = writeln!(out);
            if read == 0 {
                return Ok(None);
            }
            while line.ends_with('\n') || line.ends_with('\r') {
                line.pop();
            }
            return Ok(Some(line));
        }

        let _raw = RawMode::enable()?;
        let mut buffer = Zeroizing::new(String::new());
        loop {
            let Event::Key(key) = event::read().map_err(AppError::Io)? else {
                continue;
            };
            if key.kind != KeyEventKind::Press {
                continue;
            }
            match key.code {
                KeyCode::Enter => break,
                KeyCode::Esc => return Ok(None),
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return Ok(None),
                KeyCode::Backspace => {
                    buffer.pop();
                }
                KeyCode::Char(c) => buffer.push(c),
                _ => {}
            }
        }
        drop(_raw);
        let _ = writeln!(out);
        Ok(Some(buffer))
    }
}

/// Opens `app`'s vault, asking `prompt` for whatever it needs.
///
/// Returns once `app.state` is `Unlocked` and past any second factor. The
/// states with no terminal answer — a vault that does not exist yet, one left
/// over from the TOTP-only mode, one this machine cannot open — are refused
/// with a message rather than prompted for: both wizards are multi-step and
/// have QR codes in them, and half a vault is the one outcome worth refusing.
pub fn unlock(app: &mut App, prompt: &mut dyn Prompt) -> Result<()> {
    let mut tries = 0;
    loop {
        match &app.state {
            AppState::Unlocked(u) => {
                // Mode 3 puts the code *after* the password, so the vault can
                // be open and the server list still out of reach.
                if !matches!(u.screen, Screen::TotpPrompt(_)) {
                    return Ok(());
                }
                let Some(code) = prompt.secret("Authenticator code")? else {
                    return Err(cancelled());
                };
                app.verify_totp_prompt(code.trim());
                if matches!(&app.state, AppState::Unlocked(u) if matches!(u.screen, Screen::TotpPrompt(_))) {
                    tries += 1;
                    if tries >= MAX_TRIES {
                        return Err(AppError::Cli("too many incorrect codes".into()));
                    }
                    eprintln!("ssh-control: incorrect code");
                }
            }
            AppState::Locked(unlock) if unlock.mode == UnlockMode::MigrateTotpOnly => {
                return Err(AppError::Cli(
                    "this vault still uses the old TOTP-only mode and has to be converted first — \
                     run ssh-control with no arguments"
                        .into(),
                ));
            }
            AppState::Locked(_) => {
                let Some(password) = prompt.secret("Password")? else {
                    return Err(cancelled());
                };
                app.try_unlock(&password, false);
                if let AppState::Locked(unlock) = &app.state
                    && let Some(error) = &unlock.error
                {
                    tries += 1;
                    if tries >= MAX_TRIES {
                        return Err(AppError::Cli(error.clone()));
                    }
                    eprintln!("ssh-control: {error}");
                }
            }
            AppState::LockedTotpDaily(_) => {
                let Some(code) = prompt.secret("Authenticator code")? else {
                    return Err(cancelled());
                };
                app.try_totp_daily_unlock(code.trim());
                // A wrong code either sets an error here or escalates to the
                // password screen on its own; either way the loop follows the
                // state rather than second-guessing it.
                if let AppState::LockedTotpDaily(totp) = &app.state
                    && let Some(error) = &totp.error
                {
                    tries += 1;
                    if tries >= MAX_TRIES {
                        return Err(AppError::Cli(error.clone()));
                    }
                    eprintln!("ssh-control: {error}");
                }
            }
            AppState::Setup(_) => {
                return Err(AppError::Cli(
                    "no vault here yet — run ssh-control with no arguments to create one".into(),
                ));
            }
            AppState::Unopenable => {
                return Err(AppError::Cli(
                    "this vault's device key is not on this machine, and it has no recovery password".into(),
                ));
            }
            AppState::CannotOpen { message, .. } => return Err(AppError::Cli((*message).to_string())),
        }
    }
}

fn cancelled() -> AppError {
    AppError::Cli("cancelled".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, ConfigStore};

    /// Answers straight from a list, so the unlock loop can be driven with no
    /// terminal at all.
    struct Scripted {
        answers: Vec<Option<&'static str>>,
        asked: Vec<String>,
    }

    impl Prompt for Scripted {
        fn secret(&mut self, label: &str) -> Result<Option<Zeroizing<String>>> {
            self.asked.push(label.to_string());
            if self.answers.is_empty() {
                panic!("the loop asked more questions than the test scripted: {:?}", self.asked);
            }
            Ok(self.answers.remove(0).map(|a| Zeroizing::new(a.to_string())))
        }
    }

    const PASSWORD: &str = "correct horse battery";

    /// Password-only, for the same reason `app::tests` uses it: a vault with a
    /// device slot would read the developer's real OS credential store.
    fn password_vault(f: impl FnOnce(&mut Config)) -> (tempfile::TempDir, App) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.enc");
        {
            let store = ConfigStore::new(path.clone());
            let mut unlocked = store.init(PASSWORD).expect("init");
            f(&mut unlocked.config);
            store.save(&unlocked.config, &unlocked.master_key, &unlocked.slots).expect("save");
        }
        (dir, App::new(ConfigStore::new(path)))
    }

    #[test]
    fn the_right_password_opens_the_vault() {
        let (_dir, mut app) = password_vault(|_| {});
        let mut prompt = Scripted { answers: vec![Some(PASSWORD)], asked: Vec::new() };

        unlock(&mut app, &mut prompt).expect("the vault should open");
        assert!(matches!(app.state, AppState::Unlocked(_)));
        assert_eq!(prompt.asked, vec!["Password"]);
    }

    #[test]
    fn a_wrong_password_is_re_asked_and_then_gives_up() {
        let (_dir, mut app) = password_vault(|_| {});
        let mut prompt = Scripted { answers: vec![Some("nope"), Some("still nope"), Some("nope again")], asked: Vec::new() };

        assert!(unlock(&mut app, &mut prompt).is_err());
        assert_eq!(prompt.asked.len(), MAX_TRIES, "it must stop rather than loop forever");
        assert!(!matches!(app.state, AppState::Unlocked(_)));
    }

    #[test]
    fn a_second_try_after_a_typo_still_works() {
        let (_dir, mut app) = password_vault(|_| {});
        let mut prompt = Scripted { answers: vec![Some("nope"), Some(PASSWORD)], asked: Vec::new() };

        unlock(&mut app, &mut prompt).expect("the second answer is right");
        assert!(matches!(app.state, AppState::Unlocked(_)));
    }

    #[test]
    fn cancelling_the_prompt_is_an_error_not_an_open_vault() {
        let (_dir, mut app) = password_vault(|_| {});
        let mut prompt = Scripted { answers: vec![None], asked: Vec::new() };

        assert!(unlock(&mut app, &mut prompt).is_err());
        assert!(!matches!(app.state, AppState::Unlocked(_)));
    }

    /// Creating a vault is a multi-step wizard with a QR code in it. The CLI
    /// says so instead of asking for a password that would build half of one.
    #[test]
    fn a_missing_vault_is_refused_without_asking_anything() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut app = App::new(ConfigStore::new(dir.path().join("config.enc")));
        let mut prompt = Scripted { answers: Vec::new(), asked: Vec::new() };

        let error = unlock(&mut app, &mut prompt).expect_err("there is nothing to open");
        assert!(error.to_string().contains("no vault here yet"));
        assert!(prompt.asked.is_empty(), "nothing should have been asked");
    }
}
