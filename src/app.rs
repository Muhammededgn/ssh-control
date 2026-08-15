use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyEvent, KeyEventKind};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::config::device::{self, DeviceState};
use crate::config::format::{SLOT_DEVICE, SLOT_PASSWORD, Slot};
use crate::config::keyslot::{self, MasterKey};
use crate::config::store::{ConfigStore, Unlocked, VaultShape};
use crate::config::{Config, Script, Secret, ServerEntry, TotpConfig};
use crate::crypto::kdf::KdfParams;
use crate::error::{AppError, Result};
use crate::i18n::{Lang, Strings};
use crate::ssh;
use crate::ssh::script_runner::{self, RunEvent};
use crate::terminal::TerminalGuard;
use crate::totp::{self, AuthMode};
use crate::tui::confirm::{ConfirmOutcome, ConfirmState};
use crate::tui::main_menu::{MainMenuAction, MainMenuState};
use crate::tui::script_form::{FormMode as ScriptFormMode, ScriptFormData, ScriptFormOutcome, ScriptFormState};
use crate::tui::script_run::{ScriptRunOutcome, ScriptRunState};
use crate::tui::scripts_list::{ScriptsListAction, ScriptsListState};
use crate::tui::server_form::{FormMode, FormOutcome, ServerFormData, ServerFormState};
use crate::tui::settings::{SettingsOutcome, SettingsState};
use crate::tui::setup::{SetupOutcome, SetupState};
use crate::tui::totp_prompt::{TotpPromptOutcome, TotpPromptState};
use crate::tui::help::{self, HelpTopic};
use crate::tui::totp_unlock::{TotpUnlockOutcome, TotpUnlockState};
use crate::tui::unlock::{UnlockMode, UnlockOutcome, UnlockState};

enum Screen {
    MainMenu(MainMenuState),
    ServerForm(ServerFormState),
    ConfirmDelete { target: Uuid, state: ConfirmState },
    Settings(SettingsState),
    /// Second-factor prompt shown after a successful password unlock, only
    /// when the vault has "Password + TOTP (2FA)" enabled.
    TotpPrompt(TotpPromptState),
    Scripts(ScriptsListState),
    ScriptForm(ScriptFormState),
    ConfirmDeleteScript { server_id: Uuid, script_id: Uuid, state: ConfirmState },
    ScriptRun(ScriptRunState),
}

/// Which set of keys the help overlay lists, for the screen currently on top.
///
/// The step editor is part of `ScriptForm` as far as `Screen` is concerned, and
/// that topic lists both its hint and the step list's, so it needs no case of
/// its own here.
fn help_topic(screen: &Screen) -> HelpTopic {
    match screen {
        Screen::MainMenu(_) => HelpTopic::ServerList,
        Screen::ServerForm(_) => HelpTopic::ServerForm,
        Screen::ConfirmDelete { .. } | Screen::ConfirmDeleteScript { .. } => HelpTopic::Confirm,
        Screen::Settings(_) => HelpTopic::Settings,
        Screen::TotpPrompt(_) => HelpTopic::TotpPrompt,
        Screen::Scripts(_) => HelpTopic::ScriptList,
        Screen::ScriptForm(_) => HelpTopic::ScriptForm,
        Screen::ScriptRun(_) => HelpTopic::ScriptRun,
    }
}

/// A transient footer message ("Saved.", "Deleted."), with the moment it was
/// shown so the run loop can take it away again.
///
/// Without the timestamp a message sits there until the screen changes, so a
/// "Saved." from ten minutes ago still reads as if it describes whatever the
/// user is looking at now.
struct StatusMessage {
    text: String,
    shown_at: Instant,
}

impl StatusMessage {
    fn new(text: String) -> Self {
        Self { text, shown_at: Instant::now() }
    }
}

struct UnlockedState {
    config: Config,
    master_key: MasterKey,
    slots: Vec<Slot>,
    screen: Screen,
    status: Option<StatusMessage>,
    /// The keybinding overlay. Modal while it is up: it takes the next key to
    /// dismiss itself and hands nothing through to the screen underneath, so a
    /// key pressed to close it can never also act on the list behind it.
    help_open: bool,
}

enum AppState {
    /// First run: choose a security mode and set it up.
    Setup(SetupState),
    /// Password prompt. Also where every escalation out of `LockedTotpDaily`
    /// lands, so a copied vault, a burnt-out attempt counter and a replayed
    /// code all converge on the same screen.
    Locked(UnlockState),
    /// The everyday screen of `AuthMode::TotpDaily`: a code, checked against
    /// device-bound state, opens the device slot.
    LockedTotpDaily(TotpUnlockState),
    /// A vault whose only slot is a device slot this machine cannot supply —
    /// mode 1 carried somewhere else. There is deliberately no prompt here:
    /// nothing the user could type would help, and offering a box that can
    /// never succeed is worse than saying so.
    Unopenable,
    /// A vault this instance cannot open right now, where there is nothing
    /// useful to prompt for — reached from mode 1, which opens without asking,
    /// so there is no password box to put an error on.
    ///
    /// Carries its own text because the reasons are not interchangeable and
    /// `Unopenable` is none of them: that one is permanent and says the vault
    /// cannot be opened on *this machine*, while these clear by closing another
    /// window or installing a newer build. Showing the wrong one sends the user
    /// looking for a recovery password they do not need.
    CannotOpen { title: &'static str, message: &'static str },
    /// Boxed so the enum isn't sized by its largest variant — the locked
    /// variants are tiny and this one carries the whole decrypted config.
    Unlocked(Box<UnlockedState>),
}

/// Actions resolved from a key event before any `.await` point, so no borrow
/// of `self.state` needs to be held across the async `connect_flow`.
enum NextStep {
    None,
    /// `?` from a screen where it cannot be mistaken for text input.
    Help,
    Connect(Uuid),
    GoAdd,
    GoEdit(Uuid),
    GoDelete(Uuid),
    GoSettings,
    Lock,
    Quit,
    FormSubmit(ServerFormData),
    FormCancel,
    ConfirmYes,
    ConfirmNo,
    SettingsClose,
    SettingsLangSelected(Lang),
    SettingsAutoLockSelected(u32),
    SettingsChangePassword { current: Zeroizing<String>, new: Zeroizing<String> },
    ChangeSecurityMode { mode: AuthMode, password: Option<Zeroizing<String>>, totp_secret: Option<Zeroizing<String>> },
    TotpPromptSubmit(String),
    TotpPromptCancel,
    GoScripts(Uuid),
    ScriptsBack,
    GoScriptAdd,
    GoScriptEdit(Uuid),
    GoScriptDeleteConfirm(Uuid),
    ScriptFormCancel,
    ScriptFormSave(ScriptFormData),
    ConfirmDeleteScriptYes,
    ConfirmDeleteScriptNo,
    RunScript(Uuid, Uuid),
    ScriptRunClose,
}

pub struct App {
    store: ConfigStore,
    state: AppState,
    lang: Lang,
    should_quit: bool,
    /// When the last key was pressed, for the idle auto-lock. Also re-stamped
    /// after every `handle_key`, so time spent inside an SSH session or a
    /// script run does not count as idle.
    last_activity: Instant,
}

/// How many wrong codes in a row before the everyday TOTP path is refused and
/// the password is demanded instead.
const MAX_TOTP_FAILURES: u32 = 5;
/// How long a vault may go without seeing its password before asking for it
/// again. Guards against the user quietly forgetting the one credential that
/// can recover the vault from another machine.
const PASSWORD_CHECK_DAYS: u32 = 30;
/// How long a footer status message stays up. Long enough to read, short enough
/// that it is gone before the user could mistake it for a description of what
/// they are now looking at.
const STATUS_TTL: Duration = Duration::from_secs(4);

impl App {
    pub fn new(store: ConfigStore) -> Self {
        let lang = Lang::load_from_file(&store.prefs_path());
        let mut app = Self {
            store,
            state: AppState::Locked(UnlockState::new(UnlockMode::Unlock)),
            lang,
            should_quit: false,
            last_activity: Instant::now(),
        };
        app.state = app.resolve_initial_state();
        app
    }

    /// Decides which screen the app opens on, from what is on disk and in the
    /// OS credential store — before any user input exists.
    fn resolve_initial_state(&mut self) -> AppState {
        let strings = self.lang.strings();

        // A vault left over from the old TOTP-only mode keeps its secret in
        // plaintext beside the vault, which is exactly the weakness the
        // security modes replace. Convert it before anything else, and make the
        // user set a real password in the process — otherwise the upgraded
        // vault would have no recovery path at all.
        if self.store.totp_only_secret_exists() {
            return AppState::Locked(UnlockState::new(UnlockMode::MigrateTotpOnly));
        }

        if !self.store.exists() {
            return AppState::Setup(SetupState::new(device::credential_store_available()));
        }

        match self.store.peek_shape() {
            Ok(VaultShape::Password) => AppState::Locked(UnlockState::new(UnlockMode::Unlock)),
            Ok(shape) => self.device_backed_initial_state(shape),
            Err(e) => {
                let mut unlock = UnlockState::new(UnlockMode::Unlock);
                unlock.error = Some(format!("{}{e}", strings.save_error_prefix));
                AppState::Locked(unlock)
            }
        }
    }

    /// The startup path for a vault carrying a device slot.
    ///
    /// Everything hinges on whether this machine still has the vault's entry in
    /// the credential store. If it does not — a copied vault, a reinstalled OS,
    /// a cleared keyring — there is nothing to unlock with, and the password
    /// slot is the only way in. That fallback *is* the copy detection.
    fn device_backed_initial_state(&mut self, shape: VaultShape) -> AppState {
        let strings = self.lang.strings();
        let has_password = shape == VaultShape::DeviceAndPassword;

        let state = match self.store.device_store().and_then(|d| d.read()) {
            Ok(Some(state)) => state,
            // No entry, or the store could not be reached at all. Both mean the
            // everyday path is unavailable right now.
            Ok(None) | Err(_) => {
                return if has_password {
                    let mut unlock = UnlockState::new(UnlockMode::Unlock);
                    unlock.error = Some(strings.err_device_not_enrolled.to_string());
                    AppState::Locked(unlock)
                } else {
                    // Mode 1 without a recovery password: nothing on this
                    // machine can open the vault, and saying so plainly beats a
                    // password prompt that can never succeed.
                    AppState::Unopenable
                };
            }
        };

        // A device state carrying a TOTP secret means mode 4: the code gates
        // the device slot. Without one it is mode 1, which opens silently.
        let Some(secret) = state.totp_secret.clone() else {
            return match state.device_key().and_then(|k| self.store.load_with_device(&k)) {
                Ok(unlocked) => Self::unlocked_state(unlocked),
                // A contended lock is not a broken vault: the password would
                // not help either, since the other instance holds the lock
                // whatever this one types.
                Err(AppError::VaultInUse) => AppState::CannotOpen {
                    title: strings.vault_in_use_title,
                    message: strings.vault_in_use_message,
                },
                // Same shape, different reason: opening it would strip the
                // fields the newer build stored.
                Err(AppError::SchemaTooNew { .. }) => AppState::CannotOpen {
                    title: strings.schema_too_new_title,
                    message: strings.schema_too_new_message,
                },
                Err(e) => {
                    if has_password {
                        let mut unlock = UnlockState::new(UnlockMode::Unlock);
                        unlock.error = Some(format!("{}{e}", strings.save_error_prefix));
                        AppState::Locked(unlock)
                    } else {
                        AppState::Unopenable
                    }
                }
            };
        };
        let _ = secret;

        if has_password && state.must_escalate(MAX_TOTP_FAILURES, PASSWORD_CHECK_DAYS) {
            let mut unlock = UnlockState::new(UnlockMode::Unlock);
            unlock.error = Some(strings.err_password_required_now.to_string());
            return AppState::Locked(unlock);
        }

        AppState::LockedTotpDaily(TotpUnlockState::new())
    }

    pub async fn run(&mut self, terminal: &mut TerminalGuard) -> Result<()> {
        while !self.should_quit {
            self.draw(terminal)?;

            if event::poll(Duration::from_millis(200)).map_err(AppError::Io)?
                && let Event::Key(key) = event::read().map_err(AppError::Io)?
                && key.kind == KeyEventKind::Press
            {
                self.last_activity = Instant::now();
                self.handle_key(key, terminal).await?;
                // The flows reached from here can block for hours (a PTY
                // session, a long script). Restamping after they return keeps
                // that time from counting as idle and locking the instant the
                // user comes back to the TUI.
                self.last_activity = Instant::now();
            }

            self.expire_status();
            self.auto_lock_if_idle();
        }
        Ok(())
    }

    /// Drops a footer status message once it has had its time. Driven by the
    /// same 200 ms poll tick as the auto-lock, so the message disappears on its
    /// own rather than waiting for the next screen change.
    fn expire_status(&mut self) {
        if let AppState::Unlocked(u) = &mut self.state
            && u.status.as_ref().is_some_and(|s| s.shown_at.elapsed() >= STATUS_TTL)
        {
            u.status = None;
        }
    }

    /// Drops an idle unlocked session back to the lock screen, which zeroizes
    /// the master key with `UnlockedState`. Only the 200 ms poll tick drives
    /// this, so it cannot fire while `connect_flow` or `run_script_flow` is
    /// awaiting — a live session is never interrupted.
    fn auto_lock_if_idle(&mut self) {
        let AppState::Unlocked(u) = &self.state else {
            return;
        };
        let minutes = u.config.auto_lock_minutes;
        if minutes == 0 || self.last_activity.elapsed() < Duration::from_secs(u64::from(minutes) * 60) {
            return;
        }

        let message = self.lang.strings().status_auto_locked.to_string();
        self.state = self.locked_state();
        match &mut self.state {
            AppState::Locked(unlock) => unlock.info = Some(message),
            AppState::LockedTotpDaily(totp_unlock) => totp_unlock.info = Some(message),
            // Mode 1 re-opens with no prompt, so there is no screen to annotate
            // — the lock still did its job of zeroizing the decrypted config.
            AppState::Setup(_) | AppState::Unopenable | AppState::CannotOpen { .. } | AppState::Unlocked(_) => {}
        }
    }

    /// The locked state this vault should return to. Every path back to
    /// "locked" must go through here rather than naming a variant.
    ///
    /// Re-derives the lock screen from scratch rather than remembering which
    /// one was shown at startup: the security mode may have been changed during
    /// the session, and a device enrolled then may not be enrolled now.
    fn locked_state(&mut self) -> AppState {
        self.resolve_initial_state()
    }

    fn draw(&mut self, terminal: &mut TerminalGuard) -> Result<()> {
        let strings = self.lang.strings();
        match &mut self.state {
            AppState::Locked(unlock) => {
                terminal.terminal.draw(|frame| {
                    let area = frame.area();
                    unlock.render(frame, area, strings);
                })?;
            }
            AppState::LockedTotpDaily(totp_unlock) => {
                terminal.terminal.draw(|frame| {
                    let area = frame.area();
                    totp_unlock.render(frame, area, strings);
                })?;
            }
            AppState::Setup(setup) => {
                terminal.terminal.draw(|frame| {
                    let area = frame.area();
                    setup.render(frame, area, strings);
                })?;
            }
            AppState::Unopenable => {
                terminal.terminal.draw(|frame| {
                    let area = frame.area();
                    crate::tui::setup::render_unopenable(frame, area, strings);
                })?;
            }
            AppState::CannotOpen { title, message } => {
                let (title, message) = (*title, *message);
                terminal.terminal.draw(|frame| {
                    let area = frame.area();
                    crate::tui::setup::render_cannot_open(frame, area, title, message);
                })?;
            }
            AppState::Unlocked(u) => {
                let status = u.status.as_ref().map(|s| s.text.clone());
                // One draw for the whole screen, because the help overlay has
                // to land on top of whatever the screen drew — a second draw
                // call would start from a cleared frame instead.
                let help_open = u.help_open;
                let topic = help_topic(&u.screen);
                let UnlockedState { config, screen, .. } = &mut **u;
                terminal.terminal.draw(|frame| {
                    let area = frame.area();
                    match screen {
                        Screen::MainMenu(state) => state.render(frame, area, &config.servers, status.as_deref(), strings),
                        Screen::ServerForm(state) => state.render(frame, area, strings),
                        Screen::ConfirmDelete { state, .. } => state.render(frame, area, strings),
                        Screen::Settings(state) => state.render(frame, area, strings),
                        Screen::TotpPrompt(state) => state.render(frame, area, strings),
                        Screen::Scripts(state) => {
                            let scripts = config
                                .servers
                                .iter()
                                .find(|s| s.id == state.server_id)
                                .map(|s| s.scripts.as_slice())
                                .unwrap_or(&[]);
                            state.render(frame, area, scripts, status.as_deref(), strings);
                        }
                        Screen::ScriptForm(state) => state.render(frame, area, strings),
                        Screen::ConfirmDeleteScript { state, .. } => state.render(frame, area, strings),
                        Screen::ScriptRun(state) => state.render(frame, area, strings),
                    }
                    if help_open {
                        help::render(frame, area, topic, strings);
                    }
                })?;
            }
        }
        Ok(())
    }

    async fn handle_key(&mut self, key: KeyEvent, terminal: &mut TerminalGuard) -> Result<()> {
        match &mut self.state {
            AppState::Setup(setup) => match setup.handle_key(key, self.lang.strings()) {
                SetupOutcome::None => {}
                SetupOutcome::Quit => self.should_quit = true,
                SetupOutcome::Create { mode, password, totp_secret } => {
                    self.create_vault(mode, password.as_ref().map(|p| p.as_str()), totp_secret)
                }
            },
            // Both are dead ends with nothing to type: Esc is the only key.
            AppState::Unopenable | AppState::CannotOpen { .. } => {
                if key.code == crossterm::event::KeyCode::Esc {
                    self.should_quit = true;
                }
            }
            AppState::Locked(unlock) => {
                let migrating = unlock.mode == UnlockMode::MigrateTotpOnly;
                match unlock.handle_key(key, self.lang.strings()) {
                    UnlockOutcome::None => {}
                    UnlockOutcome::Quit => self.should_quit = true,
                    UnlockOutcome::SetPassword(password) if migrating => self.migrate_totp_only(&password),
                    UnlockOutcome::SetPassword(password) => self.try_unlock(&password, true),
                    UnlockOutcome::TryPassword(password) => self.try_unlock(&password, false),
                }
            }
            AppState::LockedTotpDaily(totp_unlock) => match totp_unlock.handle_key(key) {
                TotpUnlockOutcome::None => {}
                TotpUnlockOutcome::Quit => self.should_quit = true,
                TotpUnlockOutcome::Submit(code) => self.try_totp_daily_unlock(&code),
            },
            AppState::Unlocked(_) => self.handle_unlocked_key(key, terminal).await?,
        }
        Ok(())
    }

    /// Builds the slot set the chosen mode calls for and writes a brand-new
    /// vault.
    ///
    /// The credential-store entry is written *before* the vault, so a failure
    /// half way leaves a stray entry rather than a vault nothing can open — the
    /// same "reversible half first" rule the rest of the app follows.
    fn create_vault(&mut self, mode: AuthMode, password: Option<&str>, totp_secret: Option<Zeroizing<String>>) {
        let strings = self.lang.strings();
        let wants_device = matches!(mode, AuthMode::None | AuthMode::TotpDaily);

        let result = (|| -> Result<Unlocked> {
            let mut device_state = None;
            if wants_device {
                let mut state = DeviceState::new()?;
                // Only mode 4 puts the secret in the credential store; mode 3
                // keeps it inside the vault, where the password already
                // protects it.
                if mode == AuthMode::TotpDaily {
                    state.totp_secret = totp_secret.as_ref().map(Secret::from);
                }
                self.store.device_store()?.write(&state)?;
                device_state = Some(state);
            }

            let mut unlocked = self.store.init_slots(|mk| {
                let mut slots = Vec::new();
                if let Some(password) = password {
                    slots.push(keyslot::wrap_password(password, KdfParams::RECOVERY, mk)?);
                }
                if let Some(state) = &device_state {
                    slots.push(keyslot::wrap_device(&state.device_key()?, mk)?);
                }
                Ok(slots)
            })?;

            // Modes 3 and 4 both keep a copy inside the vault: mode 3 needs it
            // for its second factor, and mode 4 needs it so the escalation path
            // on a *new* machine can still ask for a code after the password.
            if matches!(mode, AuthMode::PasswordTotp | AuthMode::TotpDaily)
                && let Some(secret) = totp_secret
            {
                unlocked.config.totp = Some(TotpConfig { secret_base32: Secret::from(&secret) });
                self.store.save(&unlocked.config, &unlocked.master_key, &unlocked.slots)?;
            }
            Ok(unlocked)
        })();

        match result {
            Ok(unlocked) => {
                // Mode 3's prompt is driven by `config.totp`, but the user just
                // proved a live code during enrolment; asking again immediately
                // would be pure friction.
                self.state = Self::unlocked_state_skipping_totp(unlocked);
            }
            Err(e) => {
                if wants_device && let Ok(store) = self.store.device_store() {
                    store.delete();
                }
                let message = match e {
                    AppError::VaultInUse => strings.err_vault_in_use.to_string(),
                    other => format!("{}{other}", strings.save_error_prefix),
                };
                if let AppState::Setup(setup) = &mut self.state {
                    setup.error = Some(message);
                }
            }
        }
    }

    /// The everyday unlock of `AuthMode::TotpDaily`.
    ///
    /// Every outcome other than a fresh, valid code lands on the password
    /// screen. That is the whole design: the code is convenience, the password
    /// is the thing that actually holds.
    fn try_totp_daily_unlock(&mut self, code: &str) {
        let strings = self.lang.strings();

        let Ok(device_store) = self.store.device_store() else {
            return self.escalate(strings.err_device_not_enrolled);
        };
        let Ok(Some(mut state)) = device_store.read() else {
            return self.escalate(strings.err_device_not_enrolled);
        };
        let Some(secret) = state.totp_secret.clone() else {
            return self.escalate(strings.err_device_not_enrolled);
        };

        match totp::check_code(secret.as_str(), code, state.replay_step) {
            totp::CodeCheck::Accepted(step) => {
                // Persist the step *before* unlocking, so a crash between the
                // two cannot leave a used code replayable.
                state.replay_step = step;
                state.failed_attempts = 0;
                let _ = device_store.write(&state);

                match state.device_key().and_then(|key| self.store.load_with_device(&key)) {
                    Ok(unlocked) => self.state = Self::unlocked_state_skipping_totp(unlocked),
                    // The code was right and has already been spent; the vault
                    // just belongs to another instance. Say that plainly rather
                    // than dressing it up as a save failure.
                    Err(AppError::VaultInUse) => self.set_totp_daily_error(strings.err_vault_in_use.to_string()),
                    Err(e) => self.set_totp_daily_error(format!("{}{e}", strings.save_error_prefix)),
                }
            }
            // A code that was already accepted is not a typo — someone read it
            // over a shoulder or off a screen. Go straight to the password.
            totp::CodeCheck::Replayed => {
                state.failed_attempts = state.failed_attempts.saturating_add(1);
                let _ = device_store.write(&state);
                self.escalate(strings.err_totp_replayed);
            }
            totp::CodeCheck::Invalid => {
                state.failed_attempts = state.failed_attempts.saturating_add(1);
                let _ = device_store.write(&state);
                if state.failed_attempts >= MAX_TOTP_FAILURES {
                    self.escalate(strings.err_totp_too_many_failures);
                } else {
                    self.set_totp_daily_error(strings.err_totp_invalid_code.to_string());
                }
            }
        }
    }

    fn set_totp_daily_error(&mut self, message: String) {
        if let AppState::LockedTotpDaily(totp_unlock) = &mut self.state {
            totp_unlock.error = Some(message);
        }
    }

    /// Falls back to the password screen, saying why.
    fn escalate(&mut self, reason: &str) {
        let mut unlock = UnlockState::new(UnlockMode::Unlock);
        unlock.error = Some(reason.to_string());
        self.state = AppState::Locked(unlock);
    }

    fn try_unlock(&mut self, password: &str, first_run: bool) {
        let result = if first_run { self.store.init(password) } else { self.store.load(password) };
        match result {
            Ok(unlocked) => {
                self.reconcile_device_state(&unlocked);
                self.enter_unlocked(unlocked);
            }
            Err(e) => {
                let message = self.error_text(&e);
                if let AppState::Locked(unlock) = &mut self.state {
                    unlock.error = Some(message);
                }
            }
        }
    }

    /// Error text for a lock screen.
    ///
    /// Only one error gets a translated message: a contended vault lock is the
    /// one failure here the user can actually act on, and "close the other
    /// window" is useless advice if they cannot read it. Everything else keeps
    /// its `Display` text, as it always has.
    fn error_text(&self, e: &AppError) -> String {
        match e {
            AppError::VaultInUse => self.lang.strings().err_vault_in_use.to_string(),
            other => other.to_string(),
        }
    }

    /// After a password unlock, bring this machine's device state back in line
    /// with the vault.
    ///
    /// Two cases matter. A vault with a device slot but no credential-store
    /// entry has been copied here, or the entry was lost — re-enrol so the
    /// everyday path works again from the next launch. A vault whose entry is
    /// present just had its password verified, which clears the failure counter
    /// and the periodic timer.
    ///
    /// All of it is best-effort: the vault is open either way, and refusing to
    /// proceed because a keyring write failed would be worse than running with
    /// the password path for one more session.
    fn reconcile_device_state(&mut self, unlocked: &Unlocked) {
        if !keyslot::has(&unlocked.slots, SLOT_DEVICE) {
            return;
        }
        let Ok(device_store) = self.store.device_store() else {
            return;
        };

        match device_store.read() {
            Ok(Some(mut state)) => {
                state.record_password_check();
                let _ = device_store.write(&state);
            }
            Ok(None) => {
                let Ok(mut state) = DeviceState::new() else {
                    return;
                };
                state.totp_secret = unlocked.config.totp.as_ref().map(|t| t.secret_base32.clone());

                // The existing device slot was wrapped under a key this machine
                // does not have, so it has to be replaced, not reused.
                let Ok(device_key) = state.device_key() else {
                    return;
                };
                let Ok(slot) = keyslot::wrap_device(&device_key, &unlocked.master_key) else {
                    return;
                };
                let mut slots = unlocked.slots.clone();
                keyslot::replace(&mut slots, SLOT_DEVICE, slot);

                // Entry first, then the vault: a stray entry is harmless, a
                // vault pointing at an entry that was never written is not.
                if device_store.write(&state).is_ok()
                    && self.store.save(&unlocked.config, &unlocked.master_key, &slots).is_err()
                {
                    device_store.delete();
                }
            }
            Err(_) => {}
        }
    }

    /// Converts a vault from the retired TOTP-only mode.
    ///
    /// The old vault is keyed by the base32 secret sitting in plaintext beside
    /// it. That secret becomes the device-bound one, `new_password` becomes the
    /// recovery slot, and the plaintext file goes away — but only once the
    /// replacement has been written and proved to open.
    fn migrate_totp_only(&mut self, new_password: &str) {
        let strings = self.lang.strings();

        let result = (|| -> Result<Unlocked> {
            let secret = self.store.read_totp_only_secret()?;
            // Opening it also upgrades the envelope to v2 with a password slot
            // keyed by the secret; the slots are rebuilt below regardless.
            let mut unlocked = self.store.load(&secret)?;

            let mut slots = vec![keyslot::wrap_password(new_password, KdfParams::RECOVERY, &unlocked.master_key)?];

            // Without a credential store there is nowhere device-bound to put
            // the secret, so the vault becomes mode 3 rather than mode 4. Both
            // are a strict improvement on plaintext beside the vault.
            if device::credential_store_available() {
                let mut state = DeviceState::new()?;
                state.totp_secret = Some(Secret::from(&secret));
                self.store.device_store()?.write(&state)?;
                slots.push(keyslot::wrap_device(&state.device_key()?, &unlocked.master_key)?);
            }

            unlocked.config.totp = Some(TotpConfig { secret_base32: Secret::from(&secret) });
            unlocked.slots = slots;
            self.store.save(&unlocked.config, &unlocked.master_key, &unlocked.slots)?;
            Ok(unlocked)
        })();

        match result {
            Ok(unlocked) => {
                // Only now is the plaintext secret expendable.
                self.store.discard_totp_only_secret();
                self.state = Self::unlocked_state_skipping_totp(unlocked);
            }
            Err(e) => {
                if let Ok(store) = self.store.device_store() {
                    store.delete();
                }
                let message = match e {
                    AppError::VaultInUse => strings.err_vault_in_use.to_string(),
                    other => format!("{}{other}", strings.save_error_prefix),
                };
                if let AppState::Locked(unlock) = &mut self.state {
                    unlock.error = Some(message);
                }
            }
        }
    }

    /// Shared by both unlock paths: goes straight to `MainMenu`, except when
    /// the vault has "Password + TOTP (2FA)" enabled, in which case a second
    /// factor is required before `MainMenu` becomes reachable. TOTP-only mode
    /// never reaches this branch with `config.totp` set (mutually exclusive
    /// with 2FA), so no second prompt is ever stacked on top of another.
    fn enter_unlocked(&mut self, unlocked: Unlocked) {
        self.state = Self::unlocked_state(unlocked);
    }

    /// Goes straight to `MainMenu`, except when the vault carries a TOTP secret
    /// — then a second factor is required first. Mode 4 reaches this only on
    /// its escalation path, where asking for the code after the password is the
    /// documented behaviour.
    fn unlocked_state(unlocked: Unlocked) -> AppState {
        let Unlocked { config, master_key, slots } = unlocked;
        let screen = if config.totp.is_some() {
            Screen::TotpPrompt(TotpPromptState::new())
        } else {
            Screen::MainMenu(MainMenuState::new())
        };
        AppState::Unlocked(Box::new(UnlockedState { config, master_key, slots, screen, status: None, help_open: false }))
    }

    /// For the paths that have *just* checked a live code — enrolment and the
    /// mode 4 daily unlock. Asking for a second code a moment later would be
    /// friction with no security value.
    fn unlocked_state_skipping_totp(unlocked: Unlocked) -> AppState {
        let Unlocked { config, master_key, slots } = unlocked;
        AppState::Unlocked(Box::new(UnlockedState {
            config,
            master_key,
            slots,
            screen: Screen::MainMenu(MainMenuState::new()),
            status: None,
            help_open: false,
        }))
    }

    async fn handle_unlocked_key(&mut self, key: KeyEvent, terminal: &mut TerminalGuard) -> Result<()> {
        let strings = self.lang.strings();

        // F2 rather than `?` as the universal opener: `?` is a character the
        // forms and the settings password fields have every right to receive,
        // so the screens where it cannot be confused with typing offer it as
        // well, through their own `Help` outcome.
        if let AppState::Unlocked(u) = &mut self.state {
            if u.help_open {
                u.help_open = false;
                return Ok(());
            }
            if key.code == crossterm::event::KeyCode::F(2) {
                u.help_open = true;
                return Ok(());
            }
        }

        let next = {
            let AppState::Unlocked(u) = &mut self.state else {
                return Ok(());
            };
            match &mut u.screen {
                Screen::MainMenu(state) => match state.handle_key(key, &u.config.servers) {
                    MainMenuAction::None => NextStep::None,
                    MainMenuAction::Connect(id) => NextStep::Connect(id),
                    MainMenuAction::Add => NextStep::GoAdd,
                    MainMenuAction::Edit(id) => NextStep::GoEdit(id),
                    MainMenuAction::Delete(id) => NextStep::GoDelete(id),
                    MainMenuAction::Scripts(id) => NextStep::GoScripts(id),
                    MainMenuAction::Lock => NextStep::Lock,
                    MainMenuAction::Settings => NextStep::GoSettings,
                    MainMenuAction::Help => NextStep::Help,
                    MainMenuAction::Quit => NextStep::Quit,
                },
                Screen::ServerForm(state) => match state.handle_key(key, strings) {
                    FormOutcome::None => NextStep::None,
                    FormOutcome::Cancel => NextStep::FormCancel,
                    FormOutcome::Submit(data) => NextStep::FormSubmit(data),
                },
                Screen::ConfirmDelete { state, .. } => match state.handle_key(key) {
                    ConfirmOutcome::None => NextStep::None,
                    ConfirmOutcome::Yes => NextStep::ConfirmYes,
                    ConfirmOutcome::No => NextStep::ConfirmNo,
                },
                Screen::Settings(state) => match state.handle_key(key, strings) {
                    SettingsOutcome::None => NextStep::None,
                    SettingsOutcome::Close => NextStep::SettingsClose,
                    SettingsOutcome::LanguageSelected(lang) => NextStep::SettingsLangSelected(lang),
                    SettingsOutcome::AutoLockSelected(minutes) => NextStep::SettingsAutoLockSelected(minutes),
                    SettingsOutcome::ChangePassword { current, new } => {
                        NextStep::SettingsChangePassword { current, new }
                    }
                    SettingsOutcome::ChangeSecurityMode { mode, password, totp_secret } => {
                        NextStep::ChangeSecurityMode { mode, password, totp_secret }
                    }
                },
                Screen::TotpPrompt(state) => match state.handle_key(key) {
                    TotpPromptOutcome::None => NextStep::None,
                    TotpPromptOutcome::Submit(code) => NextStep::TotpPromptSubmit(code),
                    TotpPromptOutcome::Cancel => NextStep::TotpPromptCancel,
                },
                Screen::Scripts(state) => {
                    let server_id = state.server_id;
                    let scripts = u
                        .config
                        .servers
                        .iter()
                        .find(|s| s.id == server_id)
                        .map(|s| s.scripts.as_slice())
                        .unwrap_or(&[]);
                    match state.handle_key(key, scripts) {
                        ScriptsListAction::None => NextStep::None,
                        ScriptsListAction::Run(script_id) => NextStep::RunScript(server_id, script_id),
                        ScriptsListAction::Add => NextStep::GoScriptAdd,
                        ScriptsListAction::Edit(script_id) => NextStep::GoScriptEdit(script_id),
                        ScriptsListAction::Delete(script_id) => NextStep::GoScriptDeleteConfirm(script_id),
                        ScriptsListAction::Back => NextStep::ScriptsBack,
                        ScriptsListAction::Help => NextStep::Help,
                    }
                }
                Screen::ScriptForm(state) => match state.handle_key(key, strings) {
                    ScriptFormOutcome::None => NextStep::None,
                    ScriptFormOutcome::Cancel => NextStep::ScriptFormCancel,
                    ScriptFormOutcome::Submit(data) => NextStep::ScriptFormSave(data),
                },
                Screen::ConfirmDeleteScript { state, .. } => match state.handle_key(key) {
                    ConfirmOutcome::None => NextStep::None,
                    ConfirmOutcome::Yes => NextStep::ConfirmDeleteScriptYes,
                    ConfirmOutcome::No => NextStep::ConfirmDeleteScriptNo,
                },
                Screen::ScriptRun(state) => match state.handle_key(key) {
                    ScriptRunOutcome::None => NextStep::None,
                    ScriptRunOutcome::Close => NextStep::ScriptRunClose,
                    ScriptRunOutcome::Help => NextStep::Help,
                },
            }
        };

        match next {
            NextStep::None => {}
            NextStep::Help => {
                if let AppState::Unlocked(u) = &mut self.state {
                    u.help_open = true;
                }
            }
            NextStep::Quit => self.should_quit = true,
            NextStep::Lock => self.state = self.locked_state(),
            NextStep::GoAdd => self.with_unlocked(|u| {
                u.screen = Screen::ServerForm(ServerFormState::new_add());
            }),
            NextStep::GoEdit(id) => self.with_unlocked(|u| {
                if let Some(entry) = u.config.servers.iter().find(|s| s.id == id) {
                    u.screen = Screen::ServerForm(ServerFormState::new_edit(entry));
                }
            }),
            NextStep::GoDelete(id) => self.with_unlocked(|u| {
                if let Some(entry) = u.config.servers.iter().find(|s| s.id == id) {
                    let msg = format!("{}{}{}", strings.delete_confirm_prefix, entry.name, strings.delete_confirm_suffix);
                    u.screen = Screen::ConfirmDelete { target: id, state: ConfirmState::new(msg) };
                }
            }),
            NextStep::GoSettings => {
                let lang = self.lang;
                let auth_mode = self.current_auth_mode();
                self.with_unlocked(|u| {
                    let auto_lock_minutes = u.config.auto_lock_minutes;
                    u.screen = Screen::Settings(SettingsState::new(lang, auth_mode, device::credential_store_available(), auto_lock_minutes));
                });
            }
            NextStep::FormCancel => self.with_unlocked(|u| {
                let mut menu = MainMenuState::new();
                menu.clamp_selection(&u.config.servers);
                u.screen = Screen::MainMenu(menu);
            }),
            NextStep::FormSubmit(data) => self.submit_form(data)?,
            NextStep::ConfirmYes => self.confirm_delete()?,
            NextStep::ConfirmNo => self.with_unlocked(|u| {
                let mut menu = MainMenuState::new();
                menu.clamp_selection(&u.config.servers);
                u.screen = Screen::MainMenu(menu);
            }),
            NextStep::SettingsClose => self.with_unlocked(|u| {
                let mut menu = MainMenuState::new();
                menu.clamp_selection(&u.config.servers);
                u.screen = Screen::MainMenu(menu);
            }),
            NextStep::SettingsLangSelected(lang) => {
                self.lang = lang;
                lang.save_to_file(&self.store.prefs_path());
            }
            NextStep::SettingsAutoLockSelected(minutes) => self.set_auto_lock(minutes),
            NextStep::SettingsChangePassword { current, new } => {
                self.change_master_password(&current, &new)?;
            }
            NextStep::ChangeSecurityMode { mode, password, totp_secret } => {
                self.change_security_mode(mode, password.as_ref().map(|p| p.as_str()), totp_secret)
            }
            NextStep::TotpPromptSubmit(code) => self.verify_totp_prompt(&code),
            NextStep::TotpPromptCancel => self.state = self.locked_state(),
            NextStep::Connect(id) => self.connect_flow(terminal, id).await?,
            NextStep::GoScripts(server_id) => self.with_unlocked(|u| {
                if let Some(entry) = u.config.servers.iter().find(|s| s.id == server_id) {
                    u.screen = Screen::Scripts(ScriptsListState::new(server_id, entry.name.clone()));
                }
            }),
            NextStep::ScriptsBack => self.with_unlocked(|u| {
                let mut menu = MainMenuState::new();
                menu.clamp_selection(&u.config.servers);
                u.screen = Screen::MainMenu(menu);
            }),
            NextStep::GoScriptAdd => self.with_unlocked(|u| {
                let ctx = match &u.screen {
                    Screen::Scripts(state) => Some((state.server_id, state.server_name.clone())),
                    _ => None,
                };
                if let Some((server_id, server_name)) = ctx {
                    u.screen = Screen::ScriptForm(ScriptFormState::new_add(server_id, server_name));
                }
            }),
            NextStep::GoScriptEdit(script_id) => self.with_unlocked(|u| {
                let ctx = match &u.screen {
                    Screen::Scripts(state) => Some((state.server_id, state.server_name.clone())),
                    _ => None,
                };
                if let Some((server_id, server_name)) = ctx
                    && let Some(script) = u
                        .config
                        .servers
                        .iter()
                        .find(|s| s.id == server_id)
                        .and_then(|e| e.scripts.iter().find(|sc| sc.id == script_id))
                    {
                        u.screen = Screen::ScriptForm(ScriptFormState::new_edit(server_id, server_name, script));
                    }
            }),
            NextStep::GoScriptDeleteConfirm(script_id) => self.with_unlocked(|u| {
                let ctx = match &u.screen {
                    Screen::Scripts(state) => Some(state.server_id),
                    _ => None,
                };
                if let Some(server_id) = ctx
                    && let Some(script) = u
                        .config
                        .servers
                        .iter()
                        .find(|s| s.id == server_id)
                        .and_then(|e| e.scripts.iter().find(|sc| sc.id == script_id))
                    {
                        let msg =
                            format!("{}{}{}", strings.delete_script_confirm_prefix, script.name, strings.delete_script_confirm_suffix);
                        u.screen = Screen::ConfirmDeleteScript { server_id, script_id, state: ConfirmState::new(msg) };
                    }
            }),
            NextStep::ScriptFormCancel => self.with_unlocked(|u| {
                let ctx = match &u.screen {
                    Screen::ScriptForm(state) => Some((state.server_id, state.server_name.clone())),
                    _ => None,
                };
                if let Some((server_id, server_name)) = ctx {
                    u.screen = Screen::Scripts(ScriptsListState::new(server_id, server_name));
                }
            }),
            NextStep::ScriptFormSave(data) => self.submit_script_form(data)?,
            NextStep::ConfirmDeleteScriptYes => self.confirm_delete_script()?,
            NextStep::ConfirmDeleteScriptNo => self.with_unlocked(|u| {
                let ctx = match &u.screen {
                    Screen::ConfirmDeleteScript { server_id, .. } => u
                        .config
                        .servers
                        .iter()
                        .find(|s| s.id == *server_id)
                        .map(|e| (*server_id, e.name.clone())),
                    _ => None,
                };
                if let Some((server_id, server_name)) = ctx {
                    u.screen = Screen::Scripts(ScriptsListState::new(server_id, server_name));
                }
            }),
            NextStep::RunScript(server_id, script_id) => self.run_script_flow(terminal, server_id, script_id).await?,
            NextStep::ScriptRunClose => self.with_unlocked(|u| {
                let ctx = match &u.screen {
                    Screen::ScriptRun(state) => Some((state.server_id, state.server_name.clone())),
                    _ => None,
                };
                if let Some((server_id, server_name)) = ctx {
                    u.screen = Screen::Scripts(ScriptsListState::new(server_id, server_name));
                }
            }),
        }

        Ok(())
    }

    fn with_unlocked(&mut self, f: impl FnOnce(&mut UnlockedState)) {
        if let AppState::Unlocked(u) = &mut self.state {
            f(u);
        }
    }

    /// Computed fresh each time, rather than cached, since it depends on both
    /// on-disk state (`totp_only_secret_exists`) and the decrypted config.
    /// Derived, never stored: the slot set plus `config.totp` already say
    /// which mode a vault is in, and a separate persisted field could only
    /// disagree with them.
    fn current_auth_mode(&self) -> AuthMode {
        let AppState::Unlocked(u) = &self.state else {
            return AuthMode::Password;
        };
        match (keyslot::has(&u.slots, SLOT_DEVICE), u.config.totp.is_some()) {
            (true, true) => AuthMode::TotpDaily,
            (true, false) => AuthMode::None,
            (false, true) => AuthMode::PasswordTotp,
            (false, false) => AuthMode::Password,
        }
    }

    fn submit_form(&mut self, data: ServerFormData) -> Result<()> {
        let strings = self.lang.strings();
        let AppState::Unlocked(u) = &mut self.state else {
            return Ok(());
        };
        let Screen::ServerForm(form) = &u.screen else {
            return Ok(());
        };
        let mode = form.mode;

        match mode {
            FormMode::Add => {
                let entry = ServerEntry::new(data.name, data.host, data.port, data.username, data.auth);
                u.config.servers.push(entry);
            }
            FormMode::Edit(id) => {
                if let Some(entry) = u.config.servers.iter_mut().find(|s| s.id == id) {
                    entry.name = data.name;
                    entry.host = data.host;
                    entry.port = data.port;
                    entry.username = data.username;
                    entry.auth = data.auth;
                }
            }
        }

        match self.store.save(&u.config, &u.master_key, &u.slots) {
            Ok(()) => {
                let mut menu = MainMenuState::new();
                menu.clamp_selection(&u.config.servers);
                u.status = Some(StatusMessage::new(strings.status_saved.to_string()));
                u.screen = Screen::MainMenu(menu);
            }
            Err(e) => {
                if let Screen::ServerForm(state) = &mut u.screen {
                    state.error = Some(format!("{}{e}", strings.save_error_prefix));
                }
            }
        }
        Ok(())
    }

    fn confirm_delete(&mut self) -> Result<()> {
        let strings = self.lang.strings();
        let AppState::Unlocked(u) = &mut self.state else {
            return Ok(());
        };
        let Screen::ConfirmDelete { target, .. } = &u.screen else {
            return Ok(());
        };
        let target = *target;
        u.config.servers.retain(|s| s.id != target);

        let save_result = self.store.save(&u.config, &u.master_key, &u.slots);
        let mut menu = MainMenuState::new();
        menu.clamp_selection(&u.config.servers);
        u.status = Some(StatusMessage::new(match save_result {
            Ok(()) => strings.status_deleted.to_string(),
            Err(e) => format!("{}{e}", strings.delete_error_prefix),
        }));
        u.screen = Screen::MainMenu(menu);
        Ok(())
    }

    fn submit_script_form(&mut self, data: ScriptFormData) -> Result<()> {
        let strings = self.lang.strings();
        let AppState::Unlocked(u) = &mut self.state else {
            return Ok(());
        };
        let Screen::ScriptForm(form) = &u.screen else {
            return Ok(());
        };
        let server_id = form.server_id;
        let server_name = form.server_name.clone();
        let mode = form.mode;

        let Some(entry) = u.config.servers.iter_mut().find(|s| s.id == server_id) else {
            return Ok(());
        };

        match mode {
            ScriptFormMode::Add => {
                entry.scripts.push(Script {
                    id: Uuid::new_v4(),
                    name: data.name,
                    run_on_connect: data.run_on_connect,
                    steps: data.steps,
                });
            }
            ScriptFormMode::Edit(script_id) => {
                if let Some(script) = entry.scripts.iter_mut().find(|s| s.id == script_id) {
                    script.name = data.name;
                    script.run_on_connect = data.run_on_connect;
                    script.steps = data.steps;
                }
            }
        }

        match self.store.save(&u.config, &u.master_key, &u.slots) {
            Ok(()) => {
                let mut list = ScriptsListState::new(server_id, server_name);
                if let Some(entry) = u.config.servers.iter().find(|s| s.id == server_id) {
                    list.clamp_selection(&entry.scripts);
                }
                u.status = Some(StatusMessage::new(strings.status_script_saved.to_string()));
                u.screen = Screen::Scripts(list);
            }
            Err(e) => {
                if let Screen::ScriptForm(state) = &mut u.screen {
                    state.error = Some(format!("{}{e}", strings.save_error_prefix));
                }
            }
        }
        Ok(())
    }

    fn confirm_delete_script(&mut self) -> Result<()> {
        let strings = self.lang.strings();
        let AppState::Unlocked(u) = &mut self.state else {
            return Ok(());
        };
        let Screen::ConfirmDeleteScript { server_id, script_id, .. } = &u.screen else {
            return Ok(());
        };
        let (server_id, script_id) = (*server_id, *script_id);

        if let Some(entry) = u.config.servers.iter_mut().find(|s| s.id == server_id) {
            entry.scripts.retain(|s| s.id != script_id);
        }

        let save_result = self.store.save(&u.config, &u.master_key, &u.slots);
        let server_name = u.config.servers.iter().find(|s| s.id == server_id).map(|e| e.name.clone()).unwrap_or_default();
        let mut list = ScriptsListState::new(server_id, server_name);
        if let Some(entry) = u.config.servers.iter().find(|s| s.id == server_id) {
            list.clamp_selection(&entry.scripts);
        }
        u.status = Some(StatusMessage::new(match save_result {
            Ok(()) => strings.status_script_deleted.to_string(),
            Err(e) => format!("{}{e}", strings.delete_error_prefix),
        }));
        u.screen = Screen::Scripts(list);
        Ok(())
    }

    /// Re-verifies `current` against the held key (same salt/params) before
    /// re-encrypting the whole config under a freshly-derived key from `new`
    /// with a brand-new random salt.
    fn change_master_password(&mut self, current: &str, new: &str) -> Result<()> {
        let strings = self.lang.strings();
        let AppState::Unlocked(u) = &mut self.state else {
            return Ok(());
        };
        let Screen::Settings(settings) = &mut u.screen else {
            return Ok(());
        };

        // Unwrapping the password slot *is* the check that `current` is right:
        // the AES-GCM tag decides, so there is no key comparison here to leak a
        // timing signal, and no verifier field that would double as a cheaper
        // offline brute-force oracle.
        let wrong_password = match keyslot::find(&u.slots, SLOT_PASSWORD) {
            Some(slot) => keyslot::unwrap_password(slot, current).is_err(),
            None => true,
        };
        if wrong_password {
            settings.error = Some(strings.err_current_password_wrong.to_string());
            return Ok(());
        }

        // The vault body is untouched — only this one slot's wrapped copy of
        // the master key is replaced.
        let mut slots = u.slots.clone();
        keyslot::replace(&mut slots, SLOT_PASSWORD, keyslot::wrap_password(new, KdfParams::INTERACTIVE, &u.master_key)?);

        match self.store.save(&u.config, &u.master_key, &slots) {
            Ok(()) => {
                u.slots = slots;
                if let Screen::Settings(settings) = &mut u.screen {
                    settings.info = Some(strings.status_password_changed.to_string());
                }
            }
            Err(e) => {
                if let Screen::Settings(settings) = &mut u.screen {
                    settings.error = Some(format!("{}{e}", strings.save_error_prefix));
                }
            }
        }
        Ok(())
    }

    /// Persists the idle auto-lock timeout (in minutes; `0` is off) into the
    /// encrypted config, so it survives a restart. On a failed write the
    /// in-memory value is rolled back — otherwise the timer would run on a
    /// setting the user would not see again after relaunching.
    fn set_auto_lock(&mut self, minutes: u32) {
        let strings = self.lang.strings();
        let AppState::Unlocked(u) = &mut self.state else {
            return;
        };
        let previous = u.config.auto_lock_minutes;
        u.config.auto_lock_minutes = minutes;
        let result = self.store.save(&u.config, &u.master_key, &u.slots);
        if result.is_err() {
            u.config.auto_lock_minutes = previous;
        }
        if let Screen::Settings(settings) = &mut u.screen {
            match result {
                Ok(()) => settings.info = Some(strings.status_auto_lock_saved.to_string()),
                Err(e) => settings.error = Some(format!("{}{e}", strings.save_error_prefix)),
            }
        }
    }

    /// Rebuilds the vault's slot set for a different security mode.
    ///
    /// The master key never changes, so the vault body is not re-encrypted —
    /// only the wrapped copies of that key, plus whatever the new mode needs in
    /// the credential store.
    ///
    /// Write order matters and is the same rule as everywhere else: the
    /// credential-store entry goes first, because a stray entry is harmless
    /// while a vault whose device slot points at an entry that was never
    /// written is unopenable.
    fn change_security_mode(&mut self, mode: AuthMode, password: Option<&str>, totp_secret: Option<Zeroizing<String>>) {
        let strings = self.lang.strings();
        let AppState::Unlocked(u) = &mut self.state else {
            return;
        };
        let wants_device = matches!(mode, AuthMode::None | AuthMode::TotpDaily);

        let result = (|| -> Result<(Vec<Slot>, Option<TotpConfig>)> {
            let mut slots = Vec::new();

            if let Some(password) = password {
                slots.push(keyslot::wrap_password(password, KdfParams::RECOVERY, &u.master_key)?);
            } else if let Some(existing) = keyslot::find(&u.slots, SLOT_PASSWORD) {
                // No new password typed: keep the one already on the vault
                // rather than silently dropping the user's recovery path.
                slots.push(existing.clone());
            }

            // Modes 3 and 4 keep the secret inside the vault as well: mode 3
            // needs it for its second factor, mode 4 for the escalation path on
            // a machine that has no device entry yet.
            let totp = match (&totp_secret, mode) {
                (Some(secret), AuthMode::PasswordTotp | AuthMode::TotpDaily) => {
                    Some(TotpConfig { secret_base32: Secret::from(secret) })
                }
                (None, AuthMode::PasswordTotp | AuthMode::TotpDaily) => u.config.totp.clone(),
                _ => None,
            };

            if wants_device {
                let mut state = DeviceState::new()?;
                if mode == AuthMode::TotpDaily {
                    state.totp_secret = totp.as_ref().map(|t| t.secret_base32.clone());
                }
                self.store.device_store()?.write(&state)?;
                slots.push(keyslot::wrap_device(&state.device_key()?, &u.master_key)?);
            }

            if slots.is_empty() {
                return Err(AppError::Crypto("that mode would leave the vault with no way in".into()));
            }
            Ok((slots, totp))
        })();

        let (slots, totp) = match result {
            Ok(pair) => pair,
            Err(e) => {
                if wants_device && let Ok(store) = self.store.device_store() {
                    store.delete();
                }
                if let Screen::Settings(settings) = &mut u.screen {
                    settings.error = Some(format!("{}{e}", strings.save_error_prefix));
                }
                return;
            }
        };

        let previous_totp = u.config.totp.clone();
        u.config.totp = totp;

        match self.store.save(&u.config, &u.master_key, &slots) {
            Ok(()) => {
                u.slots = slots;
                // The vault no longer has a device slot, so the entry left in
                // the credential store is dead weight — and a secret that would
                // outlive its purpose.
                if !wants_device && let Ok(store) = self.store.device_store() {
                    store.delete();
                }
                let auth_mode = self.current_auth_mode();
                if let AppState::Unlocked(u) = &mut self.state
                    && let Screen::Settings(settings) = &mut u.screen
                {
                    settings.set_auth_mode(auth_mode);
                    settings.info = Some(strings.status_mode_changed.to_string());
                }
            }
            Err(e) => {
                // The on-disk vault was never replaced (writes are atomic), so
                // undoing the in-memory half restores the previous state whole.
                u.config.totp = previous_totp;
                if wants_device && let Ok(store) = self.store.device_store() {
                    store.delete();
                }
                if let Screen::Settings(settings) = &mut u.screen {
                    settings.error = Some(format!("{}{e}", strings.save_error_prefix));
                }
            }
        }
    }

    fn verify_totp_prompt(&mut self, code: &str) {
        let strings = self.lang.strings();
        let AppState::Unlocked(u) = &mut self.state else {
            return;
        };
        let Some(totp_config) = &u.config.totp else {
            u.screen = Screen::MainMenu(MainMenuState::new());
            return;
        };

        if totp::verify_enrollment(totp_config.secret_base32.as_str(), code) {
            let mut menu = MainMenuState::new();
            menu.clamp_selection(&u.config.servers);
            u.screen = Screen::MainMenu(menu);
        } else if let Screen::TotpPrompt(state) = &mut u.screen {
            state.error = Some(strings.err_totp_invalid_code.to_string());
        }
    }

    async fn connect_flow(&mut self, terminal: &mut TerminalGuard, id: Uuid) -> Result<()> {
        let strings = self.lang.strings();
        // Only what the connection itself needs, plus the scripts that run on
        // connect — never a clone of the whole entry, which would leave an
        // extra credential copy and every `Script` behind (see `ssh::Target`).
        let target = match &self.state {
            AppState::Unlocked(u) => u.config.servers.iter().find(|s| s.id == id).map(|e| {
                (ssh::Target::from_entry(e), e.scripts.iter().filter(|s| s.run_on_connect).cloned().collect::<Vec<_>>())
            }),
            AppState::Setup(_) | AppState::Unopenable | AppState::CannotOpen { .. } | AppState::Locked(_) | AppState::LockedTotpDaily(_) => None,
        };
        let Some((target, on_connect_scripts)) = target else {
            return Ok(());
        };

        terminal.suspend()?;
        let connect_result = ssh::connect(&target).await;

        let status_msg = match connect_result {
            Ok(mut connected) => {
                if let ssh::HostKeyOutcome::FirstConnect { fingerprint } = &connected.host_key_outcome
                    && let AppState::Unlocked(u) = &mut self.state {
                        if let Some(e) = u.config.servers.iter_mut().find(|s| s.id == id) {
                            e.host_key_fingerprint = Some(fingerprint.clone());
                        }
                        let _ = self.store.save(&u.config, &u.master_key, &u.slots);
                    }

                // Best-effort: a probe failure (restricted shell, no tools
                // installed, timeout) never blocks the interactive session.
                //
                // The timestamp is stamped either way, and outside the `if let`
                // for that reason — a host whose probe never succeeds is still
                // a host the user connects to, and would otherwise show as
                // never having been reached.
                let info = ssh::sysinfo::fetch(&mut connected.handle).await.ok();
                if let AppState::Unlocked(u) = &mut self.state {
                    if let Some(e) = u.config.servers.iter_mut().find(|s| s.id == id) {
                        e.last_connected_unix = Some(device::now_unix());
                        if info.is_some() {
                            e.system_info = info;
                        }
                    }
                    let _ = self.store.save(&u.config, &u.master_key, &u.slots);
                }

                // Auto-run scripts flagged `run_on_connect`, printed plain to
                // the (still-suspended) primary screen buffer — same spirit
                // as the sysinfo probe: best-effort, never blocks the
                // interactive shell that follows.
                for script in &on_connect_scripts {
                    let mut partial = String::new();
                    script_runner::run_script(&mut connected.handle, script, |event| {
                        print_script_event_plain(event, strings, &mut partial);
                    })
                    .await;
                }

                match ssh::pty_bridge::run_interactive(&mut connected.handle).await {
                    Ok(()) => None,
                    Err(e) => Some(format!("{}{e}", strings.disconnected_prefix)),
                }
            }
            Err(AppError::HostKeyChanged { fingerprint }) => Some(format!(
                "{}{fingerprint}{}",
                strings.host_key_changed_prefix, strings.host_key_changed_suffix
            )),
            Err(e) => Some(format!("{}{e}", strings.connect_error_prefix)),
        };

        terminal.resume()?;

        if let AppState::Unlocked(u) = &mut self.state {
            u.status = status_msg.map(StatusMessage::new);
        }

        Ok(())
    }

    /// Manual "run this script now" flow, triggered from the Scripts list.
    /// Unlike `connect_flow`, the terminal is never suspended — there is no
    /// PTY here, so ratatui keeps rendering throughout, and the live log
    /// screen is updated straight from `script_runner::run_script`'s
    /// `on_event` callback as it fires.
    async fn run_script_flow(&mut self, terminal: &mut TerminalGuard, server_id: Uuid, script_id: Uuid) -> Result<()> {
        let strings = self.lang.strings();
        let prepared = match &self.state {
            AppState::Unlocked(u) => u.config.servers.iter().find(|s| s.id == server_id).and_then(|e| {
                let script = e.scripts.iter().find(|s| s.id == script_id).cloned()?;
                Some((ssh::Target::from_entry(e), e.name.clone(), script))
            }),
            AppState::Setup(_) | AppState::Unopenable | AppState::CannotOpen { .. } | AppState::Locked(_) | AppState::LockedTotpDaily(_) => None,
        };
        let Some((target, server_name, script)) = prepared else {
            return Ok(());
        };

        let mut run_state = ScriptRunState::new(server_id, script_id, server_name, script.name.clone());

        match ssh::connect(&target).await {
            Ok(mut connected) => {
                script_runner::run_script(&mut connected.handle, &script, |event| {
                    match event {
                        RunEvent::StepStarted { command, .. } => run_state.step_started(command),
                        RunEvent::Output { chunk, .. } => run_state.output(chunk),
                        RunEvent::StepFinished { exit_code, .. } => run_state.step_finished(exit_code, strings),
                        RunEvent::StepSkipped { .. } => run_state.step_skipped(strings),
                        RunEvent::StepError { message, .. } => run_state.step_error(message, strings),
                        RunEvent::StepTimedOut { seconds, .. } => run_state.step_timed_out(seconds, strings),
                    }
                    let _ = terminal.terminal.draw(|frame| {
                        let area = frame.area();
                        run_state.render(frame, area, strings);
                    });
                })
                .await;
                run_state.mark_finished();
            }
            Err(e) => {
                run_state.connect_error(&format!("{}{e}", strings.connect_error_prefix), strings);
            }
        }

        self.with_unlocked(|u| {
            u.screen = Screen::ScriptRun(run_state);
        });

        Ok(())
    }
}

/// Plain (non-TUI) sink for `run_on_connect` scripts, since they execute
/// while the terminal is suspended for the interactive SSH session — see
/// `TerminalGuard::suspend`. Raw mode is never toggled off process-wide, so
/// line endings must be written as `\r\n` explicitly or output staircases.
fn print_script_event_plain(event: RunEvent, strings: &Strings, partial: &mut String) {
    use std::io::Write;
    let mut out = std::io::stdout();

    match event {
        RunEvent::StepStarted { command, .. } => {
            let _ = write!(out, "$ {command}\r\n");
        }
        RunEvent::Output { chunk, .. } => {
            partial.push_str(&String::from_utf8_lossy(chunk));
            while let Some(pos) = partial.find('\n') {
                let line: String = partial.drain(..=pos).collect();
                let _ = write!(out, "{}\r\n", line.trim_end_matches(['\r', '\n']));
            }
        }
        RunEvent::StepFinished { exit_code, .. } => {
            if !partial.is_empty() {
                let line = std::mem::take(partial);
                let _ = write!(out, "{line}\r\n");
            }
            let _ = write!(out, "[{}{exit_code}]\r\n", strings.log_exit_prefix);
        }
        RunEvent::StepSkipped { .. } => {
            let _ = write!(out, "{}\r\n", strings.log_skipped);
        }
        RunEvent::StepError { message, .. } => {
            if !partial.is_empty() {
                let line = std::mem::take(partial);
                let _ = write!(out, "{line}\r\n");
            }
            let _ = write!(out, "{}{message}\r\n", strings.log_error_prefix);
        }
        RunEvent::StepTimedOut { seconds, .. } => {
            if !partial.is_empty() {
                let line = std::mem::take(partial);
                let _ = write!(out, "{line}\r\n");
            }
            let _ = write!(out, "{}{seconds}{}\r\n", strings.log_timed_out_prefix, strings.log_timed_out_suffix);
        }
    }
    let _ = out.flush();
}
