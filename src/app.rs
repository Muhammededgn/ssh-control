use std::future::Future;
use std::ops::ControlFlow;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::config::device::{self, DeviceState};
use crate::config::format::{SLOT_DEVICE, SLOT_PASSWORD, Slot};
use crate::config::keyslot::{self, MasterKey};
use crate::config::store::{ConfigStore, Unlocked, VaultShape};
use crate::config::{Config, ConnectMode, Script, Secret, ServerEntry, SystemInfo, TotpConfig};
use crate::crypto::kdf::KdfParams;
use crate::error::{AppError, Result};
use crate::i18n::{Lang, Strings};
use crate::ssh;
use crate::session;
use crate::ssh::script_runner::{self, OwnedRunEvent, ScriptVars};
use crate::terminal::TerminalGuard;
use crate::totp::{self, AuthMode};
use crate::tui::chrome;
use crate::tui::confirm::{ConfirmOutcome, ConfirmState};
use crate::tui::main_menu::{ListStatus, MainMenuAction, MainMenuState};
use crate::tui::script_form::{FormMode as ScriptFormMode, ScriptFormData, ScriptFormOutcome, ScriptFormState};
use crate::tui::script_run::{ScriptRunOutcome, ScriptRunState};
use crate::tui::script_targets::{ScriptTargetsOutcome, ScriptTargetsState};
use crate::tui::ssh_import::{SshImportOutcome, SshImportState};
use crate::tui::forward_form::{ForwardFormData, ForwardFormOutcome, ForwardFormState};
use crate::tui::forwards_list::{ForwardsListAction, ForwardsListState};
use crate::ssh_config::SshConfigHost;
use crate::config::{AuthMethod, ForwardRule};
use crate::tui::scripts_list::{ScriptsListAction, ScriptsListState};
use crate::tui::server_form::{FormMode, FormOutcome, ServerFormData, ServerFormState};
use crate::tui::settings::{SettingsOutcome, SettingsState};
use crate::tui::setup::{SetupOutcome, SetupState};
use crate::tui::theme::{self, Theme};
use crate::tui::totp_prompt::{TotpPromptOutcome, TotpPromptState};
use crate::ssh::{sftp, transfer};
use crate::tui::file_browser::{BrowserEntry, FileBrowserOutcome, FileBrowserState, Side, TransferProgress};
use crate::tui::help::{self, HelpTopic};
use crate::tui::overwrite::{Decision, OverwriteChoice, OverwriteState};
use crate::tui::totp_unlock::{TotpUnlockOutcome, TotpUnlockState};
use crate::tui::unlock::{UnlockMode, UnlockOutcome, UnlockState};

pub(crate) enum Screen {
    MainMenu(MainMenuState),
    ServerForm(ServerFormState),
    ConfirmDelete { target: Uuid, state: ConfirmState },
    Settings(SettingsState),
    /// Second-factor prompt shown after a successful password unlock, only
    /// when the vault has "Password + TOTP (2FA)" enabled.
    TotpPrompt(TotpPromptState),
    Scripts(ScriptsListState),
    /// Which servers a script is about to run on. Ephemeral: nothing it holds
    /// is persisted (see `tui::script_targets`).
    ScriptTargets(ScriptTargetsState),
    /// Which of `~/.ssh/config`'s hosts to bring into the vault. Ephemeral:
    /// it owns its parsed rows and nothing it holds is persisted until the
    /// user confirms (see `tui::ssh_import`).
    SshImport(SshImportState),
    ScriptForm(ScriptFormState),
    ConfirmDeleteScript { server_id: Uuid, script_id: Uuid, state: ConfirmState },
    ScriptRun(ScriptRunState),
    FileBrowser(FileBrowserState),
    Forwards(ForwardsListState),
    ForwardForm(ForwardFormState),
    ConfirmDeleteForward { server_id: Uuid, forward_id: Uuid, state: ConfirmState },
}

/// Which set of keys the help overlay lists, for the screen currently on top.
///
/// The step editor is part of `ScriptForm` as far as `Screen` is concerned, and
/// that topic lists both its hint and the step list's, so it needs no case of
/// its own here.
pub(crate) fn help_topic(screen: &Screen) -> HelpTopic {
    match screen {
        Screen::MainMenu(_) => HelpTopic::ServerList,
        Screen::ServerForm(_) => HelpTopic::ServerForm,
        Screen::SshImport(_) => HelpTopic::SshImport,
        Screen::Forwards(_) => HelpTopic::Forwards,
        Screen::ForwardForm(_) => HelpTopic::ForwardForm,
        Screen::ConfirmDelete { .. } | Screen::ConfirmDeleteScript { .. } | Screen::ConfirmDeleteForward { .. } => HelpTopic::Confirm,
        Screen::Settings(_) => HelpTopic::Settings,
        Screen::TotpPrompt(_) => HelpTopic::TotpPrompt,
        Screen::Scripts(_) => HelpTopic::ScriptList,
        Screen::ScriptTargets(_) => HelpTopic::ScriptTargets,
        Screen::ScriptForm(_) => HelpTopic::ScriptForm,
        Screen::ScriptRun(_) => HelpTopic::ScriptRun,
        Screen::FileBrowser(_) => HelpTopic::FileBrowser,
    }
}

/// A transient footer message ("Saved.", "Deleted."), with the moment it was
/// shown so the run loop can take it away again.
///
/// Without the timestamp a message sits there until the screen changes, so a
/// "Saved." from ten minutes ago still reads as if it describes whatever the
/// user is looking at now.
pub(crate) struct StatusMessage {
    pub(crate) text: String,
    shown_at: Instant,
}

impl StatusMessage {
    fn new(text: String) -> Self {
        Self { text, shown_at: Instant::now() }
    }
}

pub(crate) struct UnlockedState {
    pub(crate) config: Config,
    pub(crate) master_key: MasterKey,
    pub(crate) slots: Vec<Slot>,
    pub(crate) screen: Screen,
    pub(crate) status: Option<StatusMessage>,
    /// The keybinding overlay. Modal while it is up: it takes the next key to
    /// dismiss itself and hands nothing through to the screen underneath, so a
    /// key pressed to close it can never also act on the list behind it.
    pub(crate) help_open: bool,
}

pub(crate) enum AppState {
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
pub(crate) enum NextStep {
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
    SettingsThemeSelected(Theme),
    SettingsAutoLockSelected(u32),
    SettingsConnectModeSelected(ConnectMode),
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
    CycleSort,
    GoScriptTargets(Uuid),
    ScriptTargetsCancel,
    GoSshImport,
    SshImportCancel,
    /// The hosts the user ticked. Carried by value rather than re-read from
    /// disk on confirm: the file could have changed since the screen opened,
    /// and importing something the user never saw is the one outcome a picker
    /// must not have.
    SshImportConfirm(Vec<SshConfigHost>),
    /// The script's own server, the script, and every server to run it on. A
    /// plain `Enter` on the script list is this with a one-element list, so
    /// there is one flow rather than two.
    RunScript { origin_server_id: Uuid, script_id: Uuid, targets: Vec<Uuid> },
    ScriptRunSave(String),
    ScriptRunClose,
    GoFiles(Uuid),
    FilesBack,
    FilesTransfer,
    FilesOpenRemote(String),
    FilesRefresh,
    GoForwards(Uuid),
    ForwardsBack,
    GoForwardAdd,
    GoForwardEdit(Uuid),
    GoForwardDeleteConfirm(Uuid),
    ForwardToggle(Uuid),
    ForwardFormCancel,
    ForwardFormSave(ForwardFormData),
    ConfirmDeleteForwardYes,
    ConfirmDeleteForwardNo,
}

pub struct App {
    pub(crate) store: ConfigStore,
    pub(crate) state: AppState,
    pub(crate) lang: Lang,
    pub(crate) theme: Theme,
    pub(crate) should_quit: bool,
    /// When the last key was pressed, for the idle auto-lock. Also re-stamped
    /// after every `handle_key`, so time spent inside an SSH session or a
    /// script run does not count as idle.
    pub(crate) last_activity: Instant,
    /// The live connection the file browser lists and transfers over.
    ///
    /// A sibling of `state`, deliberately not a field inside `UnlockedState`:
    /// every remote operation awaits, and no borrow of `state` may be held
    /// across an await (see the `NextStep` pattern). As its own field it can be
    /// taken out, used across the await, and put back afterwards.
    pub(crate) remote: Option<RemoteSession>,
    /// The server a flow is currently reaching, and when the attempt started.
    /// The server list's row indicator and its spinner frame both read this.
    ///
    /// Flow-scoped, and on `App` for the same reason `remote` is. Keyed by
    /// `Uuid` and never by row index: a filter or a re-sort moves rows out from
    /// under an index, which is what `MainMenuState::selected` documents.
    ///
    /// Set by the flows, cleared centrally in `App::run` — no exit path can
    /// leave the list stuck saying "connecting…".
    pub(crate) connecting: Option<(Uuid, Instant)>,
}

/// One authenticated connection plus its sftp channel. The russh handle has to
/// be kept alive alongside the stream — dropping it closes the channel out from
/// under the client.
/// Everything a connect needs from the vault, resolved inside the borrow.
///
/// A plain owned bundle rather than a tuple because both flows destructure it
/// and a fourth field would otherwise be a fourth unnamed position.
struct ConnectContext {
    /// The bastion chain, resolved. `Err` is a chain that loops or names a
    /// deleted server, and it rides this far rather than failing in
    /// `connect_context` so each flow can report it its own way.
    target: Result<ssh::Target>,
    forwards: Vec<ForwardRule>,
    on_connect: Vec<Script>,
}

pub(crate) struct RemoteSession {
    server_id: Uuid,
    #[allow(dead_code, reason = "owned to keep the channel — and any bastion tunnel under it — alive for the lifetime of the sftp stream")]
    connected: crate::ssh::Connected,
    sftp: crate::ssh::sftp::SftpClient<russh::ChannelStream<russh::client::Msg>>,
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
        // Before the first frame — the unlock screen is coloured too.
        let theme = Theme::load_from_file(&store.theme_path());
        theme::init(theme);
        let mut app = Self {
            store,
            state: AppState::Locked(UnlockState::new(UnlockMode::Unlock)),
            lang,
            theme,
            should_quit: false,
            last_activity: Instant::now(),
            remote: None,
            connecting: None,
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
                Err(AppError::SchemaTooNew { .. }) => self.schema_too_new_state(),
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
                // Whatever flow just ran has returned, so nothing is being
                // connected to any more. Cleared here rather than on each of
                // the flows' exit paths, where one of them would eventually be
                // missed and leave a row spinning forever.
                self.connecting = None;
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
        self.drop_remote();
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
        // Copied out before `self.state` is borrowed, like `status` below.
        let connecting = self.connecting;
        match &mut self.state {
            AppState::Locked(unlock) => {
                terminal.terminal.draw(|frame| {
                    let area = frame.area();
                    chrome::paint_background(frame, area);
                    unlock.render(frame, area, strings);
                })?;
            }
            AppState::LockedTotpDaily(totp_unlock) => {
                terminal.terminal.draw(|frame| {
                    let area = frame.area();
                    chrome::paint_background(frame, area);
                    totp_unlock.render(frame, area, strings);
                })?;
            }
            AppState::Setup(setup) => {
                terminal.terminal.draw(|frame| {
                    let area = frame.area();
                    chrome::paint_background(frame, area);
                    setup.render(frame, area, strings);
                })?;
            }
            AppState::Unopenable => {
                terminal.terminal.draw(|frame| {
                    let area = frame.area();
                    chrome::paint_background(frame, area);
                    crate::tui::setup::render_unopenable(frame, area, strings);
                })?;
            }
            AppState::CannotOpen { title, message } => {
                let (title, message) = (*title, *message);
                terminal.terminal.draw(|frame| {
                    let area = frame.area();
                    chrome::paint_background(frame, area);
                    crate::tui::setup::render_cannot_open(frame, area, title, message, strings);
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
                    chrome::paint_background(frame, area);
                    match screen {
                        Screen::MainMenu(state) => state.render(frame, area, &config.servers, config.server_sort, ListStatus { connecting, message: status.as_deref() }, strings),
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
                        Screen::ScriptTargets(state) => state.render(frame, area, &config.servers, strings),
                        Screen::SshImport(state) => state.render(frame, area, strings),
                        Screen::ScriptForm(state) => state.render(frame, area, strings),
                        Screen::ConfirmDeleteScript { state, .. } => state.render(frame, area, strings),
                        Screen::ScriptRun(state) => state.render(frame, area, strings),
                        Screen::FileBrowser(state) => state.render(frame, area, strings),
                        Screen::Forwards(state) => {
                            let forwards = config
                                .servers
                                .iter()
                                .find(|s| s.id == state.server_id)
                                .map(|s| s.forwards.as_slice())
                                .unwrap_or(&[]);
                            state.render(frame, area, forwards, status.as_deref(), strings);
                        }
                        Screen::ForwardForm(state) => state.render(frame, area, strings),
                        Screen::ConfirmDeleteForward { state, .. } => state.render(frame, area, strings),
                    }
                    if help_open {
                        help::render(frame, area, topic, strings);
                    }
                })?;
            }
        }
        Ok(())
    }

    /// Awaits `future` with the app still on screen: redraws on every
    /// `KEY_POLL_INTERVAL` tick so a resize lands and a spinner turns, and
    /// drains the keyboard so `Esc` can abandon the attempt. `None` is a
    /// cancel.
    ///
    /// Before this, a connect was a frozen frame — `App::run` is blocked inside
    /// the flow, so nothing repainted and the keys typed during it sat in the
    /// terminal buffer and replayed afterwards. Same shape as
    /// `run_script_flow`'s `select!` and `transfer_flow`'s
    /// `redraw_and_poll_cancel`, without the screen-specific half.
    ///
    /// **`future` must not borrow `self`**: the redraw arm needs `&mut self`.
    /// That is not an obstacle to work around, it is the constraint
    /// `transfer_flow` already lives under, and the reason `list_remote_flow`
    /// takes `self.remote` out before awaiting.
    ///
    /// Bind the result on its own statement rather than matching the call
    /// directly — the future temporary otherwise lives to the end of the
    /// `match`, and no arm can move what it borrowed.
    async fn await_redrawing<T>(&mut self, terminal: &mut TerminalGuard, cancel: Cancel, future: impl Future<Output = T>) -> Option<T> {
        let mut future = std::pin::pin!(future);
        let _ = self.draw(terminal);
        loop {
            tokio::select! {
                // A future that resolved in the same wakeup as a due tick is
                // not a cancel — the same reason `run_script_flow` is biased.
                biased;
                out = &mut future => return Some(out),
                _ = tokio::time::sleep(KEY_POLL_INTERVAL) => {
                    // Drained either way. Keys left unread would replay against
                    // whatever screen the flow returns to.
                    if cancel_requested() && cancel == Cancel::Allowed {
                        return None;
                    }
                    let _ = self.draw(terminal);
                }
            }
        }
    }

    /// `await_redrawing` where Esc abandons the wait.
    async fn await_on_screen<T>(&mut self, terminal: &mut TerminalGuard, future: impl Future<Output = T>) -> Option<T> {
        self.await_redrawing(terminal, Cancel::Allowed, future).await
    }

    /// `await_redrawing` where it does not — see `Cancel`.
    async fn redraw_while<T>(&mut self, terminal: &mut TerminalGuard, future: impl Future<Output = T>) -> T {
        self.await_redrawing(terminal, Cancel::Refused, future).await.expect("a refused cancel never returns None")
    }

    async fn handle_key(&mut self, key: KeyEvent, terminal: &mut TerminalGuard) -> Result<()> {
        if matches!(self.state, AppState::Unlocked(_)) {
            return self.handle_unlocked_key(key, terminal).await;
        }
        self.handle_locked_key(key);
        Ok(())
    }

    /// Every screen reachable before the vault is open.
    ///
    /// Split out from `handle_key` because none of it awaits and none of it
    /// needs a terminal — only `draw` and the six flows behind
    /// `handle_unlocked_key` do. That is what lets the tests drive an unlock
    /// end to end without a `TerminalGuard` to hand them.
    pub(crate) fn handle_locked_key(&mut self, key: KeyEvent) {
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
            // Handled by `handle_key` before it ever gets here.
            AppState::Unlocked(_) => {}
        }
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
    pub(crate) fn try_totp_daily_unlock(&mut self, code: &str) {
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
                    // Nor is this one a save failure, and no retyped code fixes
                    // it: the vault needs the newer binary, full stop.
                    Err(AppError::SchemaTooNew { .. }) => self.state = self.schema_too_new_state(),
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

    /// The screen a vault written by a newer build belongs on, whichever
    /// unlock route hit the refusal.
    ///
    /// `SchemaTooNew` can surface from all three — the silent device path, the
    /// TOTP-daily code, and the password — and only the first used to route it
    /// here. The other two printed it inline under `save_error_prefix`, which
    /// names the wrong operation: nothing was being saved, the vault was being
    /// opened. None of them has anything to retype, so all three land here.
    fn schema_too_new_state(&self) -> AppState {
        let strings = self.lang.strings();
        AppState::CannotOpen { title: strings.schema_too_new_title, message: strings.schema_too_new_message }
    }

    /// Falls back to the password screen, saying why.
    fn escalate(&mut self, reason: &str) {
        let mut unlock = UnlockState::new(UnlockMode::Unlock);
        unlock.error = Some(reason.to_string());
        self.state = AppState::Locked(unlock);
    }

    pub(crate) fn try_unlock(&mut self, password: &str, first_run: bool) {
        let result = if first_run { self.store.init(password) } else { self.store.load(password) };
        match result {
            Ok(unlocked) => {
                self.reconcile_device_state(&unlocked);
                self.enter_unlocked(unlocked);
            }
            // The one unlock failure that is not about the password at all.
            // Leaving it on the lock screen invites the user to try again with
            // a password that was never wrong.
            Err(AppError::SchemaTooNew { .. }) => self.state = self.schema_too_new_state(),
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
        let next = self.resolve_next_step(key);
        // Everything that can be done without a terminal is done here; what
        // comes back is one of the six flows that suspend, redraw or hold a
        // live connection, and only those need `terminal`.
        let Some(next) = self.apply_local_step(next)? else {
            return Ok(());
        };
        match next {
            NextStep::Connect(id) => self.connect_flow(terminal, id).await?,
            NextStep::RunScript { origin_server_id, script_id, targets } => {
                self.run_script_flow(terminal, origin_server_id, script_id, targets).await?
            }
            NextStep::GoFiles(id) => self.open_files_flow(terminal, id).await?,
            NextStep::FilesOpenRemote(path) => self.list_remote_flow(terminal, Some(path)).await?,
            NextStep::FilesRefresh => self.list_remote_flow(terminal, None).await?,
            NextStep::FilesTransfer => self.transfer_flow(terminal).await?,
            // `apply_local_step` returns `None` for every other variant.
            _ => {}
        }
        Ok(())
    }

    /// Resolves a key event into a `NextStep` without doing any of the work.
    ///
    /// This is the half of the `NextStep` pattern that holds the borrow of
    /// `self.state`: the borrow ends when this returns, which is what lets the
    /// async flows run afterwards. It is also the seam the tests drive — no
    /// terminal, no `.await`.
    pub(crate) fn resolve_next_step(&mut self, key: KeyEvent) -> NextStep {
        let strings = self.lang.strings();

        // F2 rather than `?` as the universal opener: `?` is a character the
        // forms and the settings password fields have every right to receive,
        // so the screens where it cannot be confused with typing offer it as
        // well, through their own `Help` outcome.
        if let AppState::Unlocked(u) = &mut self.state {
            if u.help_open {
                u.help_open = false;
                return NextStep::None;
            }
            if key.code == crossterm::event::KeyCode::F(2) {
                u.help_open = true;
                return NextStep::None;
            }
        }

        {
            let AppState::Unlocked(u) = &mut self.state else {
                return NextStep::None;
            };
            match &mut u.screen {
                Screen::MainMenu(state) => match state.handle_key(key, &u.config.servers, u.config.server_sort) {
                    MainMenuAction::None => NextStep::None,
                    MainMenuAction::Connect(id) => NextStep::Connect(id),
                    MainMenuAction::Add => NextStep::GoAdd,
                    MainMenuAction::Edit(id) => NextStep::GoEdit(id),
                    MainMenuAction::Delete(id) => NextStep::GoDelete(id),
                    MainMenuAction::Scripts(id) => NextStep::GoScripts(id),
                    MainMenuAction::Files(id) => NextStep::GoFiles(id),
                    MainMenuAction::SshImport => NextStep::GoSshImport,
                    MainMenuAction::Forwards(id) => NextStep::GoForwards(id),
                    MainMenuAction::Lock => NextStep::Lock,
                    MainMenuAction::Settings => NextStep::GoSettings,
                    MainMenuAction::CycleSort => NextStep::CycleSort,
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
                    SettingsOutcome::ThemeSelected(t) => NextStep::SettingsThemeSelected(t),
                    SettingsOutcome::AutoLockSelected(minutes) => NextStep::SettingsAutoLockSelected(minutes),
                    SettingsOutcome::ConnectModeSelected(mode) => NextStep::SettingsConnectModeSelected(mode),
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
                        ScriptsListAction::Run(script_id) => {
                            NextStep::RunScript { origin_server_id: server_id, script_id, targets: vec![server_id] }
                        }
                        ScriptsListAction::RunOn(script_id) => NextStep::GoScriptTargets(script_id),
                        ScriptsListAction::Add => NextStep::GoScriptAdd,
                        ScriptsListAction::Edit(script_id) => NextStep::GoScriptEdit(script_id),
                        ScriptsListAction::Delete(script_id) => NextStep::GoScriptDeleteConfirm(script_id),
                        ScriptsListAction::Back => NextStep::ScriptsBack,
                        ScriptsListAction::Help => NextStep::Help,
                    }
                }
                Screen::ScriptTargets(state) => {
                    let (origin_server_id, script_id) = (state.origin_server_id, state.script_id);
                    match state.handle_key(key, &u.config.servers) {
                        ScriptTargetsOutcome::None => NextStep::None,
                        ScriptTargetsOutcome::Cancel => NextStep::ScriptTargetsCancel,
                        ScriptTargetsOutcome::Help => NextStep::Help,
                        ScriptTargetsOutcome::Run(targets) => NextStep::RunScript { origin_server_id, script_id, targets },
                    }
                }
                Screen::SshImport(state) => match state.handle_key(key) {
                    SshImportOutcome::None => NextStep::None,
                    SshImportOutcome::Cancel => NextStep::SshImportCancel,
                    SshImportOutcome::Help => NextStep::Help,
                    SshImportOutcome::Import(hosts) => NextStep::SshImportConfirm(hosts),
                },
                Screen::Forwards(state) => {
                    let forwards = u
                        .config
                        .servers
                        .iter()
                        .find(|s| s.id == state.server_id)
                        .map(|s| s.forwards.clone())
                        .unwrap_or_default();
                    match state.handle_key(key, &forwards) {
                        ForwardsListAction::None => NextStep::None,
                        ForwardsListAction::Add => NextStep::GoForwardAdd,
                        ForwardsListAction::Edit(id) => NextStep::GoForwardEdit(id),
                        ForwardsListAction::Delete(id) => NextStep::GoForwardDeleteConfirm(id),
                        ForwardsListAction::Toggle(id) => NextStep::ForwardToggle(id),
                        ForwardsListAction::Back => NextStep::ForwardsBack,
                        ForwardsListAction::Help => NextStep::Help,
                    }
                }
                Screen::ForwardForm(state) => match state.handle_key(key, strings) {
                    ForwardFormOutcome::None => NextStep::None,
                    ForwardFormOutcome::Cancel => NextStep::ForwardFormCancel,
                    ForwardFormOutcome::Submit(data) => NextStep::ForwardFormSave(data),
                },
                Screen::ConfirmDeleteForward { state, .. } => match state.handle_key(key) {
                    ConfirmOutcome::None => NextStep::None,
                    ConfirmOutcome::Yes => NextStep::ConfirmDeleteForwardYes,
                    ConfirmOutcome::No => NextStep::ConfirmDeleteForwardNo,
                },
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
                    ScriptRunOutcome::Save(path) => NextStep::ScriptRunSave(path),
                },
                Screen::FileBrowser(state) => match state.handle_key(key) {
                    FileBrowserOutcome::None => NextStep::None,
                    FileBrowserOutcome::Help => NextStep::Help,
                    FileBrowserOutcome::Back => NextStep::FilesBack,
                    FileBrowserOutcome::OpenRemote(path) => NextStep::FilesOpenRemote(path),
                    FileBrowserOutcome::RefreshRemote => NextStep::FilesRefresh,
                    FileBrowserOutcome::Transfer => NextStep::FilesTransfer,
                },
            }
        }
    }

    /// Carries out every `NextStep` that needs no terminal, which is all but
    /// six of them.
    ///
    /// Returns `Ok(Some(step))` for the ones that do — `connect_flow` and the
    /// file-browser flows suspend the alternate screen or redraw from inside an
    /// `.await`, so they stay in `handle_unlocked_key`. Splitting it here is
    /// what makes the transitions testable: everything below is plain state.
    pub(crate) fn apply_local_step(&mut self, next: NextStep) -> Result<Option<NextStep>> {
        let strings = self.lang.strings();
        match next {
            NextStep::None => {}
            NextStep::Help => {
                if let AppState::Unlocked(u) = &mut self.state {
                    u.help_open = true;
                }
            }
            NextStep::Quit => {
                self.drop_remote();
                self.should_quit = true;
            }
            NextStep::Lock => {
                self.drop_remote();
                self.state = self.locked_state();
            }
            NextStep::GoAdd => self.with_unlocked(|u| {
                // Bound on its own statement: assigning inline keeps the borrow
                // of `u.config.servers` alive across the write to `u.screen`.
                let form = ServerFormState::new_add(&u.config.servers);
                u.screen = Screen::ServerForm(form);
            }),
            NextStep::GoEdit(id) => self.with_unlocked(|u| {
                let form = u
                    .config
                    .servers
                    .iter()
                    .find(|s| s.id == id)
                    .map(|entry| ServerFormState::new_edit(entry, &u.config.servers));
                if let Some(form) = form {
                    u.screen = Screen::ServerForm(form);
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
                let current_theme = self.theme;
                let auth_mode = self.current_auth_mode();
                self.with_unlocked(|u| {
                    let auto_lock_minutes = u.config.auto_lock_minutes;
                    let connect_mode = u.config.connect_mode;
                    u.screen =
                        Screen::Settings(SettingsState::new(lang, current_theme, auth_mode, device::credential_store_available(), auto_lock_minutes, connect_mode));
                });
            }
            NextStep::FormCancel => self.with_unlocked(|u| {
                let mut menu = MainMenuState::new();
                menu.clamp_selection(&u.config.servers, u.config.server_sort);
                u.screen = Screen::MainMenu(menu);
            }),
            NextStep::FormSubmit(data) => self.submit_form(data)?,
            NextStep::ConfirmYes => self.confirm_delete()?,
            NextStep::ConfirmNo => self.with_unlocked(|u| {
                let mut menu = MainMenuState::new();
                menu.clamp_selection(&u.config.servers, u.config.server_sort);
                u.screen = Screen::MainMenu(menu);
            }),
            NextStep::SettingsClose => self.with_unlocked(|u| {
                let mut menu = MainMenuState::new();
                menu.clamp_selection(&u.config.servers, u.config.server_sort);
                u.screen = Screen::MainMenu(menu);
            }),
            NextStep::SettingsLangSelected(lang) => {
                self.lang = lang;
                lang.save_to_file(&self.store.prefs_path());
            }
            // Applied immediately and written straight away, like the
            // language: both are non-secret conveniences beside the vault, and
            // a best-effort write that fails is not worth an error screen.
            NextStep::SettingsThemeSelected(t) => {
                self.theme = t;
                theme::set(t);
                t.save_to_file(&self.store.theme_path());
            }
            NextStep::SettingsAutoLockSelected(minutes) => self.set_auto_lock(minutes),
            NextStep::SettingsConnectModeSelected(mode) => self.set_connect_mode(mode),
            NextStep::SettingsChangePassword { current, new } => {
                self.change_master_password(&current, &new)?;
            }
            NextStep::ChangeSecurityMode { mode, password, totp_secret } => {
                self.change_security_mode(mode, password.as_ref().map(|p| p.as_str()), totp_secret)
            }
            NextStep::TotpPromptSubmit(code) => self.verify_totp_prompt(&code),
            NextStep::TotpPromptCancel => self.state = self.locked_state(),
            // The six that await with a terminal go back to `handle_unlocked_key`.
            NextStep::Connect(id) => return Ok(Some(NextStep::Connect(id))),
            NextStep::GoScripts(server_id) => self.with_unlocked(|u| {
                if let Some(entry) = u.config.servers.iter().find(|s| s.id == server_id) {
                    u.screen = Screen::Scripts(ScriptsListState::new(server_id, entry.name.clone()));
                }
            }),
            NextStep::ScriptsBack => self.with_unlocked(|u| {
                let mut menu = MainMenuState::new();
                menu.clamp_selection(&u.config.servers, u.config.server_sort);
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
            NextStep::CycleSort => self.cycle_server_sort(),
            NextStep::GoScriptTargets(script_id) => self.with_unlocked(|u| {
                let ctx = match &u.screen {
                    Screen::Scripts(state) => u
                        .config
                        .servers
                        .iter()
                        .find(|s| s.id == state.server_id)
                        .and_then(|e| e.scripts.iter().find(|s| s.id == script_id))
                        .map(|script| (state.server_id, script.name.clone())),
                    _ => None,
                };
                if let Some((server_id, script_name)) = ctx {
                    u.screen = Screen::ScriptTargets(ScriptTargetsState::new(server_id, script_id, script_name));
                }
            }),
            NextStep::GoForwards(id) => self.with_unlocked(|u| {
                let name = u.config.servers.iter().find(|s| s.id == id).map(|e| e.name.clone());
                if let Some(name) = name {
                    u.screen = Screen::Forwards(ForwardsListState::new(id, name));
                }
            }),
            NextStep::ForwardsBack => self.with_unlocked(|u| {
                let mut menu = MainMenuState::new();
                menu.clamp_selection(&u.config.servers, u.config.server_sort);
                u.screen = Screen::MainMenu(menu);
            }),
            NextStep::GoForwardAdd => self.with_unlocked(|u| {
                if let Screen::Forwards(list) = &u.screen {
                    u.screen = Screen::ForwardForm(ForwardFormState::new_add(list.server_id));
                }
            }),
            NextStep::GoForwardEdit(forward_id) => self.with_unlocked(|u| {
                let form = match &u.screen {
                    Screen::Forwards(list) => u
                        .config
                        .servers
                        .iter()
                        .find(|s| s.id == list.server_id)
                        .and_then(|e| e.forwards.iter().find(|f| f.id == forward_id))
                        .map(|rule| ForwardFormState::new_edit(list.server_id, rule)),
                    _ => None,
                };
                if let Some(form) = form {
                    u.screen = Screen::ForwardForm(form);
                }
            }),
            NextStep::GoForwardDeleteConfirm(forward_id) => self.with_unlocked(|u| {
                let ctx = match &u.screen {
                    Screen::Forwards(list) => u
                        .config
                        .servers
                        .iter()
                        .find(|s| s.id == list.server_id)
                        .and_then(|e| e.forwards.iter().find(|f| f.id == forward_id))
                        .map(|rule| (list.server_id, rule.label())),
                    _ => None,
                };
                if let Some((server_id, label)) = ctx {
                    let msg = format!("{}{label}{}", strings.delete_forward_confirm_prefix, strings.delete_forward_confirm_suffix);
                    u.screen = Screen::ConfirmDeleteForward { server_id, forward_id, state: ConfirmState::new(msg) };
                }
            }),
            NextStep::ForwardToggle(forward_id) => self.toggle_forward(forward_id),
            NextStep::ForwardFormCancel => self.back_to_forwards(),
            NextStep::ForwardFormSave(data) => self.submit_forward_form(data),
            NextStep::ConfirmDeleteForwardYes => self.confirm_delete_forward(),
            NextStep::ConfirmDeleteForwardNo => self.back_to_forwards(),
            NextStep::GoSshImport => self.open_ssh_import(),
            NextStep::SshImportCancel => self.with_unlocked(|u| {
                let mut menu = MainMenuState::new();
                menu.clamp_selection(&u.config.servers, u.config.server_sort);
                u.screen = Screen::MainMenu(menu);
            }),
            NextStep::SshImportConfirm(hosts) => self.import_ssh_hosts(hosts),
            NextStep::ScriptTargetsCancel => self.with_unlocked(|u| {
                let ctx = match &u.screen {
                    Screen::ScriptTargets(state) => Some(state.origin_server_id),
                    _ => None,
                };
                if let Some(server_id) = ctx {
                    let server_name = u.config.servers.iter().find(|s| s.id == server_id).map(|e| e.name.clone()).unwrap_or_default();
                    u.screen = Screen::Scripts(ScriptsListState::new(server_id, server_name));
                }
            }),
            NextStep::RunScript { origin_server_id, script_id, targets } => {
                return Ok(Some(NextStep::RunScript { origin_server_id, script_id, targets }));
            }
            NextStep::GoFiles(id) => return Ok(Some(NextStep::GoFiles(id))),
            NextStep::FilesOpenRemote(path) => return Ok(Some(NextStep::FilesOpenRemote(path))),
            NextStep::FilesRefresh => return Ok(Some(NextStep::FilesRefresh)),
            NextStep::FilesTransfer => return Ok(Some(NextStep::FilesTransfer)),
            NextStep::FilesBack => {
                self.remember_browser_dirs();
                self.drop_remote();
                self.with_unlocked(|u| {
                    let mut menu = MainMenuState::new();
                    menu.clamp_selection(&u.config.servers, u.config.server_sort);
                    u.screen = Screen::MainMenu(menu);
                });
            }
            NextStep::ScriptRunSave(path) => self.save_script_log(&path),
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

        Ok(None)
    }

    /// Closes the browser's connection.
    ///
    /// Dropping `RemoteSession` closes the channel and the ssh handle with it.
    /// Called from every path that ends the browsing session — and, critically,
    /// from the idle auto-lock: a locked vault that quietly kept an
    /// authenticated connection open would defeat the point of locking.
    fn drop_remote(&mut self) {
        self.remote = None;
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

    /// Opens the `~/.ssh/config` picker.
    ///
    /// The file is read here rather than inside the screen so the screen has
    /// no I/O in it at all and stays testable from a `&str`. A file that
    /// cannot be read still opens the screen, carrying the reason: an empty
    /// list with an explanation beats a key that appears to do nothing.
    fn open_ssh_import(&mut self) {
        let strings = self.lang.strings();
        let read = match crate::ssh_config::default_path() {
            Some(path) => std::fs::read_to_string(&path).map_err(|e| format!("{}{e}", strings.ssh_import_error_prefix)),
            None => Err(strings.ssh_import_error_prefix.to_string()),
        };
        let (hosts, error) = match read {
            Ok(text) => (crate::ssh_config::parse(&text), None),
            Err(message) => (Vec::new(), Some(message)),
        };
        self.with_unlocked(|u| {
            let state = SshImportState::new(hosts, &u.config.servers, error);
            u.screen = Screen::SshImport(state);
        });
    }

    /// Turns picked hosts into vault entries and saves once.
    ///
    /// **A host with no `IdentityFile` becomes agent auth.** That is the honest
    /// reading of an OpenSSH block naming no key, and the only reading that
    /// stores nothing: falling back to a password would prompt for a credential
    /// the user never had, and inventing a key path would point at a file that
    /// may not exist.
    ///
    /// A failed save rolls the entries back out of memory. Leaving them would
    /// show the user a list of servers the vault does not have, which the next
    /// launch would silently contradict.
    fn import_ssh_hosts(&mut self, hosts: Vec<SshConfigHost>) {
        let strings = self.lang.strings();
        let AppState::Unlocked(u) = &mut self.state else {
            return;
        };

        let before = u.config.servers.len();
        for host in hosts {
            let username = host.username();
            let auth = match host.identity_file {
                Some(key_path) => AuthMethod::SshKey { key_path, passphrase: None },
                None => AuthMethod::Agent,
            };
            u.config.servers.push(ServerEntry::new(
                host.alias,
                host.hostname,
                host.port.unwrap_or(crate::config::model::DEFAULT_PORT),
                username,
                auth,
            ));
        }
        let imported = u.config.servers.len() - before;

        match self.store.save(&u.config, &u.master_key, &u.slots) {
            Ok(()) => {
                let mut menu = MainMenuState::new();
                menu.clamp_selection(&u.config.servers, u.config.server_sort);
                u.status = Some(StatusMessage::new(format!("{}{imported}{}", strings.status_imported_prefix, strings.status_imported_suffix)));
                u.screen = Screen::MainMenu(menu);
            }
            Err(e) => {
                u.config.servers.truncate(before);
                if let Screen::SshImport(state) = &mut u.screen {
                    state.error = Some(format!("{}{e}", strings.save_error_prefix));
                }
            }
        }
    }

    /// Back to the forwards list, whichever screen asked.
    ///
    /// The `server_id` is read off whichever forward screen is on top rather
    /// than passed around, so a cancel from the form and a "no" from the
    /// confirm land in the same place without either one carrying it.
    fn back_to_forwards(&mut self) {
        self.with_unlocked(|u| {
            let server_id = match &u.screen {
                Screen::ForwardForm(form) => Some(form.server_id),
                Screen::ConfirmDeleteForward { server_id, .. } => Some(*server_id),
                _ => None,
            };
            if let Some(server_id) = server_id {
                let name = u.config.servers.iter().find(|s| s.id == server_id).map(|e| e.name.clone()).unwrap_or_default();
                // A fresh state, so the selection starts at the top rather
                // than at a row a delete may have taken away. `clamp_selection`
                // is for the screen that stays put — see `toggle_forward`.
                u.screen = Screen::Forwards(ForwardsListState::new(server_id, name));
            }
        });
    }

    /// Turns one rule on or off and saves. A rule kept but disabled is the
    /// point of the flag — deleting one to stop it for an afternoon means
    /// retyping four fields to get it back.
    fn toggle_forward(&mut self, forward_id: Uuid) {
        self.edit_forwards(|forwards| {
            if let Some(rule) = forwards.iter_mut().find(|f| f.id == forward_id) {
                rule.enabled = !rule.enabled;
            }
        });
    }

    fn submit_forward_form(&mut self, data: ForwardFormData) {
        let server_id = match &self.state {
            AppState::Unlocked(u) => match &u.screen {
                Screen::ForwardForm(form) => Some(form.server_id),
                _ => None,
            },
            _ => None,
        };
        let Some(server_id) = server_id else { return };

        self.mutate_forwards(server_id, |forwards| match data.id {
            Some(id) => {
                if let Some(rule) = forwards.iter_mut().find(|f| f.id == id) {
                    rule.kind = data.kind.clone();
                }
            }
            None => forwards.push(ForwardRule::new(data.kind.clone())),
        });
        self.back_to_forwards();
    }

    fn confirm_delete_forward(&mut self) {
        let target = match &self.state {
            AppState::Unlocked(u) => match &u.screen {
                Screen::ConfirmDeleteForward { server_id, forward_id, .. } => Some((*server_id, *forward_id)),
                _ => None,
            },
            _ => None,
        };
        let Some((server_id, forward_id)) = target else { return };
        self.mutate_forwards(server_id, |forwards| forwards.retain(|f| f.id != forward_id));
        self.back_to_forwards();
    }

    /// Applies a change to the forwards of whichever server the current
    /// forwards screen belongs to.
    fn edit_forwards(&mut self, change: impl FnOnce(&mut Vec<ForwardRule>)) {
        let server_id = match &self.state {
            AppState::Unlocked(u) => match &u.screen {
                Screen::Forwards(list) => Some(list.server_id),
                _ => None,
            },
            _ => None,
        };
        if let Some(server_id) = server_id {
            self.mutate_forwards(server_id, change);
        }
    }

    /// One place that edits a server's forwards and saves, so every path
    /// through this screen reports a failed write the same way.
    fn mutate_forwards(&mut self, server_id: Uuid, change: impl FnOnce(&mut Vec<ForwardRule>)) {
        let strings = self.lang.strings();
        let AppState::Unlocked(u) = &mut self.state else {
            return;
        };
        let Some(entry) = u.config.servers.iter_mut().find(|s| s.id == server_id) else {
            return;
        };
        change(&mut entry.forwards);

        u.status = Some(StatusMessage::new(match self.store.save(&u.config, &u.master_key, &u.slots) {
            Ok(()) => strings.status_saved.to_string(),
            Err(e) => format!("{}{e}", strings.save_error_prefix),
        }));
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
                let mut entry = ServerEntry::new(data.name, data.host, data.port, data.username, data.auth);
                entry.tags = data.tags;
                entry.jump_host = data.jump_host;
                u.config.servers.push(entry);
            }
            FormMode::Edit(id) => {
                if let Some(entry) = u.config.servers.iter_mut().find(|s| s.id == id) {
                    entry.name = data.name;
                    entry.host = data.host;
                    entry.port = data.port;
                    entry.username = data.username;
                    entry.tags = data.tags;
                    entry.auth = data.auth;
                    entry.jump_host = data.jump_host;
                }
            }
        }

        match self.store.save(&u.config, &u.master_key, &u.slots) {
            Ok(()) => {
                let mut menu = MainMenuState::new();
                menu.clamp_selection(&u.config.servers, u.config.server_sort);
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
        // Anything that connected through it now connects direct. A `Uuid` left
        // pointing at a deleted entry is a dangling reference that nothing
        // would ever clean up, and it fails at connect time rather than here —
        // long after the user could tell what caused it.
        for entry in &mut u.config.servers {
            if entry.jump_host == Some(target) {
                entry.jump_host = None;
            }
        }

        let save_result = self.store.save(&u.config, &u.master_key, &u.slots);
        let mut menu = MainMenuState::new();
        menu.clamp_selection(&u.config.servers, u.config.server_sort);
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

    /// Stores which of the two connect modes `Enter` uses.
    ///
    /// Same shape as `set_auto_lock`, and the rollback is the point: the value
    /// is only in memory until the save succeeds, so a read-only config
    /// directory cannot leave the running app on a setting the next launch
    /// will not have.
    fn set_connect_mode(&mut self, mode: ConnectMode) {
        let strings = self.lang.strings();
        let AppState::Unlocked(u) = &mut self.state else {
            return;
        };
        let previous = u.config.connect_mode;
        u.config.connect_mode = mode;
        let result = self.store.save(&u.config, &u.master_key, &u.slots);
        if result.is_err() {
            u.config.connect_mode = previous;
        }
        if let Screen::Settings(settings) = &mut u.screen {
            match result {
                Ok(()) => settings.info = Some(strings.status_connect_mode_saved.to_string()),
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

    pub(crate) fn verify_totp_prompt(&mut self, code: &str) {
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
            menu.clamp_selection(&u.config.servers, u.config.server_sort);
            u.screen = Screen::MainMenu(menu);
        } else if let Screen::TotpPrompt(state) = &mut u.screen {
            state.error = Some(strings.err_totp_invalid_code.to_string());
        }
    }

    /// Everything a connect needs out of the vault, resolved while the entry
    /// is still borrowed.
    ///
    /// Not async and no terminal, so it can be tested — and so the borrow of
    /// `self.state` ends here rather than reaching an `.await` (the `NextStep`
    /// rule). What comes out owns its credentials and its already-expanded
    /// commands; nothing in it is a `Uuid` that would need the vault again.
    ///
    /// Shared by both connect flows because a second copy would be a second
    /// chance to forget that placeholders expand per entry, or that a bastion
    /// chain is only resolvable in here.
    fn connect_context(&self, id: Uuid) -> Option<ConnectContext> {
        let AppState::Unlocked(u) = &self.state else {
            return None;
        };
        let entry = u.config.servers.iter().find(|s| s.id == id)?;
        // Placeholders are resolved here, where the entry is still borrowed —
        // the expanded copies are what crosses the await.
        let vars = ScriptVars::from_entry(entry);
        Some(ConnectContext {
            // So is the bastion chain, and it has to be: a `Uuid` means
            // nothing once `config` is out of scope.
            target: ssh::Target::from_entry(entry, &u.config.servers),
            // `ForwardRule` holds no credential, so cloning it here costs
            // nothing worth protecting — but it has to be here all the same,
            // because `entry` is gone by the time the session is up.
            forwards: entry.forwards.clone(),
            on_connect: entry.scripts.iter().filter(|s| s.run_on_connect).map(|s| vars.expand_script(s)).collect(),
        })
    }

    /// Opens the connection and records what the handshake taught the vault.
    ///
    /// `None` means there is nothing to connect to and the reason is already
    /// on the status bar — an abandoned wait, a changed host key, a refused
    /// connection. Either way nothing was suspended and nothing was written,
    /// so there is nothing for the caller to undo.
    ///
    /// Both flows go through this so `observe_handshake` + `observe_jumps` +
    /// `record_session` stay one implementation. The fingerprint is persisted
    /// *before* the session starts: one written only at the end would re-run
    /// TOFU if the process were killed during it.
    ///
    /// The future inside borrows only `target`, which is the caller's local —
    /// `await_redrawing`'s rule that the future must not borrow `self`.
    async fn establish(&mut self, terminal: &mut TerminalGuard, id: Uuid, target: &ssh::Target) -> Option<(ssh::Connected, session::SessionRecord)> {
        let strings = self.lang.strings();

        // The list stays on screen through the handshake — a blank terminal
        // with nothing on it for up to twenty seconds was the whole of #51 —
        // and the row says which server is being reached.
        self.connecting = Some((id, Instant::now()));
        let attempt = self.await_on_screen(terminal, ssh::connect(target)).await;
        // Esc. `App::run` clears the indicator.
        let connect_result = attempt?;

        let connected = match connect_result {
            Ok(connected) => connected,
            Err(AppError::HostKeyChanged { fingerprint }) => {
                self.set_status(format!("{}{fingerprint}{}", strings.host_key_changed_prefix, strings.host_key_changed_suffix));
                return None;
            }
            Err(e) => {
                self.set_status(format!("{}{e}", strings.connect_error_prefix));
                return None;
            }
        };

        // What a connect teaches the vault is decided in one place, so
        // `cli::connect` records exactly the same things (see
        // `crate::session`).
        let record = session::observe_handshake(&connected);
        let jump_records = session::observe_jumps(&connected, &target.jump_ids);
        self.record_session(id, &record, &jump_records);
        Some((connected, record))
    }

    /// The second half of the recording: the sysinfo snapshot, once the probe
    /// that rode alongside the session has produced one.
    ///
    /// Only when it actually produced something — `apply_to` keeps the last
    /// good snapshot, so a second save would rewrite the whole vault to store
    /// nothing. That rule is here rather than in each flow because it is
    /// exactly the kind of thing a copy forgets.
    fn finish(&mut self, id: Uuid, record: &mut session::SessionRecord, info: Option<SystemInfo>) {
        record.system_info = info;
        if record.system_info.is_some() {
            // The hops were written by `establish`; there is nothing new to
            // say about them.
            self.record_session(id, record, &[]);
        }
    }

    /// The full-screen connect: the terminal is handed over and the app is off
    /// screen until the remote shell exits.
    ///
    /// The counterpart is `pane_connect_flow`. What they share is in
    /// `connect_context`, `establish` and `finish`; what differs is this
    /// suspend, and it is the whole difference between the modes.
    async fn connect_flow(&mut self, terminal: &mut TerminalGuard, id: Uuid) -> Result<()> {
        let strings = self.lang.strings();
        let Some(context) = self.connect_context(id) else {
            return Ok(());
        };
        // A chain that loops or names a deleted server fails before anything is
        // opened, and reads as a connect error like any other.
        let target = match context.target {
            Ok(target) => target,
            Err(e) => {
                self.set_status(format!("{}{e}", strings.connect_error_prefix));
                return Ok(());
            }
        };

        let established = self.establish(terminal, id, &target).await;
        let Some((connected, mut record)) = established else {
            return Ok(());
        };

        // The late suspend. The primary buffer is handed over here and not a
        // line earlier, with a shell about to land on it.
        self.connecting = None;
        terminal.suspend()?;

        // Brought up after the suspend so the report lands on the primary
        // buffer with the script output, and bound to this scope: `Forwards`
        // aborts every listener when it drops, which is the whole of the
        // teardown story. It borrows nothing from `self`, so it sits inside
        // `await_redrawing`'s rule as well as the `NextStep` one.
        let _forwards = {
            let forwards = ssh::forward::start(Arc::clone(&connected.handle), &context.forwards).await;
            session::print_forward_report(&forwards, strings);
            forwards
        };

        // Auto-run scripts flagged `run_on_connect`, printed plain to the
        // (now-suspended) primary screen buffer.
        for script in &context.on_connect {
            let mut partial = String::new();
            script_runner::run_script(&connected.handle, script, |event| {
                session::print_script_event_plain(event, strings, &mut partial);
            })
            .await;
        }

        // The probe rides *alongside* the shell rather than in front of it.
        // It is one exec channel that writes nothing to the terminal, and
        // holding an interactive session behind `EXEC_TIMEOUT` to learn a CPU
        // count is the wrong trade — the probe's values are for the detail
        // pane, and nothing needs them before the user gets their prompt.
        let (shell, info) = tokio::join!(
            ssh::pty_bridge::run_interactive(&connected.handle),
            ssh::sysinfo::fetch(&connected.handle),
        );

        terminal.resume()?;

        self.finish(id, &mut record, info.ok());

        if let AppState::Unlocked(u) = &mut self.state {
            u.status = shell.err().map(|e| StatusMessage::new(format!("{}{e}", strings.disconnected_prefix)));
        }

        Ok(())
    }

    /// Folds one session's record into its entry and persists it.
    ///
    /// Best-effort, like every save `connect_flow` makes: a read-only config
    /// directory must not stand between the user and the shell they asked for.
    fn record_session(&mut self, id: Uuid, record: &session::SessionRecord, jumps: &[session::JumpRecord]) {
        if let AppState::Unlocked(u) = &mut self.state {
            if let Some(e) = u.config.servers.iter_mut().find(|s| s.id == id) {
                record.apply_to(e);
            }
            // Folded into the same save. A save per hop would rewrite the whole
            // vault once per bastion for one field each.
            for jump in jumps {
                if let Some(e) = u.config.servers.iter_mut().find(|s| s.id == jump.server_id) {
                    jump.apply_to(e);
                }
            }
            let _ = self.store.save(&u.config, &u.master_key, &u.slots);
        }
    }

    /// Manual "run this script now" flow, triggered from the Scripts list.
    /// Unlike `connect_flow`, the terminal is never suspended — there is no
    /// PTY here, so ratatui keeps rendering throughout, and the live log
    /// screen is updated straight from `script_runner::run_script`'s
    /// `on_event` callback as it fires.
    /// Runs one script on one or more servers, in the order they were picked.
    ///
    /// **Sequential, never concurrent.** The run screen is a single stream with
    /// one scroll position and one cancel key. Interleaving several hosts into
    /// it would mean tagging every output chunk with where it came from and a
    /// cancel story per connection, for a feature whose whole point is being
    /// able to read what happened.
    ///
    /// The definition comes from `origin_server_id` — a target needs no copy of
    /// its own — but **each target expands its own placeholders**. Expanding
    /// once against the origin would send one host's name to all the others,
    /// which is exactly what `ScriptVars` exists to prevent.
    ///
    /// A plain `Enter` on the script list arrives here with a one-element
    /// `targets`, so there is one flow rather than two.
    async fn run_script_flow(
        &mut self,
        terminal: &mut TerminalGuard,
        origin_server_id: Uuid,
        script_id: Uuid,
        targets: Vec<Uuid>,
    ) -> Result<()> {
        let strings = self.lang.strings();
        // Everything that crosses the `.await` is built here, while the entries
        // are still borrowed — the `NextStep` rule. What comes out owns its
        // credentials and its already-expanded commands.
        let prepared = match &self.state {
            AppState::Unlocked(u) => {
                let origin = u.config.servers.iter().find(|s| s.id == origin_server_id);
                origin.and_then(|origin| {
                    let definition = origin.scripts.iter().find(|s| s.id == script_id)?;
                    // The `Result` rides into the loop rather than ending the
                    // whole run here: a bad jump chain on one host is exactly
                    // the same kind of problem as a host that will not answer,
                    // and that already does not stop a fleet run.
                    let runs: Vec<(String, Result<ssh::Target>, Script)> = targets
                        .iter()
                        .filter_map(|id| u.config.servers.iter().find(|s| s.id == *id))
                        .map(|e| {
                            (e.name.clone(), ssh::Target::from_entry(e, &u.config.servers), ScriptVars::from_entry(e).expand_script(definition))
                        })
                        .collect();
                    Some((origin.name.clone(), definition.name.clone(), runs))
                })
            }
            AppState::Setup(_) | AppState::Unopenable | AppState::CannotOpen { .. } | AppState::Locked(_) | AppState::LockedTotpDaily(_) => None,
        };
        let Some((origin_name, script_name, runs)) = prepared.filter(|(_, _, runs)| !runs.is_empty()) else {
            return Ok(());
        };

        let mut run_state = ScriptRunState::new(origin_server_id, script_id, origin_name, script_name, runs.len());
        let mut cancelled = false;

        for (server_name, target, script) in runs {
            run_state.server_started(&server_name);
            let target = match target {
                Ok(target) => target,
                Err(e) => {
                    run_state.server_connect_error(&format!("{e}"), strings);
                    draw_run(terminal, &mut run_state, strings);
                    continue;
                }
            };
            // Drawn before the connect, not after: a DNS lookup or a TCP
            // timeout can take seconds, and without this the screen would sit
            // on the previous host's output with no sign of which one it had
            // moved on to.
            draw_run(terminal, &mut run_state, strings);

            match ssh::connect(&target).await {
                Ok(connected) => {
                    // The events travel through a channel rather than straight
                    // into `run_state`, and that is what makes the whole thing
                    // work: the run future must not borrow the screen, or the
                    // `select!` arm that redraws and reads keys could not touch
                    // it either.
                    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
                    {
                        let mut run = std::pin::pin!(script_runner::run_script(&connected.handle, &script, move |event| {
                            let _ = tx.send(event.into_owned());
                        }));
                        loop {
                            tokio::select! {
                                // A finished run wins over a tick that came due
                                // in the same wakeup; the leftover events are
                                // drained below either way.
                                biased;
                                _ = &mut run => break,
                                Some(event) = rx.recv() => {
                                    apply_run_event(event, &mut run_state, strings);
                                    // Whatever else is already queued goes on in
                                    // the same pass — one redraw per batch
                                    // rather than one per output chunk.
                                    while let Ok(more) = rx.try_recv() {
                                        apply_run_event(more, &mut run_state, strings);
                                    }
                                    draw_run(terminal, &mut run_state, strings);
                                }
                                // Polling on a timer rather than an
                                // `EventStream`: `event::poll(ZERO)` is what
                                // `transfer_flow` already uses, needs no extra
                                // dependency, and 50 ms is well under what a
                                // keypress feels like.
                                _ = tokio::time::sleep(KEY_POLL_INTERVAL) => {
                                    if poll_run_keys(&mut run_state) {
                                        cancelled = true;
                                        break;
                                    }
                                    draw_run(terminal, &mut run_state, strings);
                                }
                            }
                        }
                    }

                    // Events the run emitted just before it ended (or before
                    // the cancel) are still in the channel. Dropping them would
                    // lose the last step's exit code.
                    while let Ok(event) = rx.try_recv() {
                        apply_run_event(event, &mut run_state, strings);
                    }
                }
                // Not fatal, and not `connect_error`: the hosts that *do*
                // answer are the reason someone started a fleet run, so an
                // unreachable one is logged and the loop moves on. A cancel is
                // the only thing that stops everything.
                Err(e) => run_state.server_connect_error(&format!("{}{e}", strings.connect_error_prefix), strings),
            }

            if cancelled {
                break;
            }
            draw_run(terminal, &mut run_state, strings);
        }

        if cancelled {
            run_state.mark_cancelled(strings);
        } else {
            run_state.mark_finished();
        }

        self.with_unlocked(|u| {
            u.screen = Screen::ScriptRun(run_state);
        });

        Ok(())
    }

    /// Advances the server list's ordering and persists it.
    ///
    /// The selection is re-anchored on the entry that was selected before the
    /// reorder, not on the index: the whole point of `selected` indexing the
    /// visible list is that a reorder moves rows out from under it, and
    /// leaving the index alone would silently select a different server.
    ///
    /// A failed save leaves the new order applied in memory. It is a display
    /// preference, and refusing to reorder because the disk is full would be a
    /// stranger outcome than forgetting it at the next unlock.
    fn cycle_server_sort(&mut self) {
        let strings = self.lang.strings();
        let saved = {
            let AppState::Unlocked(u) = &mut self.state else {
                return;
            };
            let from = u.config.server_sort;
            let to = from.next();
            u.config.server_sort = to;
            let UnlockedState { config, screen, .. } = &mut **u;
            if let Screen::MainMenu(menu) = screen {
                menu.resort(&config.servers, from, to);
            }
            self.store.save(&u.config, &u.master_key, &u.slots)
        };
        if let Err(e) = saved {
            self.set_status(format!("{}{e}", strings.save_error_prefix));
        }
    }

    /// Writes the finished run's log to `path`.
    ///
    /// Not `write_file_atomic`: that exists because the vault is rewritten on
    /// every connect and has no backup copy. A log the user just asked for at
    /// a path they typed is neither, and staging a sibling `.tmp` beside it
    /// would only add a file to explain.
    ///
    /// The result is reported on the run screen rather than through `status`,
    /// since the run screen has no status line and is what the user is looking
    /// at.
    fn save_script_log(&mut self, path: &str) {
        let strings = self.lang.strings();
        let AppState::Unlocked(u) = &mut self.state else {
            return;
        };
        let Screen::ScriptRun(state) = &mut u.screen else {
            return;
        };
        match std::fs::write(path, state.plain_text()) {
            Ok(()) => state.save_succeeded(path, strings),
            Err(e) => state.save_failed(&e.to_string(), strings),
        }
    }

    /// Opens the file browser: connect if needed, ask the server where "." is,
    /// and list both sides.
    ///
    /// Follows `run_script_flow`'s shape — everything that crosses the await is
    /// a local, and the screen is installed once the work is done. The vault's
    /// remembered directory is a convenience: if it has vanished the listing
    /// falls back to the login directory rather than opening on an error.
    async fn open_files_flow(&mut self, terminal: &mut TerminalGuard, id: Uuid) -> Result<()> {
        let strings = self.lang.strings();

        let context = match &self.state {
            AppState::Unlocked(u) => u.config.servers.iter().find(|e| e.id == id).map(|e| {
                (ssh::Target::from_entry(e, &u.config.servers), e.name.clone(), e.last_remote_dir.clone(), e.last_local_dir.clone())
            }),
            _ => None,
        };
        let Some((target, server_name, last_remote, last_local)) = context else {
            return Ok(());
        };
        let target = match target {
            Ok(target) => target,
            Err(e) => return self.fail_to_open_files(e),
        };

        // The same indicator `Enter` shows, on the same row, because `f` and
        // `Enter` differ in what they do *after* connecting and not in how
        // connecting looks. It used to be a sentence in the footer, drawn once,
        // over a flow that then read no keys at all.
        self.connecting = Some((id, Instant::now()));

        if !self.remote.as_ref().is_some_and(|r| r.server_id == id) {
            self.drop_remote();
            // Bound on its own statement rather than matched inline: the future
            // temporary would otherwise hold its borrow to the end of the
            // `match`, and no arm could move `handle` out.
            let attempt = self.await_on_screen(terminal, ssh::connect(&target)).await;
            let connected = match attempt {
                Some(Ok(connected)) => connected,
                Some(Err(e)) => return self.fail_to_open_files(e),
                // Esc, with nothing yet built to tear down.
                None => return Ok(()),
            };
            // The whole `Connected` is kept, not just its handle: it owns the
            // bastion sessions this one is tunnelled through, and dropping it
            // here would close them out from under the sftp stream.
            let opened = self.await_on_screen(terminal, sftp::open_session(&connected.handle)).await;
            match opened {
                Some(Ok(sftp)) => self.remote = Some(RemoteSession { server_id: id, connected, sftp }),
                Some(Err(e)) => return self.fail_to_open_files(e),
                None => return Ok(()),
            }
        }

        let local_cwd = last_local
            .map(PathBuf::from)
            .filter(|p| p.is_dir())
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_else(|| PathBuf::from("/"));

        // Taken out so the futures below borrow a local and the redraw can have
        // `&mut self`; put back once they are done. The same move
        // `transfer_flow` makes, for the same borrow.
        let mut session = self.remote.take().expect("just connected");
        let resolved = self.redraw_while(terminal, session.sftp.realpath(last_remote.as_deref().unwrap_or("."))).await;
        let remote_cwd = match resolved {
            Ok(path) => path,
            // The remembered directory is gone. Fall back rather than open on
            // an error — it was a convenience, not a promise.
            Err(_) => {
                let fallback = self.redraw_while(terminal, session.sftp.realpath(".")).await;
                fallback.unwrap_or_else(|_| "/".to_string())
            }
        };
        let listing = self.redraw_while(terminal, session.sftp.list_dir(&remote_cwd)).await;
        self.remote = Some(session);

        let mut browser = FileBrowserState::new(id, server_name, local_cwd, remote_cwd.clone());
        match listing {
            Ok(entries) => browser.set_remote(remote_cwd, remote_entries(entries, browser.show_hidden())),
            Err(e) => {
                self.drop_remote_if_fatal(&e);
                browser.set_remote_error(format!("{}{e}", strings.sftp_error_prefix));
            }
        }

        self.with_unlocked(|u| u.screen = Screen::FileBrowser(browser));
        Ok(())
    }

    /// Lists a remote directory into the open browser — either a new path
    /// (`Enter`, `Backspace`) or the current one again (`r`, or the hidden-file
    /// toggle).
    async fn list_remote_flow(&mut self, terminal: &mut TerminalGuard, path: Option<String>) -> Result<()> {
        let strings = self.lang.strings();

        let context = match &self.state {
            AppState::Unlocked(u) => match &u.screen {
                Screen::FileBrowser(browser) => Some((
                    path.unwrap_or_else(|| browser.remote.cwd.clone()),
                    browser.show_hidden(),
                    browser.server_id,
                )),
                _ => None,
            },
            _ => None,
        };
        let Some((path, show_hidden, server_id)) = context else {
            return Ok(());
        };

        // Without a session there is nothing to list; the browser is already
        // showing why.
        if !self.remote.as_ref().is_some_and(|r| r.server_id == server_id) {
            return Ok(());
        }

        // Redrawn through the await for the reason the connect is: `App::run` is
        // blocked in here, so a resize during a slow listing would otherwise
        // repaint nothing. Not cancellable — see `Cancel`.
        let mut session = self.remote.take().expect("checked above");
        let listing = self.redraw_while(terminal, session.sftp.list_dir(&path)).await;
        self.remote = Some(session);

        match listing {
            Ok(entries) => {
                let entries = remote_entries(entries, show_hidden);
                self.with_unlocked(|u| {
                    if let Screen::FileBrowser(browser) = &mut u.screen {
                        browser.set_remote(path, entries);
                    }
                });
            }
            Err(e) => {
                self.drop_remote_if_fatal(&e);
                let message = format!("{}{e}", strings.sftp_error_prefix);
                self.with_unlocked(|u| {
                    if let Screen::FileBrowser(browser) = &mut u.screen {
                        browser.set_remote_error(message);
                    }
                });
            }
        }
        Ok(())
    }

    /// A connection that never opened leaves the user on the server list with
    /// the reason, rather than on an empty browser that can do nothing.
    fn fail_to_open_files(&mut self, error: AppError) -> Result<()> {
        let strings = self.lang.strings();
        self.drop_remote();
        self.set_status(format!("{}{error}", strings.connect_error_prefix));
        Ok(())
    }

    /// A protocol error means the stream is desynced and a lost connection
    /// means there is nothing on the other end — both make the session
    /// unusable, while a plain "permission denied" does not.
    fn drop_remote_if_fatal(&mut self, error: &AppError) {
        let fatal = match error {
            AppError::Sftp(_) | AppError::Io(_) | AppError::Ssh(_) => true,
            AppError::SftpStatus { code, .. } => {
                *code == sftp::wire::FX_NO_CONNECTION || *code == sftp::wire::FX_CONNECTION_LOST
            }
            _ => false,
        };
        if fatal {
            self.drop_remote();
        }
    }

    fn set_status(&mut self, text: String) {
        self.with_unlocked(|u| u.status = Some(StatusMessage::new(text)));
    }

    /// Scans, asks about collisions, then moves the bytes.
    ///
    /// The three phases are deliberate. Scanning first is what makes a real
    /// percentage possible, and resolving every collision *before* the copy
    /// starts means the byte loop never has to stop for a question — a prompt
    /// in the middle of it would have to run while a `&mut SftpClient` is held
    /// over a half-written file.
    async fn transfer_flow(&mut self, terminal: &mut TerminalGuard) -> Result<()> {
        let strings = self.lang.strings();

        // Everything that crosses the await is taken out as a local first, the
        // screen included — same as `run_script_flow`.
        let Some(mut browser) = self.take_browser() else {
            return Ok(());
        };
        let (side, dest) = browser.direction();
        let sources: Vec<(String, bool)> = browser
            .pane(side)
            .transfer_selection()
            .into_iter()
            .map(|e| (join_for(side, &browser.pane(side).cwd, &e.name), e.is_dir))
            .collect();

        if sources.is_empty() || self.remote.as_ref().is_none_or(|r| r.server_id != browser.server_id) {
            browser.status = Some(strings.transfer_nothing_selected.to_string());
            self.put_browser(browser);
            return Ok(());
        }

        let direction = match side {
            Side::Local => transfer::Direction::Upload,
            Side::Remote => transfer::Direction::Download,
        };
        let title = match direction {
            transfer::Direction::Upload => strings.transfer_title_upload,
            transfer::Direction::Download => strings.transfer_title_download,
        };

        let mut session = self.remote.take().expect("checked above");
        let outcome = run_transfer(&mut session.sftp, terminal, &mut browser, direction, &sources, &dest, title, strings).await;
        self.remote = Some(session);

        let status = match outcome {
            Ok(summary) => Some(summarize(&summary, strings)),
            Err(e) => {
                self.drop_remote_if_fatal(&e);
                Some(format!("{}{e}", strings.sftp_error_prefix))
            }
        };

        // Both sides may have changed: the destination has new files, and the
        // source is where a failed `.part` would have been cleaned up.
        browser.progress = None;
        browser.status = status;
        browser.reload_local();
        let refresh = browser.remote.cwd.clone();
        self.put_browser(browser);
        self.list_remote_flow(terminal, Some(refresh)).await
    }

    /// Takes the browser out of the screen so it can be borrowed across an
    /// await. The screen is left on the menu only if something goes wrong
    /// before `put_browser` runs, which no path does.
    fn take_browser(&mut self) -> Option<FileBrowserState> {
        let AppState::Unlocked(u) = &mut self.state else {
            return None;
        };
        match std::mem::replace(&mut u.screen, Screen::MainMenu(MainMenuState::new())) {
            Screen::FileBrowser(browser) => Some(browser),
            other => {
                u.screen = other;
                None
            }
        }
    }

    fn put_browser(&mut self, browser: FileBrowserState) {
        self.with_unlocked(|u| u.screen = Screen::FileBrowser(browser));
    }

    /// Remembers where both panes were pointed, so the next visit starts there.
    ///
    /// Saved on the way out rather than on every `cd`: a save re-encrypts and
    /// rewrites the whole vault, which is far too much work for a keystroke.
    /// Best-effort, like the saves `connect_flow` makes.
    fn remember_browser_dirs(&mut self) {
        let dirs = match &self.state {
            AppState::Unlocked(u) => match &u.screen {
                Screen::FileBrowser(browser) => {
                    Some((browser.server_id, browser.local.cwd.clone(), browser.remote.cwd.clone()))
                }
                _ => None,
            },
            _ => None,
        };
        let Some((server_id, local, remote)) = dirs else {
            return;
        };

        if let AppState::Unlocked(u) = &mut self.state
            && let Some(entry) = u.config.servers.iter_mut().find(|e| e.id == server_id)
        {
            entry.last_local_dir = Some(local);
            entry.last_remote_dir = Some(remote);
            let _ = self.store.save(&u.config, &u.master_key, &u.slots);
        }
    }

}

/// Joins a selected name onto its pane's directory, on whichever side it came
/// from: remote paths are always `/`-separated, local ones go through `Path`.
fn join_for(side: Side, cwd: &str, name: &str) -> String {
    match side {
        Side::Remote => crate::tui::file_browser::remote_join(cwd, name),
        Side::Local => PathBuf::from(cwd).join(name).to_string_lossy().into_owned(),
    }
}

/// One line describing what a finished run did.
fn summarize(summary: &transfer::TransferSummary, strings: &Strings) -> String {
    if summary.cancelled && summary.files == 0 {
        return strings.transfer_cancelled.to_string();
    }
    let mut text = format!(
        "{}{}{}{}",
        strings.transfer_done_prefix,
        summary.files,
        strings.transfer_done_separator,
        crate::tui::widgets::format_size(summary.bytes)
    );
    if summary.cancelled {
        text.push_str(" — ");
        text.push_str(strings.transfer_cancelled);
    }
    if let Some(first) = summary.failures.first() {
        text.push_str(" — ");
        text.push_str(strings.transfer_failed_prefix);
        text.push_str(first);
        if summary.failures.len() > 1 {
            text.push_str(&format!(" (+{})", summary.failures.len() - 1));
        }
    }
    text
}


/// Drives one transfer: scan, ask about collisions, copy.
///
/// Free-standing rather than a method because it borrows the sftp session and
/// the screen state as plain locals — both were taken out of `self` before the
/// first await, which is what keeps the `NextStep` rule intact.
#[allow(clippy::too_many_arguments, reason = "every argument is already a local the flow had to take out of self")]
async fn run_transfer(
    sftp: &mut sftp::SftpClient<russh::ChannelStream<russh::client::Msg>>,
    terminal: &mut TerminalGuard,
    browser: &mut FileBrowserState,
    direction: transfer::Direction,
    sources: &[(String, bool)],
    dest: &str,
    title: &'static str,
    strings: &'static Strings,
) -> Result<transfer::TransferSummary> {
    // Phase 1: the walk. It can take a while on a deep tree, so it reports as
    // it goes and can be cancelled like the copy itself.
    browser.progress = Some(TransferProgress {
        title: title.to_string(),
        name: String::new(),
        file_index: 0,
        file_count: 0,
        done_bytes: 0,
        total_bytes: 0,
        scanning: true,
    });

    let mut cancelled = false;
    let mut last_draw = Instant::now();
    let plan = transfer::plan(sftp, direction, sources, dest, |event| {
        if let transfer::TransferEvent::Scanning { files, bytes } = event
            && let Some(progress) = &mut browser.progress
        {
            progress.file_count = files;
            progress.total_bytes = bytes;
        }
        if redraw_and_poll_cancel(terminal, browser, strings, &mut last_draw, true) {
            cancelled = true;
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    })
    .await;

    if cancelled {
        return Ok(transfer::TransferSummary { cancelled: true, ..Default::default() });
    }
    let mut plan = plan?;

    // Phase 2: every collision is settled before a byte moves.
    if !resolve_conflicts(terminal, browser, &mut plan, strings)? {
        return Ok(transfer::TransferSummary { cancelled: true, ..Default::default() });
    }

    // Phase 3: the bytes.
    let total_bytes = plan.planned_bytes();
    let file_count = plan.file_count();
    if let Some(progress) = &mut browser.progress {
        progress.scanning = false;
        progress.total_bytes = total_bytes;
        progress.file_count = file_count;
        progress.file_index = 0;
        progress.done_bytes = 0;
    }

    let mut last_draw = Instant::now();
    let summary = transfer::run(sftp, direction, &plan, |event| {
        if let Some(progress) = &mut browser.progress {
            match event {
                transfer::TransferEvent::ItemStarted { name, .. } => {
                    progress.name = name.to_string();
                    progress.file_index += 1;
                }
                transfer::TransferEvent::Progress { done_bytes } => progress.done_bytes = done_bytes,
                _ => {}
            }
        }
        if redraw_and_poll_cancel(terminal, browser, strings, &mut last_draw, false) {
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    })
    .await;

    Ok(summary)
}

/// Redraws at most every `REDRAW_INTERVAL`, but polls for a cancel key every
/// single time.
///
/// The two are deliberately on different clocks: a 32 KiB chunk on a LAN would
/// otherwise redraw thousands of times a second, while `poll(ZERO)` is one
/// cheap syscall and Esc has to feel immediate.
fn redraw_and_poll_cancel(
    terminal: &mut TerminalGuard,
    browser: &mut FileBrowserState,
    strings: &Strings,
    last_draw: &mut Instant,
    force: bool,
) -> bool {
    const REDRAW_INTERVAL: Duration = Duration::from_millis(50);

    if force || last_draw.elapsed() >= REDRAW_INTERVAL {
        *last_draw = Instant::now();
        let _ = terminal.terminal.draw(|frame| {
            let area = frame.area();
            chrome::paint_background(frame, area);
            browser.render(frame, area, strings);
        });
    }
    cancel_requested()
}

/// Drains whatever the user typed during a transfer, looking for Esc or
/// Ctrl+C. These keystrokes never reach `App::run` — it is blocked inside the
/// flow's await — so they have to be read here or not at all.
fn cancel_requested() -> bool {
    let mut cancel = false;
    while event::poll(Duration::ZERO).unwrap_or(false) {
        match event::read() {
            Ok(Event::Key(key)) if key.kind == KeyEventKind::Press => {
                let ctrl_c = key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL);
                if key.code == KeyCode::Esc || ctrl_c {
                    cancel = true;
                }
            }
            // Resizes and mouse events are drained rather than left to pile up
            // behind the transfer.
            Ok(_) => {}
            Err(_) => break,
        }
    }
    cancel
}

/// Asks about every file that would be replaced. Returns `false` if the user
/// cancelled the whole transfer.
///
/// A blocking `event::read()` is right here: the run loop is not running, and
/// this is the one moment the flow genuinely has nothing to do but wait.
fn resolve_conflicts(
    terminal: &mut TerminalGuard,
    browser: &mut FileBrowserState,
    plan: &mut transfer::TransferPlan,
    strings: &Strings,
) -> Result<bool> {
    let conflicts = plan.conflicts();
    let mut sticky: Option<Decision> = None;

    for (position, index) in conflicts.iter().enumerate() {
        let remaining = conflicts.len() - position;
        let decision = match sticky {
            Some(decision) => decision,
            None => {
                let name = plan.items[*index].display_name().to_string();
                let mut prompt = OverwriteState::new(name, remaining);
                loop {
                    let _ = terminal.terminal.draw(|frame| {
                        let area = frame.area();
                        chrome::paint_background(frame, area);
                        browser.render(frame, area, strings);
                        prompt.render(frame, area, strings);
                    });

                    let Event::Key(key) = event::read().map_err(AppError::Io)? else {
                        continue;
                    };
                    if key.kind != KeyEventKind::Press {
                        continue;
                    }
                    match prompt.handle_key(key) {
                        OverwriteChoice::None => continue,
                        OverwriteChoice::Cancel => return Ok(false),
                        OverwriteChoice::Overwrite => {
                            if prompt.apply_to_all {
                                sticky = Some(Decision::Overwrite);
                            }
                            break Decision::Overwrite;
                        }
                        OverwriteChoice::Skip => {
                            if prompt.apply_to_all {
                                sticky = Some(Decision::Skip);
                            }
                            break Decision::Skip;
                        }
                    }
                }
            }
        };

        if decision == Decision::Skip {
            plan.items[*index].skip = Some(transfer::SkipReason::Exists);
        }
    }
    Ok(true)
}

/// Server entries as browser rows, applying the same dotfile filter the local
/// side uses — both panes hide hidden files together or neither does.
fn remote_entries(entries: Vec<sftp::RemoteEntry>, show_hidden: bool) -> Vec<BrowserEntry> {
    entries
        .into_iter()
        .filter(|e| show_hidden || !e.name.starts_with('.'))
        .map(|e| BrowserEntry { is_dir: e.is_dir(), name: e.name, size: e.size })
        .collect()
}

/// Whether `Esc` may drop the future being awaited.
///
/// `Allowed` is right for a handshake: dropping `ssh::connect` mid-flight
/// leaves nothing behind but a closed socket. `Refused` is for sftp — the
/// client keeps exactly one request in flight and has no reader task to drain
/// a reply nobody read (see `ssh::sftp`), so abandoning one desyncs every
/// request after it, and the next reply arrives bearing the wrong id.
#[derive(Clone, Copy, PartialEq)]
enum Cancel {
    Allowed,
    Refused,
}

/// How often the run loop looks for a keypress while a step is running.
///
/// The events a script emits are not a heartbeat — `sleep 300` produces none
/// at all — so a callback-driven cancel like `transfer_flow`'s cannot work
/// here. This tick is what makes Esc reachable during a step that says nothing.
///
/// `App::await_redrawing` runs on it too, for the same reason: a handshake
/// produces no events either.
const KEY_POLL_INTERVAL: Duration = Duration::from_millis(50);

fn apply_run_event(event: OwnedRunEvent, run_state: &mut ScriptRunState, strings: &'static Strings) {
    match event {
        OwnedRunEvent::StepStarted { command } => run_state.step_started(&command),
        OwnedRunEvent::Output { chunk } => run_state.output(&chunk),
        OwnedRunEvent::StepFinished { exit_code } => run_state.step_finished(exit_code, strings),
        OwnedRunEvent::StepSkipped => run_state.step_skipped(strings),
        OwnedRunEvent::StepError { message } => run_state.step_error(&message, strings),
        OwnedRunEvent::StepTimedOut { seconds } => run_state.step_timed_out(seconds, strings),
    }
}

fn draw_run(terminal: &mut TerminalGuard, run_state: &mut ScriptRunState, strings: &'static Strings) {
    let _ = terminal.terminal.draw(|frame| {
        let area = frame.area();
        chrome::paint_background(frame, area);
        run_state.render(frame, area, strings);
    });
}

/// Drains what the user typed during a step: `true` if they asked to stop.
///
/// Everything else goes to `ScriptRunState::handle_key`, which is what finally
/// makes that screen's scrolling reachable during a run — until now `App::run`
/// was blocked inside this flow, so those keys sat in the terminal buffer and
/// replayed against the script list once it returned.
fn is_cancel_key(key: KeyEvent) -> bool {
    key.code == KeyCode::Esc || (key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL))
}

fn poll_run_keys(run_state: &mut ScriptRunState) -> bool {
    let mut cancel = false;
    while event::poll(Duration::ZERO).unwrap_or(false) {
        match event::read() {
            Ok(Event::Key(key)) if key.kind == KeyEventKind::Press => {
                if is_cancel_key(key) {
                    cancel = true;
                } else {
                    // The close keys are gated on `finished`, so a stray Enter
                    // cannot dismiss a run that is still going.
                    let _ = run_state.handle_key(key);
                }
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    cancel
}


/// The state-machine tests live in `src/app/tests.rs` rather than under
/// `tests/`: an integration test only ever sees the crate's `pub` API, and
/// `AppState` / `Screen` / `NextStep` are `pub(crate)` on purpose.
#[cfg(test)]
mod tests;
