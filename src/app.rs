use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyEvent, KeyEventKind};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::config::store::{ConfigStore, Unlocked};
use crate::config::{Config, Script, ServerEntry, TotpConfig};
use crate::crypto::kdf::{KEY_LEN, KdfParams, SALT_LEN};
use crate::crypto::{cipher, kdf};
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
use crate::tui::totp_prompt::{TotpPromptOutcome, TotpPromptState};
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

struct UnlockedState {
    config: Config,
    key: Zeroizing<[u8; KEY_LEN]>,
    salt: [u8; SALT_LEN],
    params: KdfParams,
    screen: Screen,
    status: Option<String>,
}

enum AppState {
    Locked(UnlockState),
    /// "TOTP-only" mode: no password is ever asked, the sibling
    /// `totp-only.secret` file exists. See `crate::totp::AuthMode::TotpOnly`
    /// for the (reduced) threat model this mode provides.
    LockedTotpOnly(TotpUnlockState),
    /// Boxed so the enum isn't sized by its largest variant — the locked
    /// variants are tiny and this one carries the whole decrypted config.
    Unlocked(Box<UnlockedState>),
}

/// Actions resolved from a key event before any `.await` point, so no borrow
/// of `self.state` needs to be held across the async `connect_flow`.
enum NextStep {
    None,
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
    EnableTwoFactor(String),
    DisableTwoFactor,
    EnableTotpOnly(String),
    SwitchToPassword(Zeroizing<String>),
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

impl App {
    pub fn new(store: ConfigStore) -> Self {
        let lang = Lang::load_from_file(&store.prefs_path());
        let state = if store.totp_only_secret_exists() {
            AppState::LockedTotpOnly(TotpUnlockState::new())
        } else {
            let mode = if store.exists() { UnlockMode::Unlock } else { UnlockMode::FirstRun };
            AppState::Locked(UnlockState::new(mode))
        };
        Self { store, state, lang, should_quit: false, last_activity: Instant::now() }
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

            self.auto_lock_if_idle();
        }
        Ok(())
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
            AppState::LockedTotpOnly(totp_unlock) => totp_unlock.info = Some(message),
            AppState::Unlocked(_) => {}
        }
    }

    /// The locked state this vault should return to. A TOTP-only vault is
    /// encrypted under its TOTP secret, not a password, so sending it to the
    /// password screen would leave it unopenable until restart — every path
    /// back to "locked" must go through here rather than naming a variant.
    fn locked_state(&self) -> AppState {
        if self.store.totp_only_secret_exists() {
            AppState::LockedTotpOnly(TotpUnlockState::new())
        } else {
            AppState::Locked(UnlockState::new(UnlockMode::Unlock))
        }
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
            AppState::LockedTotpOnly(totp_unlock) => {
                terminal.terminal.draw(|frame| {
                    let area = frame.area();
                    totp_unlock.render(frame, area, strings);
                })?;
            }
            AppState::Unlocked(u) => {
                let status = u.status.clone();
                let config = &u.config;
                match &mut u.screen {
                    Screen::MainMenu(state) => {
                        terminal.terminal.draw(|frame| {
                            let area = frame.area();
                            state.render(frame, area, &config.servers, status.as_deref(), strings);
                        })?;
                    }
                    Screen::ServerForm(state) => {
                        terminal.terminal.draw(|frame| {
                            let area = frame.area();
                            state.render(frame, area, strings);
                        })?;
                    }
                    Screen::ConfirmDelete { state, .. } => {
                        terminal.terminal.draw(|frame| {
                            let area = frame.area();
                            state.render(frame, area, strings);
                        })?;
                    }
                    Screen::Settings(state) => {
                        terminal.terminal.draw(|frame| {
                            let area = frame.area();
                            state.render(frame, area, strings);
                        })?;
                    }
                    Screen::TotpPrompt(state) => {
                        terminal.terminal.draw(|frame| {
                            let area = frame.area();
                            state.render(frame, area, strings);
                        })?;
                    }
                    Screen::Scripts(state) => {
                        let scripts = config
                            .servers
                            .iter()
                            .find(|s| s.id == state.server_id)
                            .map(|s| s.scripts.as_slice())
                            .unwrap_or(&[]);
                        terminal.terminal.draw(|frame| {
                            let area = frame.area();
                            state.render(frame, area, scripts, status.as_deref(), strings);
                        })?;
                    }
                    Screen::ScriptForm(state) => {
                        terminal.terminal.draw(|frame| {
                            let area = frame.area();
                            state.render(frame, area, strings);
                        })?;
                    }
                    Screen::ConfirmDeleteScript { state, .. } => {
                        terminal.terminal.draw(|frame| {
                            let area = frame.area();
                            state.render(frame, area, strings);
                        })?;
                    }
                    Screen::ScriptRun(state) => {
                        terminal.terminal.draw(|frame| {
                            let area = frame.area();
                            state.render(frame, area, strings);
                        })?;
                    }
                }
            }
        }
        Ok(())
    }

    async fn handle_key(&mut self, key: KeyEvent, terminal: &mut TerminalGuard) -> Result<()> {
        match &mut self.state {
            AppState::Locked(unlock) => match unlock.handle_key(key, self.lang.strings()) {
                UnlockOutcome::None => {}
                UnlockOutcome::Quit => self.should_quit = true,
                UnlockOutcome::SetPassword(password) => self.try_unlock(&password, true),
                UnlockOutcome::TryPassword(password) => self.try_unlock(&password, false),
            },
            AppState::LockedTotpOnly(totp_unlock) => match totp_unlock.handle_key(key) {
                TotpUnlockOutcome::None => {}
                TotpUnlockOutcome::Quit => self.should_quit = true,
                TotpUnlockOutcome::Submit(code) => self.try_totp_only_unlock(&code),
            },
            AppState::Unlocked(_) => self.handle_unlocked_key(key, terminal).await?,
        }
        Ok(())
    }

    fn try_unlock(&mut self, password: &str, first_run: bool) {
        let result = if first_run { self.store.init(password) } else { self.store.load(password) };
        match result {
            Ok(unlocked) => self.enter_unlocked(unlocked),
            Err(e) => {
                if let AppState::Locked(unlock) = &mut self.state {
                    unlock.error = Some(e.to_string());
                }
            }
        }
    }

    /// TOTP-only mode: no password exists at all — the secret string itself
    /// is used wherever `derive_key` would normally take a password (see
    /// `ConfigStore::load`, which is generic over "some string + salt").
    fn try_totp_only_unlock(&mut self, code: &str) {
        let Ok(secret) = self.store.read_totp_only_secret() else {
            if let AppState::LockedTotpOnly(totp_unlock) = &mut self.state {
                totp_unlock.error = Some(self.lang.strings().err_totp_invalid_code.to_string());
            }
            return;
        };

        if !totp::verify_code(&secret, code) {
            if let AppState::LockedTotpOnly(totp_unlock) = &mut self.state {
                totp_unlock.error = Some(self.lang.strings().err_totp_invalid_code.to_string());
            }
            return;
        }

        match self.store.load(&secret) {
            Ok(unlocked) => self.enter_unlocked(unlocked),
            // The code was valid but the secret does not open the vault, so
            // the secret file and the config disagree — the only way that
            // happens is a mode switch interrupted between its two writes
            // (see `enable_totp_only`). Drop the stale secret file and fall
            // back to the master password, which is what the config is still
            // encrypted under. Without this the vault would be unopenable.
            Err(AppError::WrongPasswordOrCorrupt) => {
                self.store.discard_totp_only_secret();
                let mut unlock = UnlockState::new(UnlockMode::Unlock);
                unlock.error = Some(self.lang.strings().err_totp_only_vault_mismatch.to_string());
                self.state = AppState::Locked(unlock);
            }
            Err(e) => {
                if let AppState::LockedTotpOnly(totp_unlock) = &mut self.state {
                    totp_unlock.error = Some(e.to_string());
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
        let Unlocked { config, key, salt, params } = unlocked;
        let screen = if config.totp.is_some() {
            Screen::TotpPrompt(TotpPromptState::new())
        } else {
            Screen::MainMenu(MainMenuState::new())
        };
        self.state = AppState::Unlocked(Box::new(UnlockedState { config, key, salt, params, screen, status: None }));
    }

    async fn handle_unlocked_key(&mut self, key: KeyEvent, terminal: &mut TerminalGuard) -> Result<()> {
        let strings = self.lang.strings();
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
                    SettingsOutcome::EnableTwoFactor { secret_base32 } => NextStep::EnableTwoFactor(secret_base32),
                    SettingsOutcome::DisableTwoFactor => NextStep::DisableTwoFactor,
                    SettingsOutcome::EnableTotpOnly { secret_base32 } => NextStep::EnableTotpOnly(secret_base32),
                    SettingsOutcome::SwitchToPassword { new } => NextStep::SwitchToPassword(new),
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
                },
            }
        };

        match next {
            NextStep::None => {}
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
                    u.screen = Screen::Settings(SettingsState::new(lang, auth_mode, auto_lock_minutes));
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
            NextStep::EnableTwoFactor(secret_base32) => self.enable_two_factor(secret_base32),
            NextStep::DisableTwoFactor => self.disable_two_factor(),
            NextStep::EnableTotpOnly(secret_base32) => self.enable_totp_only(secret_base32)?,
            NextStep::SwitchToPassword(new) => self.switch_to_password(&new)?,
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
    fn current_auth_mode(&self) -> AuthMode {
        if self.store.totp_only_secret_exists() {
            return AuthMode::TotpOnly;
        }
        match &self.state {
            AppState::Unlocked(u) if u.config.totp.is_some() => AuthMode::TwoFactor,
            _ => AuthMode::Password,
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

        match self.store.save(&u.config, &u.key, &u.salt, u.params) {
            Ok(()) => {
                let mut menu = MainMenuState::new();
                menu.clamp_selection(&u.config.servers);
                u.status = Some(strings.status_saved.to_string());
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

        let save_result = self.store.save(&u.config, &u.key, &u.salt, u.params);
        let mut menu = MainMenuState::new();
        menu.clamp_selection(&u.config.servers);
        u.status = Some(match save_result {
            Ok(()) => strings.status_deleted.to_string(),
            Err(e) => format!("{}{e}", strings.delete_error_prefix),
        });
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

        match self.store.save(&u.config, &u.key, &u.salt, u.params) {
            Ok(()) => {
                let mut list = ScriptsListState::new(server_id, server_name);
                if let Some(entry) = u.config.servers.iter().find(|s| s.id == server_id) {
                    list.clamp_selection(&entry.scripts);
                }
                u.status = Some(strings.status_script_saved.to_string());
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

        let save_result = self.store.save(&u.config, &u.key, &u.salt, u.params);
        let server_name = u.config.servers.iter().find(|s| s.id == server_id).map(|e| e.name.clone()).unwrap_or_default();
        let mut list = ScriptsListState::new(server_id, server_name);
        if let Some(entry) = u.config.servers.iter().find(|s| s.id == server_id) {
            list.clamp_selection(&entry.scripts);
        }
        u.status = Some(match save_result {
            Ok(()) => strings.status_script_deleted.to_string(),
            Err(e) => format!("{}{e}", strings.delete_error_prefix),
        });
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

        let candidate = kdf::derive_key(current, &u.salt, u.params)?;
        if *candidate != *u.key {
            settings.error = Some(strings.err_current_password_wrong.to_string());
            return Ok(());
        }

        let new_salt = cipher::random_salt()?;
        let new_params = KdfParams::INTERACTIVE;
        let new_key = kdf::derive_key(new, &new_salt, new_params)?;

        match self.store.save(&u.config, &new_key, &new_salt, new_params) {
            Ok(()) => {
                u.key = new_key;
                u.salt = new_salt;
                u.params = new_params;
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
        let result = self.store.save(&u.config, &u.key, &u.salt, u.params);
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

    /// Enables "Password + TOTP (2FA)": the secret rides inside the
    /// already-encrypted config blob, so this is just a field update + save,
    /// no re-encryption needed (same key/salt as before).
    fn enable_two_factor(&mut self, secret_base32: String) {
        let strings = self.lang.strings();
        let AppState::Unlocked(u) = &mut self.state else {
            return;
        };
        u.config.totp = Some(TotpConfig { secret_base32 });
        let result = self.store.save(&u.config, &u.key, &u.salt, u.params);
        if let Screen::Settings(settings) = &mut u.screen {
            match result {
                Ok(()) => {
                    settings.set_auth_mode(AuthMode::TwoFactor);
                    settings.info = Some(strings.status_2fa_enabled.to_string());
                }
                Err(e) => settings.error = Some(format!("{}{e}", strings.save_error_prefix)),
            }
        }
    }

    fn disable_two_factor(&mut self) {
        let strings = self.lang.strings();
        let AppState::Unlocked(u) = &mut self.state else {
            return;
        };
        u.config.totp = None;
        let result = self.store.save(&u.config, &u.key, &u.salt, u.params);
        if let Screen::Settings(settings) = &mut u.screen {
            match result {
                Ok(()) => {
                    settings.set_auth_mode(AuthMode::Password);
                    settings.info = Some(strings.status_2fa_disabled.to_string());
                }
                Err(e) => settings.error = Some(format!("{}{e}", strings.save_error_prefix)),
            }
        }
    }

    /// Switches the vault to "TOTP-only" mode: the config is re-encrypted
    /// under a key derived from the TOTP secret itself (same `kdf::derive_key`
    /// used for passwords — the secret string just takes the password's
    /// place), and the secret is written in the clear to the sibling
    /// `totp-only.secret` file so it's readable before any user input. This
    /// is the accepted tradeoff of this mode, not an oversight.
    ///
    /// Ordering matters: the secret file is written *first* because it is the
    /// only cheaply reversible half of the switch. If re-encrypting then
    /// fails, deleting it puts the vault back exactly where it started. The
    /// reverse order has no such recovery — a config already re-encrypted
    /// under a secret that never reached disk would be unopenable forever.
    fn enable_totp_only(&mut self, secret_base32: String) -> Result<()> {
        let strings = self.lang.strings();
        let AppState::Unlocked(u) = &mut self.state else {
            return Ok(());
        };

        let new_salt = cipher::random_salt()?;
        let new_params = KdfParams::INTERACTIVE;
        let new_key = kdf::derive_key(&secret_base32, &new_salt, new_params)?;
        let previous_totp = u.config.totp.take();

        let result = self
            .store
            .write_totp_only_secret(&secret_base32)
            .and_then(|()| self.store.save(&u.config, &new_key, &new_salt, new_params));

        match result {
            Ok(()) => {
                u.key = new_key;
                u.salt = new_salt;
                u.params = new_params;
                if let Screen::Settings(settings) = &mut u.screen {
                    settings.set_auth_mode(AuthMode::TotpOnly);
                    settings.info = Some(strings.status_totp_only_enabled.to_string());
                }
            }
            Err(e) => {
                // Roll back both halves: the on-disk config was never
                // replaced (writes are atomic), so dropping the secret file
                // and restoring the in-memory 2FA field leaves the vault
                // byte-for-byte as it was before this attempt.
                self.store.discard_totp_only_secret();
                u.config.totp = previous_totp;
                if let Screen::Settings(settings) = &mut u.screen {
                    settings.error = Some(format!("{}{e}", strings.save_error_prefix));
                }
            }
        }
        Ok(())
    }

    /// Switches a "TOTP-only" vault back to normal password protection: a
    /// fresh salt + password-derived key re-encrypts the config, and the
    /// sibling secret file is removed so the app goes back to asking for a
    /// password on the next launch.
    ///
    /// The secret file is stashed (renamed aside) before re-encrypting rather
    /// than deleted after it, so a failed save can put it back. Leaving the
    /// file in place while the config moves to a password key would strand
    /// the vault: the next launch would see TOTP-only mode and unlock with a
    /// secret that no longer opens anything.
    fn switch_to_password(&mut self, new_password: &str) -> Result<()> {
        let strings = self.lang.strings();
        let AppState::Unlocked(u) = &mut self.state else {
            return Ok(());
        };

        let new_salt = cipher::random_salt()?;
        let new_params = KdfParams::INTERACTIVE;
        let new_key = kdf::derive_key(new_password, &new_salt, new_params)?;

        let stashed = match self.store.stash_totp_only_secret() {
            Ok(stashed) => stashed,
            Err(e) => {
                if let Screen::Settings(settings) = &mut u.screen {
                    settings.error = Some(format!("{}{e}", strings.save_error_prefix));
                }
                return Ok(());
            }
        };

        match self.store.save(&u.config, &new_key, &new_salt, new_params) {
            Ok(()) => {
                self.store.discard_stashed_totp_only_secret();
                u.key = new_key;
                u.salt = new_salt;
                u.params = new_params;
                if let Screen::Settings(settings) = &mut u.screen {
                    settings.set_auth_mode(AuthMode::Password);
                    settings.info = Some(strings.status_switched_to_password.to_string());
                }
            }
            Err(e) => {
                if stashed {
                    let _ = self.store.restore_totp_only_secret();
                }
                if let Screen::Settings(settings) = &mut u.screen {
                    settings.error = Some(format!("{}{e}", strings.save_error_prefix));
                }
            }
        }
        Ok(())
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

        if totp::verify_code(&totp_config.secret_base32, code) {
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
            AppState::Locked(_) | AppState::LockedTotpOnly(_) => None,
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
                        let _ = self.store.save(&u.config, &u.key, &u.salt, u.params);
                    }

                // Best-effort: a probe failure (restricted shell, no tools
                // installed, timeout) never blocks the interactive session.
                if let Ok(info) = ssh::sysinfo::fetch(&mut connected.handle).await
                    && let AppState::Unlocked(u) = &mut self.state {
                        if let Some(e) = u.config.servers.iter_mut().find(|s| s.id == id) {
                            e.system_info = Some(info);
                        }
                        let _ = self.store.save(&u.config, &u.key, &u.salt, u.params);
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
            u.status = status_msg;
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
            AppState::Locked(_) | AppState::LockedTotpOnly(_) => None,
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
    }
    let _ = out.flush();
}
