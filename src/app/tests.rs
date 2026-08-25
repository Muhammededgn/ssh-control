//! Transitions of the app state machine.
//!
//! In-crate rather than under `tests/`: an integration test only sees the
//! crate's `pub` surface, and `AppState`, `Screen` and `NextStep` are
//! `pub(crate)` precisely because nothing outside should name them.
//!
//! **Every fixture here is a password-only vault, and that is load-bearing.**
//! `resolve_initial_state` only reaches for the OS credential store when the
//! vault carries a device slot, and `reconcile_device_state` returns early
//! without one — so nothing in this file touches the user's real keyring. A
//! test that needed a device slot would not be hermetic and does not belong
//! here.

use super::*;
use crate::config::model::{AuthMethod, ServerEntry, SystemInfo};
use crate::tui::server_form::ServerFormData;

const PASSWORD: &str = "correct horse battery";

/// A vault on disk plus an `App` sitting on its lock screen.
///
/// The store that writes the vault is dropped before the `App` is built, and
/// that is not tidiness: `VaultLock` holds an `flock` in a `File` owned by the
/// `ConfigStore` (`config::lock`), and `flock` conflicts between two
/// descriptors on the same file *within one process*. A store still alive here
/// would make the `App` report `VaultInUse` instead of opening.
fn password_vault(f: impl FnOnce(&mut Config)) -> (tempfile::TempDir, App) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("config.enc");
    {
        let store = ConfigStore::new(path.clone());
        let mut unlocked = store.init(PASSWORD).expect("init");
        f(&mut unlocked.config);
        store.save(&unlocked.config, &unlocked.master_key, &unlocked.slots).expect("save");
    }
    let app = App::new(ConfigStore::new(path));
    (dir, app)
}

fn entry(name: &str) -> ServerEntry {
    ServerEntry::new(name.to_string(), format!("{name}.example.com"), 22, "root".to_string(), AuthMethod::password("hunter2"))
}

fn char_key(c: char) -> KeyEvent {
    KeyEvent::from(KeyCode::Char(c))
}

/// Drives one key through the unlocked half of the machine, the way
/// `handle_unlocked_key` does minus the six flows that need a terminal.
fn press(app: &mut App, key: KeyEvent) {
    let next = app.resolve_next_step(key);
    app.apply_local_step(next).expect("a local step never fails");
}

fn type_password(app: &mut App, password: &str) {
    for c in password.chars() {
        app.handle_locked_key(char_key(c));
    }
    app.handle_locked_key(KeyEvent::from(KeyCode::Enter));
}

fn unlocked(app: &App) -> &UnlockedState {
    match &app.state {
        AppState::Unlocked(u) => u,
        _ => panic!("expected an unlocked vault"),
    }
}

fn screen_name(app: &App) -> &'static str {
    match &app.state {
        AppState::Setup(_) => "Setup",
        AppState::Locked(_) => "Locked",
        AppState::LockedTotpDaily(_) => "LockedTotpDaily",
        AppState::Unopenable => "Unopenable",
        AppState::CannotOpen { .. } => "CannotOpen",
        AppState::Unlocked(u) => match u.screen {
            Screen::MainMenu(_) => "MainMenu",
            Screen::ServerForm(_) => "ServerForm",
            Screen::ConfirmDelete { .. } => "ConfirmDelete",
            Screen::Settings(_) => "Settings",
            Screen::TotpPrompt(_) => "TotpPrompt",
            Screen::Scripts(_) => "Scripts",
            Screen::ScriptTargets(_) => "ScriptTargets",
            Screen::SshImport(_) => "SshImport",
            Screen::Forwards(_) => "Forwards",
            Screen::ForwardForm(_) => "ForwardForm",
            Screen::ConfirmDeleteForward { .. } => "ConfirmDeleteForward",
            Screen::ScriptForm(_) => "ScriptForm",
            Screen::ConfirmDeleteScript { .. } => "ConfirmDeleteScript",
            Screen::ScriptRun(_) => "ScriptRun",
            Screen::FileBrowser(_) => "FileBrowser",
        },
    }
}

/// Makes the next `ConfigStore::save` fail without touching the vault that is
/// already on disk.
///
/// `write_file_atomic` stages a sibling `<name>.tmp` and its very first move is
/// `File::create` on it — a *directory* at that path fails with `EISDIR`. A
/// read-only parent directory would do the same thing but is ignored when the
/// tests run as root, and it would also block the rollback paths' own reads.
fn block_saves(dir: &tempfile::TempDir) {
    std::fs::create_dir(dir.path().join("config.enc.tmp")).expect("stage the blocker");
}

// ---------------------------------------------------------------------------
// Unlock paths
// ---------------------------------------------------------------------------

#[test]
fn a_password_vault_opens_on_the_lock_screen() {
    let (_dir, app) = password_vault(|_| {});
    assert_eq!(screen_name(&app), "Locked");
}

#[test]
fn the_right_password_reaches_the_server_list() {
    let (_dir, mut app) = password_vault(|c| c.servers.push(entry("web-1")));
    type_password(&mut app, PASSWORD);

    assert_eq!(screen_name(&app), "MainMenu");
    assert_eq!(unlocked(&app).config.servers.len(), 1);
}

/// A wrong password and a corrupt file deliberately produce the same error —
/// there is no verifier field to tell them apart. What matters here is that the
/// vault stays shut and the screen says so.
#[test]
fn a_wrong_password_stays_on_the_lock_screen() {
    let (_dir, mut app) = password_vault(|_| {});
    type_password(&mut app, "not the password");

    match &app.state {
        AppState::Locked(unlock) => assert!(unlock.error.is_some(), "the screen must say why"),
        _ => panic!("a wrong password must not change screens"),
    }
}

/// Mode 3: the password opens the vault, but the server list is not reachable
/// until a code has been checked too.
#[test]
fn a_two_factor_vault_stops_at_the_second_factor() {
    let (_dir, mut app) = password_vault(|c| {
        c.totp = Some(TotpConfig { secret_base32: Secret::from("JBSWY3DPEHPK3PXP".to_string()) });
    });
    type_password(&mut app, PASSWORD);
    assert_eq!(screen_name(&app), "TotpPrompt");

    for c in "000000".chars() {
        press(&mut app, char_key(c));
    }
    press(&mut app, KeyEvent::from(KeyCode::Enter));
    assert_eq!(screen_name(&app), "TotpPrompt", "a wrong code must not fall through to the list");
}

/// Cancelling the second factor goes back through `locked_state`, which
/// re-derives which lock screen this vault belongs on. Naming
/// `AppState::Locked` at the call site is the bug this pins.
#[test]
fn cancelling_the_second_factor_relocks_the_vault() {
    let (_dir, mut app) = password_vault(|c| {
        c.totp = Some(TotpConfig { secret_base32: Secret::from("JBSWY3DPEHPK3PXP".to_string()) });
    });
    type_password(&mut app, PASSWORD);

    press(&mut app, KeyEvent::from(KeyCode::Esc));
    assert_eq!(screen_name(&app), "Locked", "the decrypted config must be gone, not merely hidden");
}

/// A vault left over from the retired TOTP-only mode keeps its secret in
/// plaintext beside itself, so the conversion is offered before anything else —
/// including before any credential-store probe, which is why this much of the
/// path is hermetic.
#[test]
fn a_totp_only_vault_is_offered_the_conversion_first() {
    let (dir, mut app) = password_vault(|_| {});
    std::fs::write(dir.path().join("totp-only.secret"), "JBSWY3DPEHPK3PXP").expect("plant the plaintext secret");

    app.state = app.resolve_initial_state();
    match &app.state {
        AppState::Locked(unlock) => assert!(matches!(unlock.mode, UnlockMode::MigrateTotpOnly)),
        _ => panic!("a plaintext secret beside the vault must be converted before anything else"),
    }
}

// ---------------------------------------------------------------------------
// Screen transitions
// ---------------------------------------------------------------------------

/// `i` reaches the importer, and a confirm writes through to disk.
///
/// The step is driven directly rather than through the screen because the
/// screen's own picking is tested in `tui::ssh_import`; what this pins is the
/// half `app.rs` owns — that the entries are built, saved and the list comes
/// back.
#[test]
fn importing_from_ssh_config_persists_the_picked_hosts() {
    let (dir, mut app) = password_vault(|_| {});
    type_password(&mut app, PASSWORD);

    press(&mut app, char_key('i'));
    assert_eq!(screen_name(&app), "SshImport");

    let hosts = crate::ssh_config::parse("Host web-1
    HostName web1.example.com
    User deploy
    Port 2222
");
    app.apply_local_step(NextStep::SshImportConfirm(hosts)).expect("import");

    assert_eq!(screen_name(&app), "MainMenu");
    let entry = &unlocked(&app).config.servers[0];
    assert_eq!(entry.name, "web-1");
    assert_eq!(entry.host, "web1.example.com");
    assert_eq!(entry.username, "deploy");
    assert_eq!(entry.port, 2222);

    drop(app);
    let store = ConfigStore::new(dir.path().join("config.enc"));
    assert_eq!(store.load(PASSWORD).expect("reopen").config.servers[0].host, "web1.example.com");
}

/// A block naming no key becomes agent auth, so the import stores no
/// credential at all — which is the acceptance criterion the issue states.
#[test]
fn a_host_with_no_identity_file_is_imported_as_agent_auth() {
    let (_dir, mut app) = password_vault(|_| {});
    type_password(&mut app, PASSWORD);

    let hosts = crate::ssh_config::parse("Host plain
    HostName plain.example.com
");
    app.apply_local_step(NextStep::SshImportConfirm(hosts)).expect("import");

    assert!(matches!(unlocked(&app).config.servers[0].auth, AuthMethod::Agent));
}

/// A save that fails must not leave the list showing servers the vault does
/// not have — the next launch would silently contradict it.
#[test]
fn a_failed_import_rolls_the_entries_back_out_of_memory() {
    let (dir, mut app) = password_vault(|_| {});
    type_password(&mut app, PASSWORD);
    press(&mut app, char_key('i'));
    block_saves(&dir);

    let hosts = crate::ssh_config::parse("Host web-1
    HostName web1.example.com
");
    app.apply_local_step(NextStep::SshImportConfirm(hosts)).expect("import");

    assert_eq!(screen_name(&app), "SshImport", "a failed save keeps the user where they were");
    assert!(unlocked(&app).config.servers.is_empty(), "nothing may be left behind in memory");
}

/// Deleting a bastion must not leave the hosts behind it pointing at nothing.
/// A dangling `Uuid` is a reference nothing would ever clean up, and it fails
/// at connect time — long after the user could tell what caused it.
#[test]
fn deleting_a_bastion_puts_the_hosts_behind_it_back_on_a_direct_connect() {
    let (_dir, mut app) = password_vault(|config| {
        let bastion = entry("bastion");
        let mut behind = entry("behind");
        behind.jump_host = Some(bastion.id);
        config.servers = vec![bastion, behind];
    });
    type_password(&mut app, PASSWORD);

    let bastion_id = unlocked(&app).config.servers[0].id;
    app.apply_local_step(NextStep::GoDelete(bastion_id)).expect("confirm");
    app.apply_local_step(NextStep::ConfirmYes).expect("delete");

    let servers = &unlocked(&app).config.servers;
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0].jump_host, None, "the reference must go with the entry");
}

/// `p` reaches the forwards list, and add / toggle / delete each write
/// through. The rules are the one thing here that a *session* acts on, so a
/// rule that is in memory and not on disk is one that quietly does not run
/// next launch.
#[test]
fn port_forwards_are_added_toggled_and_deleted_through_the_list() {
    let (dir, mut app) = password_vault(|config| config.servers = vec![entry("web-1")]);
    type_password(&mut app, PASSWORD);

    let server_id = unlocked(&app).config.servers[0].id;
    press(&mut app, char_key('p'));
    assert_eq!(screen_name(&app), "Forwards");

    press(&mut app, char_key('a'));
    assert_eq!(screen_name(&app), "ForwardForm");
    let kind = crate::config::ForwardKind::Local {
        bind_addr: "127.0.0.1".into(),
        bind_port: 8080,
        dest_host: "db.internal".into(),
        dest_port: 5432,
    };
    app.apply_local_step(NextStep::ForwardFormSave(crate::tui::forward_form::ForwardFormData { id: None, kind }))
        .expect("save");

    assert_eq!(screen_name(&app), "Forwards");
    let rule_id = unlocked(&app).config.servers[0].forwards[0].id;
    assert!(unlocked(&app).config.servers[0].forwards[0].enabled);

    // Off, but kept — that is what the flag is for.
    app.apply_local_step(NextStep::ForwardToggle(rule_id)).expect("toggle");
    assert!(!unlocked(&app).config.servers[0].forwards[0].enabled);
    assert_eq!(unlocked(&app).config.servers[0].forwards.len(), 1);

    app.apply_local_step(NextStep::GoForwardDeleteConfirm(rule_id)).expect("confirm");
    assert_eq!(screen_name(&app), "ConfirmDeleteForward");
    app.apply_local_step(NextStep::ConfirmDeleteForwardNo).expect("keep it");
    assert_eq!(screen_name(&app), "Forwards");
    assert_eq!(unlocked(&app).config.servers[0].forwards.len(), 1, "\"no\" keeps the rule");

    app.apply_local_step(NextStep::GoForwardDeleteConfirm(rule_id)).expect("confirm");
    app.apply_local_step(NextStep::ConfirmDeleteForwardYes).expect("delete");
    assert_eq!(screen_name(&app), "Forwards");
    assert!(unlocked(&app).config.servers[0].forwards.is_empty());

    // Every step above saved, so the vault agrees. Checked after the app is
    // dropped: `VaultLock` holds the flock in this process, and a second store
    // on the same file would contend with it.
    drop(app);
    let store = ConfigStore::new(dir.path().join("config.enc"));
    assert!(store.load(PASSWORD).expect("reopen").config.servers[0].forwards.is_empty());
    let _ = server_id;
}

/// A rule turned off is a rule that is still there next launch. The flag is
/// the whole reason `d` is not the only way to stop a forward.
#[test]
fn a_disabled_forward_survives_a_restart_still_disabled() {
    let (dir, mut app) = password_vault(|config| config.servers = vec![entry("web-1")]);
    type_password(&mut app, PASSWORD);
    let server_id = unlocked(&app).config.servers[0].id;

    app.apply_local_step(NextStep::GoForwards(server_id)).expect("open");
    let kind = crate::config::ForwardKind::Dynamic { bind_addr: "127.0.0.1".into(), bind_port: 1080 };
    app.apply_local_step(NextStep::GoForwardAdd).expect("add");
    app.apply_local_step(NextStep::ForwardFormSave(crate::tui::forward_form::ForwardFormData { id: None, kind }))
        .expect("save");
    let rule_id = unlocked(&app).config.servers[0].forwards[0].id;
    app.apply_local_step(NextStep::ForwardToggle(rule_id)).expect("toggle");

    drop(app);
    let store = ConfigStore::new(dir.path().join("config.enc"));
    let reopened = store.load(PASSWORD).expect("reopen");
    assert_eq!(reopened.config.servers[0].forwards.len(), 1);
    assert!(!reopened.config.servers[0].forwards[0].enabled);
}

/// None of the forward steps suspends the terminal, holds a connection or
/// redraws from inside an await, so none of them belongs in
/// `handle_unlocked_key`'s six-arm match — putting one there would quietly
/// make it untestable.
#[test]
fn the_forward_steps_need_no_terminal() {
    let (_dir, mut app) = password_vault(|config| config.servers = vec![entry("web-1")]);
    type_password(&mut app, PASSWORD);

    for step in [NextStep::GoForwards(unlocked(&app).config.servers[0].id), NextStep::GoForwardAdd, NextStep::ForwardFormCancel, NextStep::ForwardsBack] {
        assert!(app.apply_local_step(step).expect("step").is_none(), "a forward step must not need a terminal");
    }
}

#[test]
fn adding_a_server_persists_it_and_returns_to_the_list() {
    let (dir, mut app) = password_vault(|_| {});
    type_password(&mut app, PASSWORD);

    press(&mut app, char_key('a'));
    assert_eq!(screen_name(&app), "ServerForm");

    let data = ServerFormData {
        name: "web-1".into(),
        host: "web-1.example.com".into(),
        port: 22,
        username: "root".into(),
        tags: vec!["prod".into()],
        auth: AuthMethod::password("hunter2"),
        jump_host: None,
    };
    app.apply_local_step(NextStep::FormSubmit(data)).expect("submit");

    assert_eq!(screen_name(&app), "MainMenu");
    assert_eq!(unlocked(&app).config.servers[0].name, "web-1");

    // And it is actually on disk, not just in memory.
    drop(app);
    let store = ConfigStore::new(dir.path().join("config.enc"));
    assert_eq!(store.load(PASSWORD).expect("reopen").config.servers[0].name, "web-1");
}

#[test]
fn deleting_a_server_asks_first_and_then_removes_it() {
    let (_dir, mut app) = password_vault(|c| c.servers.push(entry("web-1")));
    type_password(&mut app, PASSWORD);

    press(&mut app, char_key('d'));
    assert_eq!(screen_name(&app), "ConfirmDelete");

    press(&mut app, char_key('n'));
    assert_eq!(screen_name(&app), "MainMenu");
    assert_eq!(unlocked(&app).config.servers.len(), 1, "answering no must keep the entry");

    press(&mut app, char_key('d'));
    press(&mut app, char_key('y'));
    assert_eq!(screen_name(&app), "MainMenu");
    assert!(unlocked(&app).config.servers.is_empty());
}

#[test]
fn escape_from_the_scripts_list_goes_back_to_the_server_list() {
    let (_dir, mut app) = password_vault(|c| c.servers.push(entry("web-1")));
    type_password(&mut app, PASSWORD);

    press(&mut app, char_key('s'));
    assert_eq!(screen_name(&app), "Scripts");

    press(&mut app, KeyEvent::from(KeyCode::Esc));
    assert_eq!(screen_name(&app), "MainMenu");
}

/// The overlay is modal: the key that dismisses it must not also act on the
/// list underneath, or closing help with `q` would quit the app.
#[test]
fn the_help_overlay_swallows_the_key_that_closes_it() {
    let (_dir, mut app) = password_vault(|_| {});
    type_password(&mut app, PASSWORD);

    press(&mut app, KeyEvent::from(KeyCode::F(2)));
    assert!(unlocked(&app).help_open);

    press(&mut app, char_key('q'));
    assert!(!unlocked(&app).help_open);
    assert!(!app.should_quit, "the closing key must not reach the screen behind it");
}

// ---------------------------------------------------------------------------
// Rollback, and the idle timer
// ---------------------------------------------------------------------------

/// The setting is only worth applying if it survives a restart, so a failed
/// write puts the old value back rather than leaving the two out of step.
#[test]
fn a_failed_save_leaves_the_auto_lock_where_it_was() {
    let (dir, mut app) = password_vault(|_| {});
    type_password(&mut app, PASSWORD);
    let before = unlocked(&app).config.auto_lock_minutes;
    press(&mut app, KeyEvent::from(KeyCode::F(1)));
    block_saves(&dir);

    app.apply_local_step(NextStep::SettingsAutoLockSelected(before + 5)).expect("step");

    assert_eq!(unlocked(&app).config.auto_lock_minutes, before);
    match &unlocked(&app).screen {
        Screen::Settings(s) => assert!(s.error.is_some(), "the screen must say the write failed"),
        _ => panic!("expected the settings screen"),
    }
}

/// The vault on disk was never replaced — writes are atomic — so undoing the
/// in-memory half has to restore the previous state whole. A `config.totp` left
/// set here would have the app demanding a second factor the vault knows
/// nothing about.
#[test]
fn a_failed_security_mode_change_rolls_back_completely() {
    let (dir, mut app) = password_vault(|_| {});
    type_password(&mut app, PASSWORD);
    press(&mut app, KeyEvent::from(KeyCode::F(1)));
    let slots_before = unlocked(&app).slots.len();
    block_saves(&dir);

    // `password: None` keeps the slot already on the vault, so no Argon2 runs
    // and the test stays fast; the rollback path is the same either way.
    app.apply_local_step(NextStep::ChangeSecurityMode {
        mode: AuthMode::PasswordTotp,
        password: None,
        totp_secret: Some(Zeroizing::new("JBSWY3DPEHPK3PXP".to_string())),
    })
    .expect("step");

    assert!(unlocked(&app).config.totp.is_none(), "the second factor must not survive a failed write");
    assert_eq!(unlocked(&app).slots.len(), slots_before);
    assert_eq!(app.current_auth_mode(), AuthMode::Password);
}

#[test]
fn the_idle_timer_locks_the_vault_and_says_so() {
    let (_dir, mut app) = password_vault(|_| {});
    type_password(&mut app, PASSWORD);
    app.apply_local_step(NextStep::SettingsAutoLockSelected(1)).expect("step");

    app.last_activity = Instant::now() - Duration::from_secs(3600);
    app.auto_lock_if_idle();

    match &app.state {
        AppState::Locked(unlock) => assert!(unlock.info.is_some(), "the lock screen should explain itself"),
        _ => panic!("an idle vault must re-lock"),
    }
}

/// `0` is off, and it has to stay off however long the app sits there.
#[test]
fn an_auto_lock_of_zero_never_fires() {
    let (_dir, mut app) = password_vault(|_| {});
    type_password(&mut app, PASSWORD);
    app.apply_local_step(NextStep::SettingsAutoLockSelected(0)).expect("step");

    app.last_activity = Instant::now() - Duration::from_secs(86_400);
    app.auto_lock_if_idle();

    assert_eq!(screen_name(&app), "MainMenu");
}

/// The cancel contract, pinned: only these two stop a run. Every other key is
/// forwarded to the screen, so widening this set silently takes a binding away
/// from it.
#[test]
fn only_esc_and_ctrl_c_stop_a_run() {
    assert!(is_cancel_key(KeyEvent::from(KeyCode::Esc)));
    assert!(is_cancel_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)));

    assert!(!is_cancel_key(KeyEvent::from(KeyCode::Char('c'))), "a bare c is output, not a cancel");
    assert!(!is_cancel_key(KeyEvent::from(KeyCode::Enter)));
    assert!(!is_cancel_key(KeyEvent::from(KeyCode::Char('q'))));
}

// ---------------------------------------------------------------------------
// Running a script on several servers (#21)
// ---------------------------------------------------------------------------

/// `m` is the only way to a fleet run, and it has to open with the script's own
/// server already checked — `Enter` and `m` must agree about the default.
#[test]
fn m_on_the_script_list_opens_the_target_picker() {
    let (_dir, mut app) = password_vault(|c| {
        let mut e = entry("web-1");
        e.scripts.push(Script { id: Uuid::new_v4(), name: "deploy".into(), run_on_connect: false, steps: Vec::new() });
        c.servers.push(e);
        c.servers.push(entry("web-2"));
    });
    type_password(&mut app, PASSWORD);

    press(&mut app, char_key('s'));
    press(&mut app, char_key('m'));
    assert_eq!(screen_name(&app), "ScriptTargets");

    let origin = unlocked(&app).config.servers[0].id;
    match &unlocked(&app).screen {
        Screen::ScriptTargets(state) => assert_eq!(state.origin_server_id, origin),
        _ => unreachable!(),
    }

    press(&mut app, KeyEvent::from(KeyCode::Esc));
    assert_eq!(screen_name(&app), "Scripts", "cancelling goes back to the script it came from");
}

/// The picker resolves to a `RunScript` carrying its targets, and `Enter` on the
/// list resolves to the same step with one — the two paths share a flow, so a
/// divergence here would be a second code path nobody tests.
#[test]
fn both_run_paths_resolve_to_the_same_step() {
    let (_dir, mut app) = password_vault(|c| {
        let mut e = entry("web-1");
        e.scripts.push(Script { id: Uuid::new_v4(), name: "deploy".into(), run_on_connect: false, steps: Vec::new() });
        c.servers.push(e);
        c.servers.push(entry("web-2"));
    });
    type_password(&mut app, PASSWORD);
    let (origin, second) = (unlocked(&app).config.servers[0].id, unlocked(&app).config.servers[1].id);

    press(&mut app, char_key('s'));
    match app.resolve_next_step(KeyEvent::from(KeyCode::Enter)) {
        NextStep::RunScript { origin_server_id, targets, .. } => {
            assert_eq!(origin_server_id, origin);
            assert_eq!(targets, vec![origin], "Enter still runs on the script's own server and nowhere else");
        }
        _ => panic!("Enter on the script list must run the script"),
    }

    press(&mut app, char_key('m'));
    press(&mut app, KeyEvent::from(KeyCode::Down));
    press(&mut app, char_key(' '));
    match app.resolve_next_step(KeyEvent::from(KeyCode::Enter)) {
        NextStep::RunScript { origin_server_id, targets, .. } => {
            assert_eq!(origin_server_id, origin, "the definition still comes from where it lives");
            assert_eq!(targets, vec![origin, second]);
        }
        _ => panic!("the picker must run the script"),
    }
}

/// `connect_flow` writes what the handshake taught it *before* handing the
/// terminal to the shell — a fingerprint persisted only once the session ended
/// would re-run TOFU if the process were killed during it. This is the half of
/// that flow which needs no terminal.
#[test]
fn a_handshake_record_lands_on_the_entry_and_is_saved() {
    let (dir, mut app) = password_vault(|c| c.servers.push(entry("web-1")));
    type_password(&mut app, PASSWORD);
    let id = unlocked(&app).config.servers[0].id;

    app.record_session(id, &session::SessionRecord { fingerprint: Some("SHA256:abc".into()), connected_at: 100, system_info: None }, &[]);

    let e = &unlocked(&app).config.servers[0];
    assert_eq!(e.host_key_fingerprint.as_deref(), Some("SHA256:abc"));
    assert_eq!(e.last_connected_unix, Some(100));

    // And it is on disk, not only in memory: the save is what the next launch
    // reads. The app's own store holds the `flock`, so it is dropped first.
    drop(app);
    let store = ConfigStore::new(dir.path().join("config.enc"));
    let reopened = store.load(PASSWORD).expect("reopen");
    assert_eq!(reopened.config.servers[0].host_key_fingerprint.as_deref(), Some("SHA256:abc"));
}

/// The probe now runs beside the shell rather than in front of it, so the entry
/// is written twice: once at the handshake, once when the probe comes back.
/// The second write must not disturb what the first one stamped.
#[test]
fn the_probe_s_record_adds_system_info_without_moving_the_timestamp() {
    let (_dir, mut app) = password_vault(|c| c.servers.push(entry("web-1")));
    type_password(&mut app, PASSWORD);
    let id = unlocked(&app).config.servers[0].id;

    let mut record = session::SessionRecord { fingerprint: Some("SHA256:abc".into()), connected_at: 100, system_info: None };
    app.record_session(id, &record, &[]);
    record.system_info = Some(SystemInfo { cpu_cores: Some(8), ..SystemInfo::default() });
    app.record_session(id, &record, &[]);

    let e = &unlocked(&app).config.servers[0];
    assert_eq!(e.last_connected_unix, Some(100), "the connection time is stamped once");
    assert_eq!(e.system_info.as_ref().and_then(|i| i.cpu_cores), Some(8));
}

/// The six steps that need a terminal must keep coming back out of
/// `apply_local_step` rather than being carried out inside it — putting one of
/// them in there quietly makes it untestable, which is the whole point of the
/// seam.
#[test]
fn the_steps_that_need_a_terminal_are_handed_back() {
    let (_dir, mut app) = password_vault(|c| c.servers.push(entry("web-1")));
    type_password(&mut app, PASSWORD);
    let id = unlocked(&app).config.servers[0].id;

    assert!(matches!(app.apply_local_step(NextStep::Connect(id)), Ok(Some(NextStep::Connect(_)))));
    assert!(matches!(app.apply_local_step(NextStep::GoFiles(id)), Ok(Some(NextStep::GoFiles(_)))));
    assert!(matches!(app.apply_local_step(NextStep::FilesRefresh), Ok(Some(NextStep::FilesRefresh))));
    assert!(app.connecting.is_none(), "nothing local ever sets the connect indicator");
}
