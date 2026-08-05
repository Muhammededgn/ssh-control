use ssh_control::config::{AuthMethod, ConfigStore, ServerEntry};
use ssh_control::error::AppError;

fn temp_store() -> (tempfile::TempDir, ConfigStore) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.enc");
    let store = ConfigStore::new(path);
    (dir, store)
}

#[test]
fn first_run_creates_empty_config() {
    let (_dir, store) = temp_store();
    assert!(!store.exists());

    let unlocked = store.init("master password").unwrap();
    assert!(unlocked.config.servers.is_empty());
    assert!(store.exists());
}

#[test]
fn save_and_load_roundtrip() {
    let (_dir, store) = temp_store();
    let mut unlocked = store.init("master password").unwrap();

    unlocked.config.servers.push(ServerEntry::new(
        "myserver".into(),
        "example.com".into(),
        22,
        "root".into(),
        AuthMethod::Password { password: "hunter2".into() },
    ));

    store
        .save(&unlocked.config, &unlocked.key, &unlocked.salt, unlocked.params)
        .unwrap();

    let reloaded = store.load("master password").unwrap();
    assert_eq!(reloaded.config.servers.len(), 1);
    assert_eq!(reloaded.config.servers[0].name, "myserver");
    assert_eq!(reloaded.config.servers[0].host, "example.com");
}

#[test]
fn wrong_master_password_is_rejected() {
    let (_dir, store) = temp_store();
    store.init("correct password").unwrap();

    let result = store.load("wrong password");
    assert!(matches!(result, Err(AppError::WrongPasswordOrCorrupt)));
}

#[test]
fn loading_nonexistent_config_reports_not_found() {
    let (_dir, store) = temp_store();
    let result = store.load("anything");
    assert!(matches!(result, Err(AppError::ConfigNotFound(_))));
}

#[test]
fn saving_leaves_no_temp_file_behind() {
    let (dir, store) = temp_store();
    let unlocked = store.init("master password").unwrap();
    store
        .save(&unlocked.config, &unlocked.key, &unlocked.salt, unlocked.params)
        .unwrap();

    let leftovers: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".tmp"))
        .collect();

    assert!(leftovers.is_empty(), "atomic write left temp files: {leftovers:?}");
}

#[test]
fn a_failed_save_leaves_the_previous_vault_intact() {
    let (dir, store) = temp_store();
    let mut unlocked = store.init("master password").unwrap();
    unlocked.config.servers.push(ServerEntry::new(
        "keeper".into(),
        "example.com".into(),
        22,
        "root".into(),
        AuthMethod::Password { password: "hunter2".into() },
    ));
    store
        .save(&unlocked.config, &unlocked.key, &unlocked.salt, unlocked.params)
        .unwrap();

    // Occupy the temp path with a directory so creating the staging file
    // fails, aborting the save before it can touch config.enc.
    std::fs::create_dir(dir.path().join("config.enc.tmp")).unwrap();

    unlocked.config.servers.clear();
    let result = store.save(&unlocked.config, &unlocked.key, &unlocked.salt, unlocked.params);
    assert!(result.is_err(), "save should fail when the temp path is unusable");

    let reloaded = store.load("master password").unwrap();
    assert_eq!(reloaded.config.servers.len(), 1);
    assert_eq!(reloaded.config.servers[0].name, "keeper");
}

#[test]
fn totp_only_secret_can_be_stashed_and_restored() {
    let (_dir, store) = temp_store();
    store.init("master password").unwrap();

    store.write_totp_only_secret("JBSWY3DPEHPK3PXP").unwrap();
    assert!(store.totp_only_secret_exists());

    assert!(store.stash_totp_only_secret().unwrap());
    assert!(!store.totp_only_secret_exists());

    store.restore_totp_only_secret().unwrap();
    assert!(store.totp_only_secret_exists());
    assert_eq!(store.read_totp_only_secret().unwrap(), "JBSWY3DPEHPK3PXP");
}

#[test]
fn stashing_a_missing_totp_only_secret_is_not_an_error() {
    let (_dir, store) = temp_store();
    store.init("master password").unwrap();
    assert!(!store.stash_totp_only_secret().unwrap());
}
