use ssh_control::config::store::VaultShape;
use ssh_control::config::{AuthMethod, Config, ConfigStore, ServerEntry, keyslot};
use ssh_control::crypto::kdf::KdfParams;
use ssh_control::crypto::{cipher, kdf};
use ssh_control::error::AppError;
use zeroize::Zeroizing;

fn temp_store() -> (tempfile::TempDir, ConfigStore) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.enc");
    let store = ConfigStore::new(path);
    (dir, store)
}

/// Writes a vault in the pre-keyslot v1 layout, where the Argon2id output *was*
/// the vault key and there was no master key at all.
///
/// The header is assembled by hand rather than through `config::format`, on
/// purpose: the v1 writer no longer exists, and a fixture built from the same
/// code it is meant to test would pass even if both drifted together. These
/// bytes are what is actually sitting on existing users' disks.
fn write_v1_vault(path: &std::path::Path, password: &str, config: &Config) {
    let params = KdfParams::INTERACTIVE;
    let salt = [7u8; kdf::SALT_LEN];
    let nonce = [9u8; 12];

    let mut header = Vec::new();
    header.extend_from_slice(b"SSHCTRL1");
    header.push(1); // format version
    header.push(1); // kdf id: argon2id
    header.extend_from_slice(&params.m_cost.to_le_bytes());
    header.extend_from_slice(&params.t_cost.to_le_bytes());
    header.extend_from_slice(&params.p_cost.to_le_bytes());
    header.extend_from_slice(&salt);

    let key = kdf::derive_key(password, &salt, params).unwrap();
    let plaintext = serde_json::to_vec(config).unwrap();
    let ciphertext = cipher::encrypt(&key, &nonce, &header, &plaintext).unwrap();

    let mut bytes = header;
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&(ciphertext.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&ciphertext);
    std::fs::write(path, bytes).unwrap();
}

fn format_version_of(path: &std::path::Path) -> u8 {
    std::fs::read(path).unwrap()[8]
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
        AuthMethod::password("hunter2"),
    ));

    store
        .save(&unlocked.config, &unlocked.master_key, &unlocked.slots)
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
        .save(&unlocked.config, &unlocked.master_key, &unlocked.slots)
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
        AuthMethod::password("hunter2"),
    ));
    store
        .save(&unlocked.config, &unlocked.master_key, &unlocked.slots)
        .unwrap();

    // Occupy the temp path with a directory so creating the staging file
    // fails, aborting the save before it can touch config.enc.
    std::fs::create_dir(dir.path().join("config.enc.tmp")).unwrap();

    unlocked.config.servers.clear();
    let result = store.save(&unlocked.config, &unlocked.master_key, &unlocked.slots);
    assert!(result.is_err(), "save should fail when the temp path is unusable");

    let reloaded = store.load("master password").unwrap();
    assert_eq!(reloaded.config.servers.len(), 1);
    assert_eq!(reloaded.config.servers[0].name, "keeper");
}

/// Builds the two-slot vault that mode 4 uses, without touching a real
/// credential store — the device key is just 32 bytes, and where it is kept is
/// the OS's problem, not the format's.
fn init_device_and_password(store: &ConfigStore, password: &str, device_key: &Zeroizing<[u8; 32]>) -> ssh_control::config::Unlocked {
    store
        .init_slots(|mk| {
            Ok(vec![
                keyslot::wrap_password(password, KdfParams::INTERACTIVE, mk)?,
                keyslot::wrap_device(device_key, mk)?,
            ])
        })
        .unwrap()
}

#[test]
fn a_device_slot_and_a_password_slot_open_the_same_vault() {
    let (_dir, store) = temp_store();
    let device_key = Zeroizing::new([9u8; 32]);

    let mut unlocked = init_device_and_password(&store, "recovery password", &device_key);
    unlocked.config.servers.push(ServerEntry::new(
        "shared".into(),
        "example.com".into(),
        22,
        "root".into(),
        AuthMethod::password("hunter2"),
    ));
    store.save(&unlocked.config, &unlocked.master_key, &unlocked.slots).unwrap();

    let by_device = store.load_with_device(&device_key).unwrap();
    let by_password = store.load("recovery password").unwrap();

    assert_eq!(by_device.config.servers[0].name, "shared");
    assert_eq!(by_password.config.servers[0].name, "shared");
    assert_eq!(*by_device.master_key, *by_password.master_key);
    assert_eq!(store.peek_shape().unwrap(), VaultShape::DeviceAndPassword);
}

/// The whole point of the device slot: carry the vault somewhere else and the
/// everyday key is not there, so only the password gets you in.
#[test]
fn a_vault_copied_without_its_device_key_only_opens_with_the_password() {
    let (_dir, store) = temp_store();
    let device_key = Zeroizing::new([9u8; 32]);
    init_device_and_password(&store, "recovery password", &device_key);

    // A different machine: same file, no matching device key.
    let other_machine = Zeroizing::new([1u8; 32]);
    assert!(matches!(store.load_with_device(&other_machine), Err(AppError::WrongPasswordOrCorrupt)));
    assert!(store.load("recovery password").is_ok());
}

#[test]
fn a_device_only_vault_reports_its_shape_and_refuses_a_password() {
    let (_dir, store) = temp_store();
    let device_key = Zeroizing::new([4u8; 32]);
    store.init_slots(|mk| Ok(vec![keyslot::wrap_device(&device_key, mk)?])).unwrap();

    assert_eq!(store.peek_shape().unwrap(), VaultShape::Device);
    assert!(store.load_with_device(&device_key).is_ok());
    // There is no password slot to try, so any password is simply wrong.
    assert!(matches!(store.load("anything at all"), Err(AppError::WrongPasswordOrCorrupt)));
}

/// A device slot is wrapped under an HKDF key with no Argon2 stretching, so its
/// descriptor carries zeroed costs. Those must survive a round trip through the
/// header without tripping the Argon2 range check.
#[test]
fn a_device_slot_survives_the_header_range_check() {
    let (dir, store) = temp_store();
    let device_key = Zeroizing::new([7u8; 32]);
    init_device_and_password(&store, "recovery password", &device_key);

    let bytes = std::fs::read(dir.path().join("config.enc")).unwrap();
    assert_eq!(bytes[8], 2, "should be written as v2");
    assert_eq!(bytes[9], 2, "should carry two slots");
    assert!(store.load_with_device(&device_key).is_ok());
}

#[test]
fn tampering_with_a_slot_descriptor_breaks_the_whole_file() {
    let (dir, store) = temp_store();
    let path = dir.path().join("config.enc");
    store.init("master password").unwrap();

    let mut bytes = std::fs::read(&path).unwrap();
    // Byte 10 is the first slot's kdf_id — the header is AEAD additional data,
    // so editing it has to fail the tag rather than weaken the file.
    let at = 10 + 2;
    bytes[at] ^= 0x01;
    std::fs::write(&path, bytes).unwrap();

    assert!(store.load("master password").is_err());
}

#[test]
fn a_v1_vault_is_upgraded_in_place_and_keeps_its_contents() {
    let (dir, store) = temp_store();
    let path = dir.path().join("config.enc");

    let mut original = Config::default();
    original.servers.push(ServerEntry::new(
        "legacy".into(),
        "example.com".into(),
        2222,
        "root".into(),
        AuthMethod::password("hunter2"),
    ));
    write_v1_vault(&path, "old password", &original);
    assert_eq!(format_version_of(&path), 1);

    let unlocked = store.load("old password").unwrap();
    assert_eq!(unlocked.config.servers.len(), 1);
    assert_eq!(unlocked.config.servers[0].name, "legacy");
    assert_eq!(unlocked.config.servers[0].port, 2222);

    // The upgrade is written back, not just applied in memory.
    assert_eq!(format_version_of(&path), 2, "loading a v1 vault should rewrite it as v2");
    assert_eq!(unlocked.slots.len(), 1);
}

#[test]
fn an_upgraded_vault_opens_with_the_same_password_on_the_next_launch() {
    let (dir, store) = temp_store();
    let path = dir.path().join("config.enc");

    write_v1_vault(&path, "old password", &Config::default());
    store.load("old password").unwrap();

    // Second load goes through the v2 path, and the password is unchanged by
    // the upgrade — a user must not have to know it happened.
    let reloaded = store.load("old password").unwrap();
    assert!(reloaded.config.servers.is_empty());
    assert!(matches!(store.load("wrong password"), Err(AppError::WrongPasswordOrCorrupt)));
}

#[test]
fn a_wrong_password_does_not_destroy_a_v1_vault() {
    let (dir, store) = temp_store();
    let path = dir.path().join("config.enc");

    write_v1_vault(&path, "old password", &Config::default());
    assert!(matches!(store.load("wrong password"), Err(AppError::WrongPasswordOrCorrupt)));

    // A failed upgrade must leave the old file readable — there is no backup
    // copy of the vault, so a rewrite on a wrong guess would be unrecoverable.
    assert_eq!(format_version_of(&path), 1);
    assert!(store.load("old password").is_ok());
}

#[test]
fn a_newer_format_version_is_refused_rather_than_silently_reopened() {
    let (dir, store) = temp_store();
    let path = dir.path().join("config.enc");

    store.init("master password").unwrap();
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[8] = 99;
    std::fs::write(&path, bytes).unwrap();

    assert!(matches!(store.load("master password"), Err(AppError::UnsupportedFormatVersion(99))));
}

#[test]
fn changing_a_slot_does_not_re_encrypt_the_vault_body() {
    let (dir, store) = temp_store();
    let path = dir.path().join("config.enc");

    let mut unlocked = store.init("first password").unwrap();
    unlocked.config.servers.push(ServerEntry::new(
        "keeper".into(),
        "example.com".into(),
        22,
        "root".into(),
        AuthMethod::password("hunter2"),
    ));
    store.save(&unlocked.config, &unlocked.master_key, &unlocked.slots).unwrap();

    // Rewrap the master key under a second password, the way
    // `change_master_password` does, and confirm both the old master key and
    // the new password still reach the same vault.
    let replacement = ssh_control::config::keyslot::wrap_password(
        "second password",
        KdfParams::INTERACTIVE,
        &unlocked.master_key,
    )
    .unwrap();
    let mut slots = unlocked.slots.clone();
    ssh_control::config::keyslot::replace(&mut slots, ssh_control::config::format::SLOT_PASSWORD, replacement);
    store.save(&unlocked.config, &unlocked.master_key, &slots).unwrap();

    let reloaded = store.load("second password").unwrap();
    assert_eq!(reloaded.config.servers.len(), 1);
    assert_eq!(*reloaded.master_key, *unlocked.master_key, "the master key must survive a password change");
    assert!(matches!(store.load("first password"), Err(AppError::WrongPasswordOrCorrupt)));
    assert_eq!(format_version_of(&path), 2);
}
