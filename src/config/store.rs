use std::fs;
use std::path::{Path, PathBuf};

use directories::ProjectDirs;
use zeroize::Zeroizing;

use super::device;
use super::format::{self, AnyEnvelope, SLOT_PASSWORD, Slot};
use super::keyslot::{self, MasterKey};
use super::model::Config;
use crate::crypto::{cipher, kdf};
use crate::error::{AppError, Result};

const CONFIG_FILE_NAME: &str = "config.enc";
const PREFS_FILE_NAME: &str = "prefs.lang";
const TOTP_ONLY_FILE_NAME: &str = "totp-only.secret";
const VAULT_ID_FILE_NAME: &str = "vault-id";

/// Which unlock methods a vault carries, read from the header without opening
/// it. This is what the lock screen branches on before any user input exists.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VaultShape {
    /// A password slot only — modes 2 and 3. (Whether a second TOTP factor
    /// follows is decided by `config.totp` once the vault is open.)
    Password,
    /// A device slot only — mode 1, opened with no user input at all.
    Device,
    /// Both — mode 4: TOTP against device-bound state day to day, with the
    /// password as the escalation path.
    DeviceAndPassword,
}

/// The unlocked state produced by `ConfigStore::init` (first run) or
/// `ConfigStore::load` (subsequent runs).
///
/// `master_key` is what the vault body is encrypted under; it is held for the
/// process's unlocked lifetime so later saves don't need to re-run Argon2id.
/// `slots` travels with it because every save rewrites the whole envelope, and
/// the slots are part of the body's AAD — dropping them would lock the user out
/// of every unlock method the current screen didn't happen to use.
pub struct Unlocked {
    pub config: Config,
    pub master_key: MasterKey,
    pub slots: Vec<Slot>,
}

pub struct ConfigStore {
    path: PathBuf,
}

impl ConfigStore {
    pub fn resolve_default_path() -> Result<PathBuf> {
        let dirs = ProjectDirs::from("", "", "ssh-control").ok_or(AppError::NoConfigDir)?;
        Ok(dirs.config_dir().join(CONFIG_FILE_NAME))
    }

    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Path for the (unencrypted) UI-language preference — kept separate from
    /// `config.enc` since it's not a secret and must be readable before the
    /// master password is entered (so even the unlock screen itself shows the
    /// remembered language).
    pub fn prefs_path(&self) -> PathBuf {
        self.path.with_file_name(PREFS_FILE_NAME)
    }

    /// Path for the secret left behind by the retired "TOTP-only" mode.
    ///
    /// It is plain text, which is precisely why that mode is gone: anyone who
    /// could read this file could open the vault without ever producing a code.
    /// The app now only reads it once, to migrate the vault onto a device-bound
    /// secret and a password, and then deletes it. Nothing writes it any more.
    fn totp_only_secret_path(&self) -> PathBuf {
        self.path.with_file_name(TOTP_ONLY_FILE_NAME)
    }

    pub fn totp_only_secret_exists(&self) -> bool {
        self.totp_only_secret_path().exists()
    }

    pub fn read_totp_only_secret(&self) -> Result<String> {
        Ok(fs::read_to_string(self.totp_only_secret_path())?)
    }

    /// Deletes the migrated secret. Called only after the replacement vault has
    /// been written and proved to open — see `App::migrate_totp_only`.
    pub fn discard_totp_only_secret(&self) {
        let _ = fs::remove_file(self.totp_only_secret_path());
    }

    /// A stable identifier for this vault, used to scope its credential-store
    /// entry so two vaults on one machine never share device state.
    ///
    /// Deliberately not a secret and deliberately *inside* the config
    /// directory: a copied vault carries its id along, looks up the same
    /// credential-store account on the new machine, finds nothing, and falls
    /// back to the password. That is the copy-detection mechanism working, not
    /// a leak.
    pub fn vault_id(&self) -> Result<String> {
        let path = self.path.with_file_name(VAULT_ID_FILE_NAME);
        if let Ok(existing) = fs::read_to_string(&path) {
            let trimmed = existing.trim();
            if !trimmed.is_empty() {
                return Ok(trimmed.to_string());
            }
        }
        let fresh = uuid::Uuid::new_v4().to_string();
        write_file_atomic(&path, fresh.as_bytes())?;
        Ok(fresh)
    }

    pub fn device_store(&self) -> Result<device::DeviceStore> {
        device::DeviceStore::open(&self.vault_id()?)
    }

    /// Reads which unlock methods the vault carries, without opening it.
    ///
    /// A v1 file predates slots entirely and was always password-keyed, so it
    /// reports `Password`; the upgrade happens on the first successful unlock.
    pub fn peek_shape(&self) -> Result<VaultShape> {
        let bytes = self.read_file()?;
        let slots = match format::decode_any(&bytes)? {
            AnyEnvelope::V1(_) => return Ok(VaultShape::Password),
            AnyEnvelope::V2(envelope) => envelope.slots,
        };
        Ok(shape_of(&slots))
    }

    /// First-run setup: generates a random master key, wraps it in a single
    /// password slot, and writes an empty encrypted config.
    pub fn init(&self, master_password: &str) -> Result<Unlocked> {
        self.init_slots(|mk| Ok(vec![keyslot::wrap_password(master_password, kdf::KdfParams::INTERACTIVE, mk)?]))
    }

    /// The general form: a fresh master key and an empty config, with the
    /// caller deciding which slots wrap it. Used by the setup wizard, where the
    /// chosen security mode determines the slot set.
    pub fn init_slots<F>(&self, build_slots: F) -> Result<Unlocked>
    where
        F: FnOnce(&MasterKey) -> Result<Vec<Slot>>,
    {
        let master_key = cipher::random_master_key()?;
        let slots = build_slots(&master_key)?;
        let config = Config::default();

        self.write(&config, &master_key, &slots)?;

        Ok(Unlocked { config, master_key, slots })
    }

    /// Opens a vault through its device slot — mode 1's silent unlock, and the
    /// everyday path of mode 4 once the TOTP gate has been passed.
    pub fn load_with_device(&self, device_key: &Zeroizing<[u8; 32]>) -> Result<Unlocked> {
        let bytes = self.read_file()?;
        let envelope = match format::decode_any(&bytes)? {
            AnyEnvelope::V2(envelope) => envelope,
            // A v1 file has no device slot to try; it upgrades on a password
            // unlock instead.
            AnyEnvelope::V1(_) => return Err(AppError::WrongPasswordOrCorrupt),
        };

        let slot = keyslot::find(&envelope.slots, format::SLOT_DEVICE).ok_or(AppError::WrongPasswordOrCorrupt)?;
        let master_key = keyslot::unwrap_device(slot, device_key)?;

        let config = decrypt_body(&envelope, &master_key)?;
        Ok(Unlocked { config, master_key, slots: envelope.slots })
    }

    /// Subsequent-run unlock: reads the file, unwraps the master key from the
    /// password slot, and decrypts the body with it. A wrong password surfaces
    /// as `AppError::WrongPasswordOrCorrupt` via AEAD tag failure — there is no
    /// separate verifier field.
    ///
    /// A v1 file is upgraded in place first, transparently.
    pub fn load(&self, master_password: &str) -> Result<Unlocked> {
        let bytes = self.read_file()?;

        let envelope = match format::decode_any(&bytes)? {
            AnyEnvelope::V2(envelope) => envelope,
            AnyEnvelope::V1(v1) => return self.upgrade_v1(v1, master_password),
        };

        let slot = keyslot::find(&envelope.slots, SLOT_PASSWORD)
            .ok_or(AppError::WrongPasswordOrCorrupt)?;
        let master_key = keyslot::unwrap_password(slot, master_password)?;

        let config = decrypt_body(&envelope, &master_key)?;
        Ok(Unlocked { config, master_key, slots: envelope.slots })
    }

    /// Re-encrypts and writes `config` under the already-unwrapped master key
    /// (no re-run of Argon2id) with a freshly-generated nonce.
    pub fn save(&self, config: &Config, master_key: &MasterKey, slots: &[Slot]) -> Result<()> {
        self.write(config, master_key, slots)
    }

    fn read_file(&self) -> Result<Vec<u8>> {
        fs::read(&self.path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                AppError::ConfigNotFound(self.path.clone())
            } else {
                AppError::Io(e)
            }
        })
    }

    /// Converts a pre-keyslot vault, whose Argon2id output *was* the vault key,
    /// into a v2 file with one password slot. Runs once, invisibly, the first
    /// time an old vault is opened.
    ///
    /// This is an *envelope* upgrade, distinct from the `schema_version`
    /// migration inside the decrypted JSON that issue #7 covers — the two axes
    /// move independently and neither implies the other.
    fn upgrade_v1(&self, v1: format::EnvelopeV1, master_password: &str) -> Result<Unlocked> {
        let old_key = kdf::derive_key(master_password, &v1.salt, v1.kdf_params)?;
        let aad = format::header_aad_v1(&v1);
        let plaintext = cipher::decrypt(&old_key, &v1.nonce, &aad, &v1.ciphertext)?;
        let config: Config = serde_json::from_slice(&plaintext).map_err(|e| AppError::CorruptFile(e.to_string()))?;

        // The upgraded file keeps the cost parameters the old one was written
        // with, so a vault someone deliberately tuned is not silently reset.
        let master_key = cipher::random_master_key()?;
        let slots = vec![keyslot::wrap_password(master_password, v1.kdf_params, &master_key)?];

        // `write_file_atomic` means a failure here leaves the readable v1 file
        // in place; the next launch simply tries the upgrade again.
        self.write(&config, &master_key, &slots)?;

        Ok(Unlocked { config, master_key, slots })
    }

    fn write(&self, config: &Config, master_key: &MasterKey, slots: &[Slot]) -> Result<()> {
        if slots.is_empty() {
            return Err(AppError::Crypto("refusing to write a vault with no key slots".into()));
        }

        let aad = format::header_aad(slots);
        // Wiped on drop: this buffer holds every credential in the vault in the
        // clear, and the vault is rewritten on every connect. `cipher::decrypt`
        // already returns `Zeroizing` for the same reason on the read side.
        let plaintext = Zeroizing::new(serde_json::to_vec(config)?);
        let nonce = cipher::random_nonce()?;
        let ciphertext = cipher::encrypt(master_key, &nonce, &aad, &plaintext)?;
        let bytes = format::encode(slots, &nonce, &ciphertext);

        write_file_atomic(&self.path, &bytes)
    }
}

pub fn shape_of(slots: &[Slot]) -> VaultShape {
    match (keyslot::has(slots, SLOT_PASSWORD), keyslot::has(slots, format::SLOT_DEVICE)) {
        (true, true) => VaultShape::DeviceAndPassword,
        (false, true) => VaultShape::Device,
        // A vault with neither cannot be written (`ConfigStore::write` refuses),
        // so "no device slot" means password.
        _ => VaultShape::Password,
    }
}

fn decrypt_body(envelope: &format::Envelope, master_key: &MasterKey) -> Result<Config> {
    let aad = format::header_aad(&envelope.slots);
    let plaintext = cipher::decrypt(master_key, &envelope.nonce, &aad, &envelope.ciphertext)?;
    serde_json::from_slice(&plaintext).map_err(|e| AppError::CorruptFile(e.to_string()))
}

/// Writes `bytes` to `path` without ever leaving a partially-written file
/// behind: the content goes to a sibling `.tmp` file (same directory, so the
/// rename stays within one filesystem), is flushed to disk, and only then
/// replaces `path` via an atomic rename. A crash or I/O failure at any point
/// leaves the previous `path` fully intact — important because the vault has
/// no backup copy and is rewritten on every connect.
fn write_file_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        set_dir_permissions(parent)?;
    }

    let tmp_path = tmp_sibling(path);
    // Scoped so the handle is closed before the rename (required on Windows,
    // harmless on unix).
    {
        let mut file = fs::File::create(&tmp_path)?;
        set_file_permissions(&tmp_path)?;
        if let Err(e) = file.write_all(bytes).and_then(|()| file.sync_all()) {
            let _ = fs::remove_file(&tmp_path);
            return Err(AppError::Io(e));
        }
    }

    if let Err(e) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(AppError::Io(e));
    }

    // Best-effort: makes the rename itself durable, not just the file
    // contents. Not every platform/filesystem allows opening a directory, so
    // a failure here is ignored rather than failing an otherwise-good write.
    if let Some(parent) = path.parent()
        && let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }

    Ok(())
}

fn tmp_sibling(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".tmp");
    path.with_file_name(name)
}

#[cfg(unix)]
fn set_dir_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_dir_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}
