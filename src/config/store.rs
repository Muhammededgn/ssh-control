use std::fs;
use std::path::{Path, PathBuf};

use directories::ProjectDirs;
use zeroize::Zeroizing;

use super::format::{self, Header, KDF_ARGON2ID, FORMAT_VERSION};
use super::model::Config;
use crate::crypto::{cipher, kdf};
use crate::error::{AppError, Result};

const CONFIG_FILE_NAME: &str = "config.enc";
const PREFS_FILE_NAME: &str = "prefs.lang";
const TOTP_ONLY_FILE_NAME: &str = "totp-only.secret";

/// The unlocked state produced by `ConfigStore::init` (first run) or
/// `ConfigStore::load` (subsequent runs). The key is kept for the process's
/// unlocked lifetime so later saves don't need to re-run Argon2id.
pub struct Unlocked {
    pub config: Config,
    pub key: Zeroizing<[u8; kdf::KEY_LEN]>,
    pub salt: [u8; kdf::SALT_LEN],
    pub params: kdf::KdfParams,
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

    /// Path for the "TOTP-only" mode secret — deliberately **unencrypted**
    /// (plain text, like `prefs_path`), because in this mode there is no
    /// password to protect it with: the app must be able to read it before
    /// any user input at all, purely from a live 6-digit code. See the
    /// TOTP-only threat-model note in the plan/docs — this file being
    /// readable is the accepted tradeoff of that mode, not an oversight.
    fn totp_only_secret_path(&self) -> PathBuf {
        self.path.with_file_name(TOTP_ONLY_FILE_NAME)
    }

    pub fn totp_only_secret_exists(&self) -> bool {
        self.totp_only_secret_path().exists()
    }

    pub fn read_totp_only_secret(&self) -> Result<String> {
        Ok(fs::read_to_string(self.totp_only_secret_path())?)
    }

    pub fn write_totp_only_secret(&self, secret_base32: &str) -> Result<()> {
        write_file_atomic(&self.totp_only_secret_path(), secret_base32.as_bytes())
    }

    /// Deletes the TOTP-only secret outright, sending the app back to
    /// password mode on the next launch. Used to roll back a half-applied
    /// switch *into* TOTP-only mode.
    pub fn discard_totp_only_secret(&self) {
        let _ = fs::remove_file(self.totp_only_secret_path());
    }

    /// Moves the TOTP-only secret aside so the app boots into password mode,
    /// while keeping the file recoverable via `restore_totp_only_secret` if
    /// the rest of the mode switch fails. Returns `true` if a file was
    /// actually moved.
    pub fn stash_totp_only_secret(&self) -> Result<bool> {
        let path = self.totp_only_secret_path();
        if !path.exists() {
            return Ok(false);
        }
        fs::rename(&path, tmp_sibling(&path))?;
        Ok(true)
    }

    pub fn restore_totp_only_secret(&self) -> Result<()> {
        let path = self.totp_only_secret_path();
        fs::rename(tmp_sibling(&path), &path)?;
        Ok(())
    }

    pub fn discard_stashed_totp_only_secret(&self) {
        let _ = fs::remove_file(tmp_sibling(&self.totp_only_secret_path()));
    }

    /// First-run setup: generates a fresh salt, derives the key, and writes an
    /// empty encrypted config.
    pub fn init(&self, master_password: &str) -> Result<Unlocked> {
        let salt = cipher::random_salt()?;
        let params = kdf::KdfParams::INTERACTIVE;
        let key = kdf::derive_key(master_password, &salt, params)?;
        let config = Config::default();

        self.write(&config, &key, &salt, params)?;

        Ok(Unlocked { config, key, salt, params })
    }

    /// Subsequent-run unlock: reads the file, re-derives the key from the
    /// stored salt/params, and decrypts. A wrong password surfaces as
    /// `AppError::WrongPasswordOrCorrupt` via AEAD tag failure — there is no
    /// separate verifier field.
    pub fn load(&self, master_password: &str) -> Result<Unlocked> {
        let bytes = fs::read(&self.path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                AppError::ConfigNotFound(self.path.clone())
            } else {
                AppError::Io(e)
            }
        })?;

        let envelope = format::decode(&bytes)?;
        let params = envelope.header.kdf_params;
        let salt = envelope.header.salt;
        let key = kdf::derive_key(master_password, &salt, params)?;

        let aad = format::header_aad(&envelope.header);
        let plaintext = cipher::decrypt(&key, &envelope.nonce, &aad, &envelope.ciphertext)?;

        let config: Config =
            serde_json::from_slice(&plaintext).map_err(|e| AppError::CorruptFile(e.to_string()))?;

        Ok(Unlocked { config, key, salt, params })
    }

    /// Re-encrypts and writes `config` using the already-derived key (no
    /// re-run of Argon2id) with a freshly-generated nonce.
    pub fn save(
        &self,
        config: &Config,
        key: &Zeroizing<[u8; kdf::KEY_LEN]>,
        salt: &[u8; kdf::SALT_LEN],
        params: kdf::KdfParams,
    ) -> Result<()> {
        self.write(config, key, salt, params)
    }

    fn write(
        &self,
        config: &Config,
        key: &Zeroizing<[u8; kdf::KEY_LEN]>,
        salt: &[u8; kdf::SALT_LEN],
        params: kdf::KdfParams,
    ) -> Result<()> {
        let header = Header {
            format_version: FORMAT_VERSION,
            kdf_id: KDF_ARGON2ID,
            kdf_params: params,
            salt: *salt,
        };
        let aad = format::header_aad(&header);
        let plaintext = serde_json::to_vec(config)?;
        let nonce = cipher::random_nonce()?;
        let ciphertext = cipher::encrypt(key, &nonce, &aad, &plaintext)?;
        let bytes = format::encode(&header, &nonce, &ciphertext);

        write_file_atomic(&self.path, &bytes)
    }
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
