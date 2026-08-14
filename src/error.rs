use std::path::PathBuf;

#[derive(thiserror::Error, Debug)]
pub enum AppError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("could not determine config directory")]
    NoConfigDir,

    #[error("config file not found at {0}")]
    ConfigNotFound(PathBuf),

    #[error("incorrect password")]
    WrongPasswordOrCorrupt,

    #[error("not a ssh-control config file")]
    NotOurFile,

    #[error("unsupported config format version {0}")]
    UnsupportedFormatVersion(u8),

    #[error("config file is corrupt: {0}")]
    CorruptFile(String),

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("validation error: {0}")]
    Validation(String),

    #[error("connection failed: {0}")]
    SshConnect(String),

    #[error("authentication failed: {0}")]
    SshAuthFailed(String),

    #[error("ssh error: {0}")]
    Ssh(#[from] russh::Error),

    #[error("host key changed for this server: new fingerprint {fingerprint}")]
    HostKeyChanged { fingerprint: String },

    #[error("key derivation error: {0}")]
    Kdf(String),

    #[error("encryption error: {0}")]
    Crypto(String),

    /// Another running instance holds this vault's advisory lock. Transient by
    /// nature — deliberately distinct from the errors that mean the vault
    /// itself cannot be opened, because the fix is "close the other window",
    /// not "find your password".
    #[error("another instance of ssh-control already has this vault open")]
    VaultInUse,

    /// The OS credential store could not be reached or did not hold what was
    /// expected. Deliberately distinct from a missing entry, which is a normal
    /// outcome that means "this device is not enrolled" rather than a failure.
    #[error("credential store error: {0}")]
    Keyring(String),
}

pub type Result<T> = std::result::Result<T, AppError>;
