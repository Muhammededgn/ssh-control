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
}

pub type Result<T> = std::result::Result<T, AppError>;
