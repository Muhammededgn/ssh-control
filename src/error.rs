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

    /// The decrypted config was written by a newer version of ssh-control.
    ///
    /// Refused rather than opened: serde drops fields it does not know and
    /// every save rewrites the whole config, so opening it would quietly
    /// destroy whatever the newer version had stored.
    #[error("this vault was written by a newer version of ssh-control (schema {found}, this build understands {supported}) — upgrade to open it")]
    SchemaTooNew { found: u32, supported: u32 },

    /// Another running instance holds this vault's advisory lock. Transient by
    /// nature — deliberately distinct from the errors that mean the vault
    /// itself cannot be opened, because the fix is "close the other window",
    /// not "find your password".
    #[error("another instance of ssh-control already has this vault open")]
    VaultInUse,

    /// A malformed frame, a desynced stream, a reply whose request id does not
    /// match, or a subsystem the server would not start. The stream cannot be
    /// trusted afterwards, so every one of these drops the session rather than
    /// retrying the operation.
    #[error("sftp error: {0}")]
    Sftp(String),

    /// The server answered, and said no. Carries the code because the browser
    /// reacts differently to a denied listing (stay put, show it on that pane)
    /// than to a lost connection (drop the session).
    #[error("{message} ({path})")]
    SftpStatus { code: u32, path: String, message: String },

    /// The OS credential store could not be reached or did not hold what was
    /// expected. Deliberately distinct from a missing entry, which is a normal
    /// outcome that means "this device is not enrolled" rather than a failure.
    #[error("credential store error: {0}")]
    Keyring(String),
}

pub type Result<T> = std::result::Result<T, AppError>;
