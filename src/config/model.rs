use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const DEFAULT_PORT: u16 = 22;
pub const CURRENT_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    #[serde(default)]
    pub servers: Vec<ServerEntry>,
    /// Present only in "Password + TOTP (2FA)" mode. Rides inside this
    /// already-AES-GCM-encrypted blob, so no extra crypto layer is needed —
    /// the master password protects it exactly like everything else here.
    #[serde(default)]
    pub totp: Option<TotpConfig>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TotpConfig {
    pub secret_base32: String,
}

impl std::fmt::Debug for TotpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpConfig").field("secret_base32", &"<redacted>").finish()
    }
}

fn default_schema_version() -> u32 {
    CURRENT_SCHEMA_VERSION
}

impl Default for Config {
    fn default() -> Self {
        Self {
            schema_version: CURRENT_SCHEMA_VERSION,
            servers: Vec::new(),
            totp: None,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ServerEntry {
    pub id: Uuid,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth: AuthMethod,
    #[serde(default)]
    pub host_key_fingerprint: Option<String>,
    /// Snapshot from the most recent successful connection, refreshed every
    /// time the user connects. Rides inside the encrypted config like
    /// everything else here — no separate storage/crypto needed.
    #[serde(default)]
    pub system_info: Option<SystemInfo>,
    /// User-defined automation for this server (see `ssh::script_runner`).
    /// Only the definitions are persisted here — a run's live output is
    /// ephemeral and never written back to the encrypted config.
    #[serde(default)]
    pub scripts: Vec<Script>,
}

impl ServerEntry {
    pub fn new(name: String, host: String, port: u16, username: String, auth: AuthMethod) -> Self {
        Self {
            id: Uuid::new_v4(),
            name,
            host,
            port,
            username,
            auth,
            host_key_fingerprint: None,
            system_info: None,
            scripts: Vec::new(),
        }
    }
}

/// A named, ordered sequence of remote shell commands. Each step's
/// `condition` is evaluated against the immediately preceding step's outcome
/// (see `ssh::script_runner::should_run`) — the first step's condition is
/// always treated as `Always` regardless of what's stored here, since there
/// is no preceding step to check.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Script {
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub run_on_connect: bool,
    pub steps: Vec<ScriptStep>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScriptStep {
    pub command: String,
    pub condition: StepCondition,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum StepCondition {
    Always,
    OnSuccess,
    OnFailure,
    OutputContains(String),
}

/// Best-effort hardware snapshot fetched over a one-shot exec channel right
/// after connecting (see `ssh::sysinfo::fetch`). Every field is optional
/// because not every remote shell has every probing tool installed (no
/// `lspci` means no GPU line, etc.) — a partial snapshot is still shown.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct SystemInfo {
    pub cpu_model: Option<String>,
    pub cpu_cores: Option<u32>,
    pub mem_total_bytes: Option<u64>,
    pub mem_used_bytes: Option<u64>,
    pub disk_total_bytes: Option<u64>,
    pub disk_used_bytes: Option<u64>,
    pub gpu_model: Option<String>,
    pub fetched_at_unix: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub enum AuthMethod {
    Password { password: String },
    SshKey { key_path: String, passphrase: Option<String> },
}

impl std::fmt::Debug for AuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthMethod::Password { .. } => f
                .debug_struct("Password")
                .field("password", &"<redacted>")
                .finish(),
            AuthMethod::SshKey { key_path, .. } => f
                .debug_struct("SshKey")
                .field("key_path", key_path)
                .field("passphrase", &"<redacted>")
                .finish(),
        }
    }
}

impl std::fmt::Debug for ServerEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerEntry")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("auth", &self.auth)
            .field("host_key_fingerprint", &self.host_key_fingerprint)
            .field("system_info", &self.system_info)
            .field("scripts", &self.scripts)
            .finish()
    }
}
