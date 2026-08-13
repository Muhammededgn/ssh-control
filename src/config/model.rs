use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::secret::Secret;

pub const DEFAULT_PORT: u16 = 22;
pub const CURRENT_SCHEMA_VERSION: u32 = 1;
/// Idle minutes before the vault re-locks itself. A file written before this
/// field existed gets the protective default rather than "off" — an old vault
/// should not stay unlocked forever just because it predates the feature.
pub const DEFAULT_AUTO_LOCK_MINUTES: u32 = 15;

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
    /// Minutes of no key input before `App` drops back to the locked state.
    /// `0` disables it. Lives inside the encrypted config (rather than beside
    /// it like `prefs.lang`) because nothing needs to read it before unlock.
    #[serde(default = "default_auto_lock_minutes")]
    pub auto_lock_minutes: u32,
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

fn default_auto_lock_minutes() -> u32 {
    DEFAULT_AUTO_LOCK_MINUTES
}

impl Default for Config {
    fn default() -> Self {
        Self {
            schema_version: CURRENT_SCHEMA_VERSION,
            servers: Vec::new(),
            totp: None,
            auto_lock_minutes: DEFAULT_AUTO_LOCK_MINUTES,
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

/// Credentials are held in `Secret`, never `String`, so every copy made along
/// the way — deserialization, a form submission, the `ssh::Target` a connect
/// flow carries — wipes itself on drop. `Secret` serializes as a bare string,
/// so the on-disk shape is unchanged.
#[derive(Clone, Serialize, Deserialize)]
pub enum AuthMethod {
    Password { password: Secret },
    SshKey { key_path: String, passphrase: Option<Secret> },
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

impl AuthMethod {
    pub fn password(password: impl Into<String>) -> Self {
        AuthMethod::Password { password: Secret::from(password.into()) }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Exactly what a vault written before `Secret` and `auto_lock_minutes`
    /// existed contains. Decryption hands this to `serde_json`, so if it stops
    /// parsing, every already-written vault is unopenable.
    const LEGACY_CONFIG_JSON: &str = r#"{
        "schema_version": 1,
        "servers": [{
            "id": "6f1e7f3a-0000-4000-8000-00000000cafe",
            "name": "box",
            "host": "example.com",
            "port": 22,
            "username": "root",
            "auth": { "Password": { "password": "hunter2" } }
        }],
        "totp": null
    }"#;

    #[test]
    fn legacy_config_without_the_new_fields_still_loads() {
        let config: Config = serde_json::from_str(LEGACY_CONFIG_JSON).expect("an existing vault must still deserialize");
        assert_eq!(config.auto_lock_minutes, DEFAULT_AUTO_LOCK_MINUTES);
        let AuthMethod::Password { password } = &config.servers[0].auth else {
            panic!("expected password auth");
        };
        assert_eq!(password.as_str(), "hunter2");
    }

    #[test]
    fn credentials_serialize_as_bare_strings() {
        let entry = ServerEntry::new("box".into(), "example.com".into(), DEFAULT_PORT, "root".into(), AuthMethod::password("hunter2"));
        let json = serde_json::to_string(&entry.auth).unwrap();
        assert_eq!(json, r#"{"Password":{"password":"hunter2"}}"#);

        let key_auth = AuthMethod::SshKey { key_path: "/k".into(), passphrase: Some(Secret::from("pp".to_string())) };
        assert_eq!(serde_json::to_string(&key_auth).unwrap(), r#"{"SshKey":{"key_path":"/k","passphrase":"pp"}}"#);
    }

    #[test]
    fn debug_never_prints_a_credential() {
        let entry = ServerEntry::new("box".into(), "example.com".into(), DEFAULT_PORT, "root".into(), AuthMethod::password("hunter2"));
        assert!(!format!("{entry:?}").contains("hunter2"));
    }
}
