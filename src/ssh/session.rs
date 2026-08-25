use std::sync::Arc;
use std::time::Duration;

use russh::client;
use russh::keys::agent::AgentIdentity;
use russh::keys::agent::client::AgentClient;
use russh::keys::{PrivateKeyWithHashAlg, load_secret_key};

use super::client::{Handler, HostKeyOutcome};
use crate::config::{AuthMethod, ServerEntry};
use crate::error::{AppError, Result};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub struct Connected {
    pub handle: client::Handle<Handler>,
    pub host_key_outcome: HostKeyOutcome,
}

/// Everything `connect` needs from a `ServerEntry`, and nothing else.
///
/// The connect flows in `app.rs` have to own their input across an `.await`
/// (no borrow of `App::state` may be held that long — see the `NextStep`
/// pattern), so they build one of these instead of cloning the whole entry
/// with its name, `system_info` and every `Script`. The credential copy that
/// remains is a `Secret`, so it is wiped when the `Target` drops.
pub struct Target {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth: AuthMethod,
    pub host_key_fingerprint: Option<String>,
}

impl Target {
    pub fn from_entry(entry: &ServerEntry) -> Self {
        Self {
            host: entry.host.clone(),
            port: entry.port,
            username: entry.username.clone(),
            auth: entry.auth.clone(),
            host_key_fingerprint: entry.host_key_fingerprint.clone(),
        }
    }
}

/// Establishes and authenticates an SSH connection to `server`. This is the
/// shared core reused both by the interactive PTY passthrough (phase 1) and,
/// in the future, by scripted command execution — only what happens with the
/// resulting `Handle` (open a `request_pty` shell vs. `channel.exec`) differs.
pub async fn connect(server: &Target) -> Result<Connected> {
    let config = Arc::new(client::Config::default());
    let handler = Handler::new(server.host_key_fingerprint.clone());
    let outcome_ref = handler.outcome.clone();

    let addr = (server.host.as_str(), server.port);
    let connect_result = tokio::time::timeout(CONNECT_TIMEOUT, client::connect(config, addr, handler))
        .await
        .map_err(|_| AppError::SshConnect("connection timed out".into()))?;

    let mut handle = match connect_result {
        Ok(handle) => handle,
        Err(e) => {
            let outcome = outcome_ref.lock().expect("outcome mutex poisoned").clone();
            if let Some(HostKeyOutcome::Mismatch { actual, .. }) = outcome {
                return Err(AppError::HostKeyChanged { fingerprint: actual });
            }
            return Err(e);
        }
    };

    authenticate(&mut handle, server).await?;

    let host_key_outcome = outcome_ref
        .lock()
        .expect("outcome mutex poisoned")
        .clone()
        .unwrap_or(HostKeyOutcome::Trusted);

    Ok(Connected { handle, host_key_outcome })
}

async fn authenticate(handle: &mut client::Handle<Handler>, server: &Target) -> Result<()> {
    let auth_result = match &server.auth {
        // russh takes the password by value and we cannot reach inside it to
        // wipe it afterwards — this hand-off is the end of the line for what
        // `Secret` can protect, not an oversight.
        AuthMethod::Password { password } => {
            handle
                .authenticate_password(server.username.clone(), password.as_str().to_string())
                .await?
        }
        AuthMethod::SshKey { key_path, passphrase } => {
            let key = load_secret_key(key_path, passphrase.as_ref().map(|p| p.as_str()))
                .map_err(|e| AppError::SshAuthFailed(format!("failed to load key '{key_path}': {e}")))?;
            let hash_alg = handle.best_supported_rsa_hash().await?.flatten();
            let key_with_hash = PrivateKeyWithHashAlg::new(Arc::new(key), hash_alg);
            handle
                .authenticate_publickey(server.username.clone(), key_with_hash)
                .await?
        }
        AuthMethod::Agent => return authenticate_via_agent(handle, &server.username).await,
    };

    match auth_result {
        client::AuthResult::Success => Ok(()),
        client::AuthResult::Failure { .. } => {
            Err(AppError::SshAuthFailed("credentials rejected by server".into()))
        }
    }
}

/// Public-key authentication where the key never leaves the agent.
///
/// **Every identity is tried, not just the first.** An agent commonly holds
/// several keys and only one of them is in this host's `authorized_keys`;
/// offering one and giving up is the difference between "works" and a bare
/// "credentials rejected by server", which would send the user to look at the
/// wrong machine.
///
/// The three ways this can fail before a server ever sees a signature — no
/// agent configured, a socket that is gone, an agent holding nothing — are all
/// `AppError::SshAgent` rather than `SshAuthFailed`, because in none of them is
/// there anything wrong with the user's account on the remote host.
async fn authenticate_via_agent(handle: &mut client::Handle<Handler>, username: &str) -> Result<()> {
    let mut agent = AgentClient::connect_env().await.map_err(|e| {
        AppError::SshAgent(match e {
            russh::keys::Error::EnvVar(_) => "SSH_AUTH_SOCK is not set — no agent is running".to_string(),
            russh::keys::Error::BadAuthSock => "SSH_AUTH_SOCK points at a socket that is not there — the agent has gone away".to_string(),
            other => format!("could not reach the agent: {other}"),
        })
    })?;

    let identities = agent
        .request_identities()
        .await
        .map_err(|e| AppError::SshAgent(format!("could not list the agent's keys: {e}")))?;

    // Certificates need `authenticate_certificate_with` and a different reply
    // shape; skipping them here loses nothing an agent-only user has today.
    let keys: Vec<_> = identities
        .into_iter()
        .filter_map(|id| match id {
            AgentIdentity::PublicKey { key, .. } => Some(key),
            AgentIdentity::Certificate { .. } => None,
        })
        .collect();

    if keys.is_empty() {
        return Err(AppError::SshAgent("the agent is running but holds no usable keys — try `ssh-add`".into()));
    }

    let hash_alg = handle.best_supported_rsa_hash().await?.flatten();

    for key in keys {
        let attempt = handle
            .authenticate_publickey_with(username.to_string(), key, hash_alg, &mut agent)
            .await
            // `S::Error` here is russh's `AgentAuthError`, not `russh::Error`,
            // so there is no `From` to lean on.
            .map_err(|e| AppError::SshAgent(format!("the agent refused to sign: {e}")))?;
        if let client::AuthResult::Success = attempt {
            return Ok(());
        }
    }

    Err(AppError::SshAuthFailed("the server accepted none of the agent's keys".into()))
}
