use std::sync::Arc;
use std::time::Duration;

use russh::client;
use russh::keys::{PrivateKeyWithHashAlg, load_secret_key};

use super::client::{Handler, HostKeyOutcome};
use crate::config::{AuthMethod, ServerEntry};
use crate::error::{AppError, Result};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub struct Connected {
    pub handle: client::Handle<Handler>,
    pub host_key_outcome: HostKeyOutcome,
}

/// Establishes and authenticates an SSH connection to `server`. This is the
/// shared core reused both by the interactive PTY passthrough (phase 1) and,
/// in the future, by scripted command execution — only what happens with the
/// resulting `Handle` (open a `request_pty` shell vs. `channel.exec`) differs.
pub async fn connect(server: &ServerEntry) -> Result<Connected> {
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

async fn authenticate(handle: &mut client::Handle<Handler>, server: &ServerEntry) -> Result<()> {
    let auth_result = match &server.auth {
        AuthMethod::Password { password } => {
            handle
                .authenticate_password(server.username.clone(), password.clone())
                .await?
        }
        AuthMethod::SshKey { key_path, passphrase } => {
            let key = load_secret_key(key_path, passphrase.as_deref())
                .map_err(|e| AppError::SshAuthFailed(format!("failed to load key '{key_path}': {e}")))?;
            let hash_alg = handle.best_supported_rsa_hash().await?.flatten();
            let key_with_hash = PrivateKeyWithHashAlg::new(Arc::new(key), hash_alg);
            handle
                .authenticate_publickey(server.username.clone(), key_with_hash)
                .await?
        }
    };

    match auth_result {
        client::AuthResult::Success => Ok(()),
        client::AuthResult::Failure { .. } => {
            Err(AppError::SshAuthFailed("credentials rejected by server".into()))
        }
    }
}
