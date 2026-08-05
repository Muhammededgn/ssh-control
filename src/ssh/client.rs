use std::sync::{Arc, Mutex};

use russh::client;
use russh::keys::{HashAlg, PublicKey};

use crate::error::AppError;

/// Result of the TOFU (trust-on-first-connect) host-key check, recorded by
/// `Handler::check_server_key` so `ssh::session::connect` can inspect it after
/// the handshake completes (or fails).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostKeyOutcome {
    /// Fingerprint matched the one already stored for this server.
    Trusted,
    /// No fingerprint was stored yet; this one was accepted and should now be
    /// persisted onto the `ServerEntry`.
    FirstConnect { fingerprint: String },
    /// Fingerprint did not match the stored one — connection is rejected.
    Mismatch { expected: String, actual: String },
}

/// russh client handler. Its only job is the TOFU host-key check; everything
/// else uses default (no-op) trait method implementations.
pub struct Handler {
    expected_fingerprint: Option<String>,
    pub outcome: Arc<Mutex<Option<HostKeyOutcome>>>,
}

impl Handler {
    pub fn new(expected_fingerprint: Option<String>) -> Self {
        Self {
            expected_fingerprint,
            outcome: Arc::new(Mutex::new(None)),
        }
    }
}

impl client::Handler for Handler {
    type Error = AppError;

    async fn check_server_key(&mut self, server_public_key: &PublicKey) -> Result<bool, Self::Error> {
        let actual = server_public_key.fingerprint(HashAlg::Sha256).to_string();

        let (accept, result) = match &self.expected_fingerprint {
            None => (true, HostKeyOutcome::FirstConnect { fingerprint: actual }),
            Some(expected) if *expected == actual => (true, HostKeyOutcome::Trusted),
            Some(expected) => (
                false,
                HostKeyOutcome::Mismatch {
                    expected: expected.clone(),
                    actual,
                },
            ),
        };

        *self.outcome.lock().expect("outcome mutex poisoned") = Some(result);
        Ok(accept)
    }
}
