//! Device-bound state, kept in the OS credential store rather than next to the
//! vault.
//!
//! This is the whole mechanism behind "ask for the password when the config is
//! copied to another machine". The key material for the everyday unlock lives
//! *outside* the config directory, so copying `config.enc` somewhere else
//! brings the vault but not the means to open it — the copy falls back to the
//! password slot, which is exactly the intended behaviour.
//!
//! What it does **not** protect against: another process running as the same
//! user in an unlocked session can ask the credential store for this entry just
//! as the app can. The threat this addresses is a stolen disk, a backup, a
//! synced dotfile repository or a plain `cp` — not local malware.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::secret::Secret;
use crate::crypto::kdf::KEY_LEN;
use crate::error::{AppError, Result};

const KEYRING_SERVICE: &str = "ssh-control";
const DEVICE_KEY_LEN: usize = 32;

/// Domain separation for the device slot's key-encryption key. Changing this
/// string makes every enrolled device unable to unwrap its slot, so it is
/// versioned rather than edited.
const HKDF_INFO: &[u8] = b"ssh-control device slot v1";

/// Whether a usable Secret Service is reachable at all.
///
/// Probed rather than assumed: on a headless box there is typically no D-Bus
/// session bus and no unlocked keyring daemon, and the modes that depend on one
/// are offered to the user only when this returns `true`. Installing a keyring
/// package does not make this true — the daemon has to be running and unlocked,
/// which normally happens at graphical login.
pub fn credential_store_available() -> bool {
    keyring::Entry::store_status().is_ok()
}

/// Everything about this device's relationship to one vault. Serialised as a
/// single JSON blob into one credential-store entry.
///
/// The counters live here, beside the device key, on purpose: an attacker who
/// clears `failed_attempts` to keep guessing has to destroy `device_key` in the
/// same move, which forces the password path anyway. The state cannot be rolled
/// back without losing the thing it guards.
#[derive(Clone, Serialize, Deserialize)]
pub struct DeviceState {
    /// The device key, base64 of 32 random bytes. `Secret` so it wipes itself.
    device_key: Secret,
    /// Present only in the mode where TOTP is the daily factor; the secret has
    /// to be readable before the vault is open, so it cannot live inside it.
    #[serde(default)]
    pub totp_secret: Option<Secret>,
    /// Highest TOTP step already accepted. A code at or below this is a replay.
    #[serde(default)]
    pub replay_step: u64,
    #[serde(default)]
    pub failed_attempts: u32,
    #[serde(default)]
    pub last_password_check_unix: u64,
}

impl std::fmt::Debug for DeviceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceState")
            .field("device_key", &"<redacted>")
            .field("totp_secret", &self.totp_secret.as_ref().map(|_| "<redacted>"))
            .field("replay_step", &self.replay_step)
            .field("failed_attempts", &self.failed_attempts)
            .field("last_password_check_unix", &self.last_password_check_unix)
            .finish()
    }
}

impl DeviceState {
    /// A newly enrolled device: fresh key, no TOTP, counters clear.
    pub fn new() -> Result<Self> {
        let mut raw = Zeroizing::new([0u8; DEVICE_KEY_LEN]);
        getrandom::fill(raw.as_mut_slice()).map_err(|e| AppError::Crypto(e.to_string()))?;
        Ok(Self {
            device_key: Secret::from(BASE64.encode(raw.as_slice())),
            totp_secret: None,
            replay_step: 0,
            failed_attempts: 0,
            last_password_check_unix: now_unix(),
        })
    }

    pub fn device_key(&self) -> Result<Zeroizing<[u8; DEVICE_KEY_LEN]>> {
        let decoded = Zeroizing::new(
            BASE64
                .decode(self.device_key.as_str())
                .map_err(|e| AppError::Keyring(format!("device key is not valid base64: {e}")))?,
        );
        let key: [u8; DEVICE_KEY_LEN] = decoded
            .as_slice()
            .try_into()
            .map_err(|_| AppError::Keyring("device key has the wrong length".into()))?;
        Ok(Zeroizing::new(key))
    }

    /// Marks a successful password unlock, which is what clears an escalation.
    pub fn record_password_check(&mut self) {
        self.last_password_check_unix = now_unix();
        self.failed_attempts = 0;
    }

    /// Whether the everyday path should be refused in favour of the password.
    ///
    /// `max_failed` of 0 or `max_age_days` of 0 disables that trigger, matching
    /// how `auto_lock_minutes` treats 0.
    pub fn must_escalate(&self, max_failed: u32, max_age_days: u32) -> bool {
        if max_failed > 0 && self.failed_attempts >= max_failed {
            return true;
        }
        if max_age_days > 0 {
            let age = now_unix().saturating_sub(self.last_password_check_unix);
            if age > u64::from(max_age_days) * 86_400 {
                return true;
            }
        }
        false
    }
}

/// The key-encryption key for a device slot.
///
/// HKDF rather than Argon2: the input is already 32 uniformly random bytes, so
/// there is nothing to stretch and a memory-hard KDF would only cost the user
/// time. Argon2 is for the password slots, where the input is guessable.
pub fn device_kek(device_key: &[u8; DEVICE_KEY_LEN], salt: &[u8; 16]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let hk = Hkdf::<Sha256>::new(Some(salt), device_key);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(HKDF_INFO, out.as_mut_slice())
        .map_err(|e| AppError::Kdf(format!("hkdf expand failed: {e}")))?;
    Ok(out)
}

/// One vault's entry in the OS credential store.
pub struct DeviceStore {
    entry: keyring::Entry,
}

impl DeviceStore {
    /// `vault_id` scopes the entry so two vaults on one machine — say a
    /// personal one and one under `--config` — never share device state.
    pub fn open(vault_id: &str) -> Result<Self> {
        let entry = keyring::Entry::new(KEYRING_SERVICE, vault_id)
            .map_err(|e| AppError::Keyring(e.to_string()))?;
        Ok(Self { entry })
    }

    /// `Ok(None)` means this device is not enrolled — a normal state, and the
    /// signal that a copied vault has landed somewhere new. Only a genuine
    /// store failure is an error.
    pub fn read(&self) -> Result<Option<DeviceState>> {
        match self.entry.get_secret() {
            Ok(bytes) => {
                let bytes = Zeroizing::new(bytes);
                let state = serde_json::from_slice(&bytes)
                    .map_err(|e| AppError::Keyring(format!("stored device state is unreadable: {e}")))?;
                Ok(Some(state))
            }
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(AppError::Keyring(e.to_string())),
        }
    }

    pub fn write(&self, state: &DeviceState) -> Result<()> {
        let bytes = Zeroizing::new(serde_json::to_vec(state)?);
        self.entry.set_secret(&bytes).map_err(|e| AppError::Keyring(e.to_string()))
    }

    /// Best-effort removal. A device that cannot be un-enrolled is not a reason
    /// to fail the operation that asked for it — the vault is still openable by
    /// password, and a stale entry only wastes a keyring slot.
    pub fn delete(&self) {
        let _ = self.entry.delete_credential();
    }
}

/// Wall-clock seconds, saturating to 0 rather than panicking on a clock set
/// before the epoch. Shared with `app.rs`, which stamps the same kind of
/// timestamp onto a server entry after a connect.
pub(crate) fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_device_key_round_trips_through_base64() {
        let state = DeviceState::new().expect("generating a device key should work");
        let key = state.device_key().expect("the key should decode");
        assert_eq!(key.len(), DEVICE_KEY_LEN);
        assert_ne!(*key, [0u8; DEVICE_KEY_LEN], "the key must not be all zeroes");
    }

    #[test]
    fn two_devices_get_different_keys() {
        let a = DeviceState::new().expect("generate a");
        let b = DeviceState::new().expect("generate b");
        assert_ne!(*a.device_key().expect("a"), *b.device_key().expect("b"));
    }

    #[test]
    fn the_kek_is_deterministic_for_a_key_and_salt() {
        let key = [3u8; DEVICE_KEY_LEN];
        let first = device_kek(&key, &[1u8; 16]).expect("derive");
        let second = device_kek(&key, &[1u8; 16]).expect("derive again");
        assert_eq!(*first, *second);
    }

    #[test]
    fn a_different_salt_or_key_gives_a_different_kek() {
        let base = device_kek(&[3u8; DEVICE_KEY_LEN], &[1u8; 16]).expect("derive");
        assert_ne!(*base, *device_kek(&[3u8; DEVICE_KEY_LEN], &[2u8; 16]).expect("other salt"));
        assert_ne!(*base, *device_kek(&[4u8; DEVICE_KEY_LEN], &[1u8; 16]).expect("other key"));
    }

    #[test]
    fn state_serialises_without_leaking_through_debug() {
        let state = DeviceState::new().expect("generate");
        let rendered = format!("{state:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains(state.device_key.as_str()));
    }

    #[test]
    fn state_round_trips_through_json() {
        let mut original = DeviceState::new().expect("generate");
        original.totp_secret = Some(Secret::from("JBSWY3DPEHPK3PXP".to_string()));
        original.replay_step = 42;
        original.failed_attempts = 3;

        let json = serde_json::to_vec(&original).expect("serialize");
        let restored: DeviceState = serde_json::from_slice(&json).expect("deserialize");

        assert_eq!(*restored.device_key().expect("key"), *original.device_key().expect("key"));
        assert_eq!(restored.totp_secret.as_ref().map(|s| s.as_str()), Some("JBSWY3DPEHPK3PXP"));
        assert_eq!(restored.replay_step, 42);
        assert_eq!(restored.failed_attempts, 3);
    }

    #[test]
    fn too_many_failures_forces_the_password() {
        let mut state = DeviceState::new().expect("generate");
        assert!(!state.must_escalate(5, 30));
        state.failed_attempts = 5;
        assert!(state.must_escalate(5, 30));
        // A threshold of 0 turns the trigger off, like auto_lock_minutes.
        assert!(!state.must_escalate(0, 30));
    }

    #[test]
    fn a_stale_password_check_forces_the_password() {
        let mut state = DeviceState::new().expect("generate");
        assert!(!state.must_escalate(5, 30));

        state.last_password_check_unix = now_unix() - 31 * 86_400;
        assert!(state.must_escalate(5, 30));
        assert!(!state.must_escalate(5, 0), "0 days must disable the periodic trigger");

        state.record_password_check();
        assert!(!state.must_escalate(5, 30), "a successful password unlock clears it");
    }
}
