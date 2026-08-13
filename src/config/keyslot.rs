//! Wrapping and unwrapping the vault's master key.
//!
//! The vault body is encrypted under a random 32-byte master key that is never
//! derived from user input. Each keyslot holds that same master key wrapped
//! under a different key-encryption key, so a vault can be opened by more than
//! one method, and changing one method rewraps 32 bytes instead of
//! re-encrypting everything.
//!
//! As everywhere else in this codebase, the AES-GCM tag is the only check that
//! a key was right — a failed unwrap and a corrupt slot are deliberately the
//! same error.

use zeroize::Zeroizing;

use crate::config::device;
use crate::config::format::{MK_LEN, SLOT_DEVICE, SLOT_PASSWORD, Slot, WRAPPED_MK_LEN, slot_aad};
use crate::config::format::{KDF_ARGON2ID, KDF_HKDF_SHA256};
use crate::crypto::cipher;
use crate::crypto::kdf::{self, KdfParams};
use crate::error::{AppError, Result};

pub type MasterKey = Zeroizing<[u8; MK_LEN]>;

/// Wraps `master_key` under a key derived from `password`.
pub fn wrap_password(password: &str, params: KdfParams, master_key: &MasterKey) -> Result<Slot> {
    let salt = cipher::random_salt()?;
    let kek = kdf::derive_key(password, &salt, params)?;
    wrap_under(SLOT_PASSWORD, KDF_ARGON2ID, params, salt, &kek, master_key)
}

/// Unwraps the master key from a password slot. A wrong password surfaces as
/// `WrongPasswordOrCorrupt`, same as everywhere else.
pub fn unwrap_password(slot: &Slot, password: &str) -> Result<MasterKey> {
    if slot.kdf_id != KDF_ARGON2ID {
        return Err(AppError::CorruptFile("password slot is not argon2id".into()));
    }
    let kek = kdf::derive_key(password, &slot.salt, slot.kdf_params)?;
    unwrap_under(slot, &kek)
}

/// The shared tail of every `wrap_*`: pick a nonce, encrypt the master key with
/// the slot's own descriptor as AAD, and assemble the slot.
pub fn wrap_under(
    kind: u8,
    kdf_id: u8,
    params: KdfParams,
    salt: [u8; kdf::SALT_LEN],
    kek: &Zeroizing<[u8; kdf::KEY_LEN]>,
    master_key: &MasterKey,
) -> Result<Slot> {
    let wrap_nonce = cipher::random_nonce()?;
    // The descriptor is fully determined before the wrap, so the AAD can be
    // built from a slot whose wrapped key is still a placeholder.
    let mut slot = Slot { kind, kdf_id, kdf_params: params, salt, wrap_nonce, wrapped_mk: [0u8; WRAPPED_MK_LEN] };
    let sealed = cipher::encrypt(kek, &wrap_nonce, &slot_aad(&slot), master_key.as_slice())?;
    slot.wrapped_mk = sealed
        .as_slice()
        .try_into()
        .map_err(|_| AppError::Crypto("wrapped master key has the wrong length".into()))?;
    Ok(slot)
}

pub fn unwrap_under(slot: &Slot, kek: &Zeroizing<[u8; kdf::KEY_LEN]>) -> Result<MasterKey> {
    let plain = cipher::decrypt(kek, &slot.wrap_nonce, &slot_aad(slot), &slot.wrapped_mk)?;
    let mk: [u8; MK_LEN] = plain
        .as_slice()
        .try_into()
        .map_err(|_| AppError::CorruptFile("unwrapped master key has the wrong length".into()))?;
    Ok(Zeroizing::new(mk))
}

/// The first slot of `kind`, if the vault has one. Slots are few and fixed, so
/// a scan is fine; callers use this to decide which unlock screen to show.
pub fn find(slots: &[Slot], kind: u8) -> Option<&Slot> {
    slots.iter().find(|s| s.kind == kind)
}

pub fn has(slots: &[Slot], kind: u8) -> bool {
    find(slots, kind).is_some()
}

/// Replaces every slot of `kind` with `replacement`, or appends it if the vault
/// has none. Used when a password changes or a device is re-enrolled.
pub fn replace(slots: &mut Vec<Slot>, kind: u8, replacement: Slot) {
    slots.retain(|s| s.kind != kind);
    slots.push(replacement);
    // Keep a stable order so the encoded header — and therefore the body AAD —
    // does not churn between saves for reasons unrelated to the slots' contents.
    slots.sort_by_key(|s| s.kind);
}

pub const DEVICE_KDF_ID: u8 = KDF_HKDF_SHA256;

/// Wraps `master_key` under this device's key. The slot carries a random salt
/// like the password slots do, so re-enrolling the same device produces a
/// different wrapped key rather than a recognisably identical one.
pub fn wrap_device(device_key: &Zeroizing<[u8; 32]>, master_key: &MasterKey) -> Result<Slot> {
    let salt = cipher::random_salt()?;
    let kek = device::device_kek(device_key, &salt)?;
    wrap_under(SLOT_DEVICE, DEVICE_KDF_ID, KdfParams::NONE, salt, &kek, master_key)
}

pub fn unwrap_device(slot: &Slot, device_key: &Zeroizing<[u8; 32]>) -> Result<MasterKey> {
    if slot.kdf_id != DEVICE_KDF_ID {
        return Err(AppError::CorruptFile("device slot is not hkdf-sha256".into()));
    }
    let kek = device::device_kek(device_key, &slot.salt)?;
    unwrap_under(slot, &kek)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::format::SLOT_DEVICE;

    fn test_params() -> KdfParams {
        // The real INTERACTIVE cost makes this file take ~10s; the wrapping
        // logic under test does not care how expensive the KDF was.
        KdfParams { m_cost: 8, t_cost: 1, p_cost: 1 }
    }

    fn master_key() -> MasterKey {
        Zeroizing::new([42u8; MK_LEN])
    }

    #[test]
    fn a_password_slot_round_trips() {
        let mk = master_key();
        let slot = wrap_password("hunter2", test_params(), &mk).expect("wrap should succeed");
        let recovered = unwrap_password(&slot, "hunter2").expect("the right password should unwrap");
        assert_eq!(*recovered, *mk);
    }

    #[test]
    fn the_wrong_password_does_not_unwrap() {
        let slot = wrap_password("hunter2", test_params(), &master_key()).expect("wrap should succeed");
        assert!(matches!(unwrap_password(&slot, "hunter3"), Err(AppError::WrongPasswordOrCorrupt)));
    }

    /// The slot descriptor is the wrap's AAD, so editing it — say, rolling the
    /// cost parameters back to something cheap to attack — must break the tag
    /// rather than silently produce a weaker-but-working slot.
    #[test]
    fn tampering_with_the_descriptor_breaks_the_unwrap() {
        let slot = wrap_password("hunter2", test_params(), &master_key()).expect("wrap should succeed");

        let mut retyped = slot.clone();
        retyped.kind = SLOT_DEVICE;
        assert!(matches!(unwrap_password(&retyped, "hunter2"), Err(AppError::WrongPasswordOrCorrupt)));

        let mut resalted = slot.clone();
        resalted.salt[0] ^= 0xff;
        assert!(matches!(unwrap_password(&resalted, "hunter2"), Err(AppError::WrongPasswordOrCorrupt)));
    }

    #[test]
    fn two_slots_carry_the_same_master_key() {
        let mk = master_key();
        let a = wrap_password("first", test_params(), &mk).expect("wrap should succeed");
        let b = wrap_password("second", test_params(), &mk).expect("wrap should succeed");

        assert_ne!(a.wrapped_mk, b.wrapped_mk, "different keks must produce different ciphertext");
        assert_eq!(*unwrap_password(&a, "first").expect("unwrap a"), *mk);
        assert_eq!(*unwrap_password(&b, "second").expect("unwrap b"), *mk);
    }

    #[test]
    fn replace_swaps_one_kind_and_leaves_the_others() {
        let mk = master_key();
        let mut slots = vec![
            wrap_password("old", test_params(), &mk).expect("wrap should succeed"),
            Slot { kind: SLOT_DEVICE, kdf_id: DEVICE_KDF_ID, kdf_params: KdfParams::NONE, salt: [1u8; kdf::SALT_LEN], wrap_nonce: [2u8; 12], wrapped_mk: [3u8; WRAPPED_MK_LEN] },
        ];

        let fresh = wrap_password("new", test_params(), &mk).expect("wrap should succeed");
        replace(&mut slots, SLOT_PASSWORD, fresh);

        assert_eq!(slots.len(), 2);
        assert!(has(&slots, SLOT_DEVICE), "the device slot must survive a password change");
        let password_slot = find(&slots, SLOT_PASSWORD).expect("the new password slot should be there");
        assert_eq!(*unwrap_password(password_slot, "new").expect("unwrap"), *mk);
        assert!(unwrap_password(password_slot, "old").is_err());
    }

    #[test]
    fn replace_appends_when_the_kind_is_absent() {
        let mk = master_key();
        let mut slots = Vec::new();
        replace(&mut slots, SLOT_PASSWORD, wrap_password("only", test_params(), &mk).expect("wrap should succeed"));
        assert_eq!(slots.len(), 1);
        assert!(has(&slots, SLOT_PASSWORD));
    }
}
