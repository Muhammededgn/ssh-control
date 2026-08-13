use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

use crate::error::{AppError, Result};

pub const SALT_LEN: usize = 16;
pub const KEY_LEN: usize = 32;

#[derive(Clone, Copy, Debug)]
pub struct KdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl KdfParams {
    /// Tuned for roughly 300-500ms derivation time on typical desktop hardware.
    /// Stored explicitly in the config header rather than relying on a library
    /// default that could silently change between argon2-crate versions.
    pub const INTERACTIVE: Self = Self {
        m_cost: 19_456,
        t_cost: 2,
        p_cost: 1,
    };

    /// For a password slot that is only reached when the everyday unlock path
    /// has already failed — a recovery prompt is worth seconds, not
    /// milliseconds. Deliberately below the 1 GiB header cap in
    /// `config::format` so it stays inside the range check, and below what a
    /// small VM would refuse to allocate.
    pub const RECOVERY: Self = Self {
        m_cost: 262_144, // 256 MiB
        t_cost: 4,
        p_cost: 1,
    };

    /// Placeholder for slots whose key-encryption key is not stretched at all.
    /// A device key is already 32 random bytes, so running Argon2 over it buys
    /// nothing; those slots store zeroes here and `config::format` skips the
    /// Argon2 range check for them.
    pub const NONE: Self = Self {
        m_cost: 0,
        t_cost: 0,
        p_cost: 0,
    };
}

/// Derives a 32-byte AES-256 key from the master password using Argon2id.
pub fn derive_key(
    password: &str,
    salt: &[u8; SALT_LEN],
    params: KdfParams,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let argon2_params = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(KEY_LEN))
        .map_err(|e| AppError::Kdf(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(password.as_bytes(), salt, out.as_mut_slice())
        .map_err(|e| AppError::Kdf(e.to_string()))?;
    Ok(out)
}
