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
