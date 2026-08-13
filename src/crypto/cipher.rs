use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit, Nonce, Payload};
use zeroize::Zeroizing;

use crate::error::{AppError, Result};

pub const NONCE_LEN: usize = 12;

/// Encrypts `plaintext` under `key`/`nonce`, authenticating (but not encrypting)
/// `aad` alongside it. The nonce MUST be freshly random for every call with the
/// same key (never reused) — see `random_nonce`.
pub fn encrypt(key: &[u8; 32], nonce: &[u8; NONCE_LEN], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| AppError::Crypto(e.to_string()))?;
    let nonce = Nonce::<Aes256Gcm>::from(*nonce);
    cipher
        .encrypt(&nonce, Payload { msg: plaintext, aad })
        .map_err(|e| AppError::Crypto(e.to_string()))
}

/// Decrypts `ciphertext` under `key`/`nonce`/`aad`. Relies entirely on the AES-GCM
/// authentication tag for integrity: a wrong key (i.e. wrong master password) or a
/// tampered header/ciphertext both surface as the same `WrongPasswordOrCorrupt`
/// error, by design — this AEAD failure is the only "password check" in the app,
/// deliberately avoiding a separate verifier that would double as a weaker
/// offline-brute-force oracle.
pub fn decrypt(key: &[u8; 32], nonce: &[u8; NONCE_LEN], aad: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| AppError::Crypto(e.to_string()))?;
    let nonce = Nonce::<Aes256Gcm>::from(*nonce);
    cipher
        .decrypt(&nonce, Payload { msg: ciphertext, aad })
        .map(Zeroizing::new)
        .map_err(|_| AppError::WrongPasswordOrCorrupt)
}

pub fn random_nonce() -> Result<[u8; NONCE_LEN]> {
    let mut buf = [0u8; NONCE_LEN];
    getrandom::fill(&mut buf).map_err(|e| AppError::Crypto(e.to_string()))?;
    Ok(buf)
}

/// A fresh master key. This is the key the vault body is actually encrypted
/// under; every keyslot stores a wrapped copy of it. It is generated once, at
/// vault creation, and never derived from anything the user types — which is
/// what lets a password change rewrap 32 bytes instead of re-encrypting the
/// whole vault.
pub fn random_master_key() -> Result<Zeroizing<[u8; super::kdf::KEY_LEN]>> {
    let mut buf = Zeroizing::new([0u8; super::kdf::KEY_LEN]);
    getrandom::fill(buf.as_mut_slice()).map_err(|e| AppError::Crypto(e.to_string()))?;
    Ok(buf)
}

pub fn random_salt() -> Result<[u8; super::kdf::SALT_LEN]> {
    let mut buf = [0u8; super::kdf::SALT_LEN];
    getrandom::fill(&mut buf).map_err(|e| AppError::Crypto(e.to_string()))?;
    Ok(buf)
}
