use crate::crypto::cipher::NONCE_LEN;
use crate::crypto::kdf::{KdfParams, SALT_LEN};
use crate::error::{AppError, Result};

pub const MAGIC: &[u8; 8] = b"SSHCTRL1";
pub const FORMAT_VERSION: u8 = 1;
pub const KDF_ARGON2ID: u8 = 1;

/// Bounds on the KDF cost parameters read out of a file's header. The header
/// is authenticated (it doubles as AEAD AAD), but that check only happens
/// *after* the key has been derived — so a hostile file could otherwise make
/// the app allocate an arbitrary amount of memory before the tag ever gets
/// verified. These caps sit far above `KdfParams::INTERACTIVE` so legitimate
/// files (including future ones tuned for stronger hardware) still load.
const MAX_M_COST_KIB: u32 = 1_048_576; // 1 GiB
const MIN_M_COST_KIB: u32 = 8; // argon2's own floor
const MAX_T_COST: u32 = 64;
const MAX_P_COST: u32 = 64;

const HEADER_LEN: usize = 8 + 1 + 1 + 4 + 4 + 4 + SALT_LEN;

#[derive(Clone, Copy, Debug)]
pub struct Header {
    pub format_version: u8,
    pub kdf_id: u8,
    pub kdf_params: KdfParams,
    pub salt: [u8; SALT_LEN],
}

pub struct Envelope {
    pub header: Header,
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

/// Encodes the header fields that also double as AEAD Additional Authenticated
/// Data (AAD) — binding them means a tampered header (e.g. someone rolling back
/// `kdf_params` to weaken it) also fails the AES-GCM tag check on decrypt.
fn encode_header(header: &Header) -> Vec<u8> {
    let mut buf = Vec::with_capacity(HEADER_LEN);
    buf.extend_from_slice(MAGIC);
    buf.push(header.format_version);
    buf.push(header.kdf_id);
    buf.extend_from_slice(&header.kdf_params.m_cost.to_le_bytes());
    buf.extend_from_slice(&header.kdf_params.t_cost.to_le_bytes());
    buf.extend_from_slice(&header.kdf_params.p_cost.to_le_bytes());
    buf.extend_from_slice(&header.salt);
    buf
}

pub fn header_aad(header: &Header) -> Vec<u8> {
    encode_header(header)
}

pub fn encode(header: &Header, nonce: &[u8; NONCE_LEN], ciphertext: &[u8]) -> Vec<u8> {
    let mut buf = encode_header(header);
    buf.extend_from_slice(nonce);
    buf.extend_from_slice(&(ciphertext.len() as u32).to_le_bytes());
    buf.extend_from_slice(ciphertext);
    buf
}

pub fn decode(bytes: &[u8]) -> Result<Envelope> {
    if bytes.len() < HEADER_LEN + NONCE_LEN + 4 {
        return Err(AppError::CorruptFile("file too short".into()));
    }

    let magic = &bytes[0..8];
    if magic != MAGIC {
        return Err(AppError::NotOurFile);
    }

    let format_version = bytes[8];
    if format_version != FORMAT_VERSION {
        return Err(AppError::UnsupportedFormatVersion(format_version));
    }

    let kdf_id = bytes[9];
    if kdf_id != KDF_ARGON2ID {
        return Err(AppError::CorruptFile(format!("unknown kdf id {kdf_id}")));
    }

    let m_cost = u32::from_le_bytes(bytes[10..14].try_into().expect("slice is 4 bytes"));
    let t_cost = u32::from_le_bytes(bytes[14..18].try_into().expect("slice is 4 bytes"));
    let p_cost = u32::from_le_bytes(bytes[18..22].try_into().expect("slice is 4 bytes"));
    if !(MIN_M_COST_KIB..=MAX_M_COST_KIB).contains(&m_cost)
        || !(1..=MAX_T_COST).contains(&t_cost)
        || !(1..=MAX_P_COST).contains(&p_cost)
    {
        return Err(AppError::CorruptFile(format!(
            "kdf parameters out of range (m={m_cost}, t={t_cost}, p={p_cost})"
        )));
    }

    let salt: [u8; SALT_LEN] = bytes[22..22 + SALT_LEN]
        .try_into()
        .expect("slice is SALT_LEN bytes");

    let mut offset = HEADER_LEN;
    let nonce: [u8; NONCE_LEN] = bytes[offset..offset + NONCE_LEN]
        .try_into()
        .expect("slice is NONCE_LEN bytes");
    offset += NONCE_LEN;

    let ciphertext_len = u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("slice is 4 bytes"),
    ) as usize;
    offset += 4;

    if bytes.len() != offset + ciphertext_len {
        return Err(AppError::CorruptFile("ciphertext length mismatch".into()));
    }
    let ciphertext = bytes[offset..offset + ciphertext_len].to_vec();

    Ok(Envelope {
        header: Header {
            format_version,
            kdf_id,
            kdf_params: KdfParams { m_cost, t_cost, p_cost },
            salt,
        },
        nonce,
        ciphertext,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_bytes(params: KdfParams, kdf_id: u8) -> Vec<u8> {
        let header = Header {
            format_version: FORMAT_VERSION,
            kdf_id,
            kdf_params: params,
            salt: [7u8; SALT_LEN],
        };
        encode(&header, &[9u8; NONCE_LEN], b"ciphertext")
    }

    #[test]
    fn well_formed_envelope_round_trips() {
        let bytes = sample_bytes(KdfParams::INTERACTIVE, KDF_ARGON2ID);
        let envelope = decode(&bytes).expect("a freshly encoded envelope should decode");

        assert_eq!(envelope.header.kdf_id, KDF_ARGON2ID);
        assert_eq!(envelope.header.kdf_params.m_cost, KdfParams::INTERACTIVE.m_cost);
        assert_eq!(envelope.header.salt, [7u8; SALT_LEN]);
        assert_eq!(envelope.ciphertext, b"ciphertext");
    }

    #[test]
    fn absurd_memory_cost_is_rejected_before_key_derivation() {
        let params = KdfParams { m_cost: u32::MAX, ..KdfParams::INTERACTIVE };
        let bytes = sample_bytes(params, KDF_ARGON2ID);
        assert!(matches!(decode(&bytes), Err(AppError::CorruptFile(_))));
    }

    #[test]
    fn zero_cost_parameters_are_rejected() {
        for params in [
            KdfParams { m_cost: 0, ..KdfParams::INTERACTIVE },
            KdfParams { t_cost: 0, ..KdfParams::INTERACTIVE },
            KdfParams { p_cost: 0, ..KdfParams::INTERACTIVE },
        ] {
            let bytes = sample_bytes(params, KDF_ARGON2ID);
            assert!(matches!(decode(&bytes), Err(AppError::CorruptFile(_))));
        }
    }

    #[test]
    fn unknown_kdf_id_is_rejected() {
        let bytes = sample_bytes(KdfParams::INTERACTIVE, 99);
        assert!(matches!(decode(&bytes), Err(AppError::CorruptFile(_))));
    }

    #[test]
    fn foreign_magic_is_not_our_file() {
        let mut bytes = sample_bytes(KdfParams::INTERACTIVE, KDF_ARGON2ID);
        bytes[0] = b'X';
        assert!(matches!(decode(&bytes), Err(AppError::NotOurFile)));
    }
}
