use crate::crypto::cipher::NONCE_LEN;
use crate::crypto::kdf::{KdfParams, SALT_LEN};
use crate::error::{AppError, Result};

pub const MAGIC: &[u8; 8] = b"SSHCTRL1";
pub const FORMAT_VERSION: u8 = 2;
/// The original single-key layout. Still decodable so `config::migrate` can
/// read an existing vault once and rewrite it as v2; never written any more.
pub const FORMAT_VERSION_V1: u8 = 1;

pub const KDF_ARGON2ID: u8 = 1;
pub const KDF_HKDF_SHA256: u8 = 2;

/// Slot kinds. The byte is deliberately wider than the two values in use so a
/// later unlock method can be added without another format bump — an unknown
/// kind is skipped, not rejected, as long as *some* slot still opens the file.
pub const SLOT_PASSWORD: u8 = 1;
pub const SLOT_DEVICE: u8 = 2;

/// Length of the master key the vault is actually encrypted under, and of that
/// key once wrapped (AES-256-GCM appends a 16-byte tag).
pub const MK_LEN: usize = 32;
pub const WRAPPED_MK_LEN: usize = MK_LEN + 16;

/// Bounds on the KDF cost parameters read out of a file's header. The header
/// is authenticated (it doubles as AEAD AAD), but that check only happens
/// *after* the key has been derived — so a hostile file could otherwise make
/// the app allocate an arbitrary amount of memory before the tag ever gets
/// verified. These caps sit far above `KdfParams::RECOVERY` so legitimate
/// files (including future ones tuned for stronger hardware) still load.
const MAX_M_COST_KIB: u32 = 1_048_576; // 1 GiB
const MIN_M_COST_KIB: u32 = 8; // argon2's own floor
const MAX_T_COST: u32 = 64;
const MAX_P_COST: u32 = 64;

/// Same reasoning as the cost caps: a hostile file must not be able to make the
/// app allocate or iterate an unbounded number of slots before anything is
/// authenticated.
const MAX_SLOTS: u8 = 4;

/// The part of a slot that is authenticated as AAD when *its own* wrapped key is
/// unwrapped: kind, kdf id, cost parameters, salt. Binding these means a slot
/// descriptor cannot be edited or swapped for a weaker one without the wrap's
/// own tag check failing.
const SLOT_DESC_LEN: usize = 1 + 1 + 4 + 4 + 4 + SALT_LEN;
const SLOT_LEN: usize = SLOT_DESC_LEN + NONCE_LEN + WRAPPED_MK_LEN;

const V2_PREFIX_LEN: usize = 8 + 1 + 1; // magic, version, slot count
const V1_HEADER_LEN: usize = 8 + 1 + 1 + 4 + 4 + 4 + SALT_LEN;

/// One way of getting at the master key. Every slot wraps the *same* 32-byte
/// master key under a different key-encryption key, which is what lets one vault
/// be opened by, say, either a password or a device key without re-encrypting
/// the whole thing when one of them changes.
#[derive(Clone, Debug)]
pub struct Slot {
    pub kind: u8,
    pub kdf_id: u8,
    pub kdf_params: KdfParams,
    pub salt: [u8; SALT_LEN],
    pub wrap_nonce: [u8; NONCE_LEN],
    pub wrapped_mk: [u8; WRAPPED_MK_LEN],
}

pub struct Envelope {
    pub slots: Vec<Slot>,
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

/// A v1 file: one Argon2id derivation whose output *is* the vault key, with no
/// master key and no slots. Produced only by `decode_any` for the migration path.
pub struct EnvelopeV1 {
    pub kdf_params: KdfParams,
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

pub enum AnyEnvelope {
    V1(EnvelopeV1),
    V2(Envelope),
}

fn encode_slot_desc(slot: &Slot) -> Vec<u8> {
    let mut buf = Vec::with_capacity(SLOT_DESC_LEN);
    buf.push(slot.kind);
    buf.push(slot.kdf_id);
    buf.extend_from_slice(&slot.kdf_params.m_cost.to_le_bytes());
    buf.extend_from_slice(&slot.kdf_params.t_cost.to_le_bytes());
    buf.extend_from_slice(&slot.kdf_params.p_cost.to_le_bytes());
    buf.extend_from_slice(&slot.salt);
    buf
}

/// AAD for unwrapping this slot's copy of the master key.
pub fn slot_aad(slot: &Slot) -> Vec<u8> {
    encode_slot_desc(slot)
}

fn encode_slot(slot: &Slot) -> Vec<u8> {
    let mut buf = encode_slot_desc(slot);
    buf.extend_from_slice(&slot.wrap_nonce);
    buf.extend_from_slice(&slot.wrapped_mk);
    buf
}

/// Encodes the header fields that also double as AEAD Additional Authenticated
/// Data (AAD) for the vault body. Every slot is included *in full* — descriptor,
/// wrap nonce and wrapped key alike — so neither a weakened cost parameter nor a
/// slot spliced in from another file survives the tag check on decrypt.
fn encode_header(slots: &[Slot]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(V2_PREFIX_LEN + slots.len() * SLOT_LEN);
    buf.extend_from_slice(MAGIC);
    buf.push(FORMAT_VERSION);
    buf.push(slots.len() as u8);
    for slot in slots {
        buf.extend_from_slice(&encode_slot(slot));
    }
    buf
}

pub fn header_aad(slots: &[Slot]) -> Vec<u8> {
    encode_header(slots)
}

pub fn encode(slots: &[Slot], nonce: &[u8; NONCE_LEN], ciphertext: &[u8]) -> Vec<u8> {
    let mut buf = encode_header(slots);
    buf.extend_from_slice(nonce);
    buf.extend_from_slice(&(ciphertext.len() as u32).to_le_bytes());
    buf.extend_from_slice(ciphertext);
    buf
}

/// Cost parameters are only meaningful for the Argon2id slots. An HKDF slot
/// stretches nothing — its input keying material is already 32 random bytes —
/// so it stores zeroes there, which the Argon2 range check would reject.
fn check_kdf_params(kdf_id: u8, params: &KdfParams) -> Result<()> {
    match kdf_id {
        KDF_ARGON2ID => {
            if !(MIN_M_COST_KIB..=MAX_M_COST_KIB).contains(&params.m_cost)
                || !(1..=MAX_T_COST).contains(&params.t_cost)
                || !(1..=MAX_P_COST).contains(&params.p_cost)
            {
                return Err(AppError::CorruptFile(format!(
                    "kdf parameters out of range (m={}, t={}, p={})",
                    params.m_cost, params.t_cost, params.p_cost
                )));
            }
            Ok(())
        }
        KDF_HKDF_SHA256 => Ok(()),
        other => Err(AppError::CorruptFile(format!("unknown kdf id {other}"))),
    }
}

pub fn decode(bytes: &[u8]) -> Result<Envelope> {
    match decode_any(bytes)? {
        AnyEnvelope::V2(envelope) => Ok(envelope),
        AnyEnvelope::V1(_) => Err(AppError::CorruptFile("v1 file needs migration".into())),
    }
}

pub fn decode_any(bytes: &[u8]) -> Result<AnyEnvelope> {
    if bytes.len() < 9 {
        return Err(AppError::CorruptFile("file too short".into()));
    }
    if &bytes[0..8] != MAGIC {
        return Err(AppError::NotOurFile);
    }

    match bytes[8] {
        FORMAT_VERSION_V1 => decode_v1(bytes).map(AnyEnvelope::V1),
        FORMAT_VERSION => decode_v2(bytes).map(AnyEnvelope::V2),
        other => Err(AppError::UnsupportedFormatVersion(other)),
    }
}

fn decode_v2(bytes: &[u8]) -> Result<Envelope> {
    let slot_count = bytes[9];
    if slot_count == 0 || slot_count > MAX_SLOTS {
        return Err(AppError::CorruptFile(format!("slot count {slot_count} out of range")));
    }
    let slot_count = slot_count as usize;

    let body_start = V2_PREFIX_LEN + slot_count * SLOT_LEN;
    if bytes.len() < body_start + NONCE_LEN + 4 {
        return Err(AppError::CorruptFile("file too short".into()));
    }

    let mut slots = Vec::with_capacity(slot_count);
    for i in 0..slot_count {
        let at = V2_PREFIX_LEN + i * SLOT_LEN;
        let kind = bytes[at];
        let kdf_id = bytes[at + 1];
        let m_cost = u32::from_le_bytes(bytes[at + 2..at + 6].try_into().expect("slice is 4 bytes"));
        let t_cost = u32::from_le_bytes(bytes[at + 6..at + 10].try_into().expect("slice is 4 bytes"));
        let p_cost = u32::from_le_bytes(bytes[at + 10..at + 14].try_into().expect("slice is 4 bytes"));
        let kdf_params = KdfParams { m_cost, t_cost, p_cost };
        check_kdf_params(kdf_id, &kdf_params)?;

        let salt_at = at + 14;
        let salt: [u8; SALT_LEN] = bytes[salt_at..salt_at + SALT_LEN].try_into().expect("slice is SALT_LEN bytes");
        let nonce_at = salt_at + SALT_LEN;
        let wrap_nonce: [u8; NONCE_LEN] = bytes[nonce_at..nonce_at + NONCE_LEN].try_into().expect("slice is NONCE_LEN bytes");
        let wrapped_at = nonce_at + NONCE_LEN;
        let wrapped_mk: [u8; WRAPPED_MK_LEN] = bytes[wrapped_at..wrapped_at + WRAPPED_MK_LEN].try_into().expect("slice is WRAPPED_MK_LEN bytes");

        slots.push(Slot { kind, kdf_id, kdf_params, salt, wrap_nonce, wrapped_mk });
    }

    let mut offset = body_start;
    let nonce: [u8; NONCE_LEN] = bytes[offset..offset + NONCE_LEN].try_into().expect("slice is NONCE_LEN bytes");
    offset += NONCE_LEN;

    let ciphertext_len = u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("slice is 4 bytes")) as usize;
    offset += 4;

    if bytes.len() != offset + ciphertext_len {
        return Err(AppError::CorruptFile("ciphertext length mismatch".into()));
    }
    let ciphertext = bytes[offset..offset + ciphertext_len].to_vec();

    Ok(Envelope { slots, nonce, ciphertext })
}

fn decode_v1(bytes: &[u8]) -> Result<EnvelopeV1> {
    if bytes.len() < V1_HEADER_LEN + NONCE_LEN + 4 {
        return Err(AppError::CorruptFile("file too short".into()));
    }

    let kdf_id = bytes[9];
    if kdf_id != KDF_ARGON2ID {
        return Err(AppError::CorruptFile(format!("unknown kdf id {kdf_id}")));
    }

    let m_cost = u32::from_le_bytes(bytes[10..14].try_into().expect("slice is 4 bytes"));
    let t_cost = u32::from_le_bytes(bytes[14..18].try_into().expect("slice is 4 bytes"));
    let p_cost = u32::from_le_bytes(bytes[18..22].try_into().expect("slice is 4 bytes"));
    let kdf_params = KdfParams { m_cost, t_cost, p_cost };
    check_kdf_params(kdf_id, &kdf_params)?;

    let salt: [u8; SALT_LEN] = bytes[22..22 + SALT_LEN].try_into().expect("slice is SALT_LEN bytes");

    let mut offset = V1_HEADER_LEN;
    let nonce: [u8; NONCE_LEN] = bytes[offset..offset + NONCE_LEN].try_into().expect("slice is NONCE_LEN bytes");
    offset += NONCE_LEN;

    let ciphertext_len = u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("slice is 4 bytes")) as usize;
    offset += 4;

    if bytes.len() != offset + ciphertext_len {
        return Err(AppError::CorruptFile("ciphertext length mismatch".into()));
    }
    let ciphertext = bytes[offset..offset + ciphertext_len].to_vec();

    Ok(EnvelopeV1 { kdf_params, salt, nonce, ciphertext })
}

/// Rebuilds the exact AAD a v1 file was written with, so `migrate` can decrypt
/// one. Mirrors the old `encode_header`, which no longer exists.
pub fn header_aad_v1(envelope: &EnvelopeV1) -> Vec<u8> {
    let mut buf = Vec::with_capacity(V1_HEADER_LEN);
    buf.extend_from_slice(MAGIC);
    buf.push(FORMAT_VERSION_V1);
    buf.push(KDF_ARGON2ID);
    buf.extend_from_slice(&envelope.kdf_params.m_cost.to_le_bytes());
    buf.extend_from_slice(&envelope.kdf_params.t_cost.to_le_bytes());
    buf.extend_from_slice(&envelope.kdf_params.p_cost.to_le_bytes());
    buf.extend_from_slice(&envelope.salt);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slot(kind: u8, kdf_id: u8, params: KdfParams) -> Slot {
        Slot {
            kind,
            kdf_id,
            kdf_params: params,
            salt: [7u8; SALT_LEN],
            wrap_nonce: [3u8; NONCE_LEN],
            wrapped_mk: [5u8; WRAPPED_MK_LEN],
        }
    }

    fn sample_bytes(slots: &[Slot]) -> Vec<u8> {
        encode(slots, &[9u8; NONCE_LEN], b"ciphertext")
    }

    /// Builds a v1 file the way the pre-keyslot code did, so the migration path
    /// has something real to decode.
    fn sample_v1_bytes(params: KdfParams, kdf_id: u8) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(MAGIC);
        buf.push(FORMAT_VERSION_V1);
        buf.push(kdf_id);
        buf.extend_from_slice(&params.m_cost.to_le_bytes());
        buf.extend_from_slice(&params.t_cost.to_le_bytes());
        buf.extend_from_slice(&params.p_cost.to_le_bytes());
        buf.extend_from_slice(&[7u8; SALT_LEN]);
        buf.extend_from_slice(&[9u8; NONCE_LEN]);
        buf.extend_from_slice(&(b"ciphertext".len() as u32).to_le_bytes());
        buf.extend_from_slice(b"ciphertext");
        buf
    }

    #[test]
    fn well_formed_envelope_round_trips() {
        let slots = vec![slot(SLOT_PASSWORD, KDF_ARGON2ID, KdfParams::INTERACTIVE)];
        let envelope = decode(&sample_bytes(&slots)).expect("a freshly encoded envelope should decode");

        assert_eq!(envelope.slots.len(), 1);
        assert_eq!(envelope.slots[0].kind, SLOT_PASSWORD);
        assert_eq!(envelope.slots[0].kdf_params.m_cost, KdfParams::INTERACTIVE.m_cost);
        assert_eq!(envelope.slots[0].salt, [7u8; SALT_LEN]);
        assert_eq!(envelope.ciphertext, b"ciphertext");
    }

    #[test]
    fn two_slots_round_trip_in_order() {
        let slots = vec![
            slot(SLOT_PASSWORD, KDF_ARGON2ID, KdfParams::RECOVERY),
            slot(SLOT_DEVICE, KDF_HKDF_SHA256, KdfParams::NONE),
        ];
        let envelope = decode(&sample_bytes(&slots)).expect("two slots should decode");

        assert_eq!(envelope.slots.len(), 2);
        assert_eq!(envelope.slots[0].kind, SLOT_PASSWORD);
        assert_eq!(envelope.slots[1].kind, SLOT_DEVICE);
        assert_eq!(envelope.slots[1].kdf_id, KDF_HKDF_SHA256);
    }

    #[test]
    fn every_slot_is_covered_by_the_body_aad() {
        let slots = vec![
            slot(SLOT_PASSWORD, KDF_ARGON2ID, KdfParams::INTERACTIVE),
            slot(SLOT_DEVICE, KDF_HKDF_SHA256, KdfParams::NONE),
        ];
        let aad = header_aad(&slots);

        let mut weakened = slots.clone();
        weakened[0].kdf_params.m_cost = MIN_M_COST_KIB;
        assert_ne!(aad, header_aad(&weakened), "a rolled-back cost must change the AAD");

        let mut spliced = slots.clone();
        spliced[1].wrapped_mk = [6u8; WRAPPED_MK_LEN];
        assert_ne!(aad, header_aad(&spliced), "a swapped wrapped key must change the AAD");
    }

    #[test]
    fn a_slots_own_aad_covers_its_descriptor_but_not_its_wrapped_key() {
        let original = slot(SLOT_PASSWORD, KDF_ARGON2ID, KdfParams::INTERACTIVE);

        let mut retyped = original.clone();
        retyped.kind = SLOT_DEVICE;
        assert_ne!(slot_aad(&original), slot_aad(&retyped));

        // The wrapped key is the AEAD message, not its own AAD.
        let mut rewrapped = original.clone();
        rewrapped.wrapped_mk = [1u8; WRAPPED_MK_LEN];
        assert_eq!(slot_aad(&original), slot_aad(&rewrapped));
    }

    #[test]
    fn absurd_memory_cost_is_rejected_before_key_derivation() {
        let slots = vec![slot(SLOT_PASSWORD, KDF_ARGON2ID, KdfParams { m_cost: u32::MAX, ..KdfParams::INTERACTIVE })];
        assert!(matches!(decode(&sample_bytes(&slots)), Err(AppError::CorruptFile(_))));
    }

    #[test]
    fn zero_cost_parameters_are_rejected_for_argon2_slots() {
        for params in [
            KdfParams { m_cost: 0, ..KdfParams::INTERACTIVE },
            KdfParams { t_cost: 0, ..KdfParams::INTERACTIVE },
            KdfParams { p_cost: 0, ..KdfParams::INTERACTIVE },
        ] {
            let slots = vec![slot(SLOT_PASSWORD, KDF_ARGON2ID, params)];
            assert!(matches!(decode(&sample_bytes(&slots)), Err(AppError::CorruptFile(_))));
        }
    }

    /// The mirror of the test above: an HKDF slot stretches nothing, so its
    /// zeroed cost fields must *not* trip the Argon2 range check.
    #[test]
    fn zero_cost_parameters_are_accepted_for_hkdf_slots() {
        let slots = vec![slot(SLOT_DEVICE, KDF_HKDF_SHA256, KdfParams::NONE)];
        assert!(decode(&sample_bytes(&slots)).is_ok());
    }

    #[test]
    fn unknown_kdf_id_is_rejected() {
        let slots = vec![slot(SLOT_PASSWORD, 99, KdfParams::INTERACTIVE)];
        assert!(matches!(decode(&sample_bytes(&slots)), Err(AppError::CorruptFile(_))));
    }

    #[test]
    fn absurd_slot_count_is_rejected_before_allocation() {
        let slots = vec![slot(SLOT_PASSWORD, KDF_ARGON2ID, KdfParams::INTERACTIVE)];
        let mut bytes = sample_bytes(&slots);
        bytes[9] = u8::MAX;
        assert!(matches!(decode(&bytes), Err(AppError::CorruptFile(_))));

        bytes[9] = 0;
        assert!(matches!(decode(&bytes), Err(AppError::CorruptFile(_))));
    }

    #[test]
    fn foreign_magic_is_not_our_file() {
        let slots = vec![slot(SLOT_PASSWORD, KDF_ARGON2ID, KdfParams::INTERACTIVE)];
        let mut bytes = sample_bytes(&slots);
        bytes[0] = b'X';
        assert!(matches!(decode(&bytes), Err(AppError::NotOurFile)));
    }

    #[test]
    fn a_newer_format_version_is_refused_outright() {
        let slots = vec![slot(SLOT_PASSWORD, KDF_ARGON2ID, KdfParams::INTERACTIVE)];
        let mut bytes = sample_bytes(&slots);
        bytes[8] = FORMAT_VERSION + 1;
        assert!(matches!(decode_any(&bytes), Err(AppError::UnsupportedFormatVersion(v)) if v == FORMAT_VERSION + 1));
    }

    #[test]
    fn a_v1_file_still_decodes_for_migration() {
        let bytes = sample_v1_bytes(KdfParams::INTERACTIVE, KDF_ARGON2ID);
        let AnyEnvelope::V1(envelope) = decode_any(&bytes).expect("v1 must stay readable") else {
            panic!("a v1 file should not decode as v2");
        };

        assert_eq!(envelope.salt, [7u8; SALT_LEN]);
        assert_eq!(envelope.kdf_params.m_cost, KdfParams::INTERACTIVE.m_cost);
        assert_eq!(envelope.ciphertext, b"ciphertext");
        // The AAD has to be reconstructible byte-for-byte or the file will not
        // decrypt during migration.
        assert_eq!(header_aad_v1(&envelope), bytes[..V1_HEADER_LEN]);
    }

    #[test]
    fn the_plain_decoder_refuses_a_v1_file() {
        let bytes = sample_v1_bytes(KdfParams::INTERACTIVE, KDF_ARGON2ID);
        assert!(matches!(decode(&bytes), Err(AppError::CorruptFile(_))));
    }
}
