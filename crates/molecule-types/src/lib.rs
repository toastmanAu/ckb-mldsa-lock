//! Molecule serialization for CKB ML-DSA-65 witness types.
//!
//! Implements the hand-rolled Molecule encoding matching the lock script's
//! `parse_mldsa_witness` parser and the CKB `WitnessArgs` table layout.

/// ML-DSA-65 parameter sizes (FIPS 204).
pub const PUBLICKEY_BYTES: usize = 1952;
pub const SIGNATURE_BYTES: usize = 3309;

/// Lock args layout (36 bytes):
///   [0]    version  = 0x01
///   [1]    algo_id  = 0x02 (ML-DSA)
///   [2]    param_id = 0x02 (ML-DSA-65)
///   [3]    reserved = 0x00
///   [4-35] blake2b_256(pubkey)
pub const ARGS_LEN: usize = 36;
pub const ARGS_VERSION: u8 = 0x01;
pub const ARGS_ALGO_ID: u8 = 0x02;
pub const ARGS_PARAM_ID: u8 = 0x02;

/// Domain separation string for the signing digest.
pub const DOMAIN: &[u8] = b"CKB-MLDSA-LOCK";

// ── MldsaWitness ──────────────────────────────────────────────────────────
//
// Molecule table (6 fields):
//   full_size(4) | offset[0..5](4 each) | version(1) | algo_id(1) |
//   param_id(1) | flags(1) | pubkey(4+1952) | sig(4+3309)
//
const WIT_HDR: usize = 4 + 6 * 4; // 28 bytes
const WIT_TOTAL: usize = WIT_HDR + 1 + 1 + 1 + 1
    + 4 + PUBLICKEY_BYTES
    + 4 + SIGNATURE_BYTES; // 5305 bytes

/// Serialize an `MldsaWitness` Molecule table into `out` (must be `WIT_TOTAL` bytes).
pub fn serialize_mldsa_witness(
    out: &mut [u8; WIT_TOTAL],
    pubkey: &[u8; PUBLICKEY_BYTES],
    sig: &[u8; SIGNATURE_BYTES],
) {
    write_u32_le(&mut out[0..], WIT_TOTAL as u32);

    let mut off = WIT_HDR as u32;
    write_u32_le(&mut out[4..],  off); off += 1; // version
    write_u32_le(&mut out[8..],  off); off += 1; // algo_id
    write_u32_le(&mut out[12..], off); off += 1; // param_id
    write_u32_le(&mut out[16..], off); off += 1; // flags
    write_u32_le(&mut out[20..], off); off += 4 + PUBLICKEY_BYTES as u32; // pubkey
    write_u32_le(&mut out[24..], off);            // sig (no advance needed)

    let p = &mut out[WIT_HDR..];
    p[0] = ARGS_VERSION;  // version
    p[1] = ARGS_ALGO_ID;  // algo_id
    p[2] = ARGS_PARAM_ID; // param_id
    p[3] = 0x00;          // flags

    let mut cursor = 4usize;
    write_u32_le(&mut p[cursor..], PUBLICKEY_BYTES as u32); cursor += 4;
    p[cursor..cursor + PUBLICKEY_BYTES].copy_from_slice(pubkey); cursor += PUBLICKEY_BYTES;
    write_u32_le(&mut p[cursor..], SIGNATURE_BYTES as u32); cursor += 4;
    p[cursor..cursor + SIGNATURE_BYTES].copy_from_slice(sig);
}

// ── WitnessArgs ───────────────────────────────────────────────────────────
//
// Molecule table (3 fields: lock, input_type, output_type).
// We set only lock (as Bytes = 4-byte length prefix + data).
// input_type and output_type are absent (BytesOpt::None = 0 bytes).
//
// Layout: total(4) | off[0](4) | off[1](4) | off[2](4) | lock_len(4) | lock_data

/// Serialize a `WitnessArgs` Molecule table with only the lock field set.
/// Returns a `Vec<u8>` containing the full WitnessArgs encoding.
pub fn serialize_witness_args(lock_data: &[u8]) -> Vec<u8> {
    let hdr: u32 = 4 + 3 * 4; // 16 bytes
    let f0_size = 4 + lock_data.len() as u32;
    let total = hdr + f0_size;

    let mut buf = vec![0u8; total as usize];
    write_u32_le(&mut buf[0..], total);

    let off = hdr;
    write_u32_le(&mut buf[4..], off);           // lock starts at hdr
    write_u32_le(&mut buf[8..], off + f0_size); // input_type (absent)
    write_u32_le(&mut buf[12..], off + f0_size); // output_type (absent)

    write_u32_le(&mut buf[hdr as usize..], lock_data.len() as u32);
    buf[hdr as usize + 4..].copy_from_slice(lock_data);

    buf
}

/// Build the full witness bytes (WitnessArgs wrapping MldsaWitness) for a transaction.
pub fn build_witness(pubkey: &[u8; PUBLICKEY_BYTES], sig: &[u8; SIGNATURE_BYTES]) -> Vec<u8> {
    let mut mldsa_wit = [0u8; WIT_TOTAL];
    serialize_mldsa_witness(&mut mldsa_wit, pubkey, sig);
    serialize_witness_args(&mldsa_wit)
}

// ── helpers ───────────────────────────────────────────────────────────────

#[inline]
fn write_u32_le(buf: &mut [u8], v: u32) {
    buf[0] = v as u8;
    buf[1] = (v >> 8) as u8;
    buf[2] = (v >> 16) as u8;
    buf[3] = (v >> 24) as u8;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn witness_args_length() {
        let pk = [0u8; PUBLICKEY_BYTES];
        let sig = [0u8; SIGNATURE_BYTES];
        let wa = build_witness(&pk, &sig);
        // WitnessArgs header(16) + Bytes length prefix(4) + MldsaWitness(5305)
        assert_eq!(wa.len(), 16 + 4 + WIT_TOTAL);
    }

    #[test]
    fn witness_args_header_valid() {
        let pk = [0u8; PUBLICKEY_BYTES];
        let sig = [0u8; SIGNATURE_BYTES];
        let wa = build_witness(&pk, &sig);
        let total = u32::from_le_bytes(wa[0..4].try_into().unwrap());
        assert_eq!(total as usize, wa.len());
    }
}
