//! Inlined helpers from `ckb-fips204-utils` — trimmed to what this crate needs.
//!
//! This crate avoids depending on `ckb-fips204-utils` because that crate
//! pins `ckb-std 0.17.1` and hard-deps on the `fips204` crate, neither of
//! which we want. The code below is the ML-DSA-only subset, copied and
//! adapted for `ckb-std 1.0`.
//!
//! The SOURCE OF TRUTH for this logic lives in
//! `key-vault-wasm/crates/ckb-fips204-utils/src/lib.rs`. Any change to the
//! lock args layout, flag packing, personalisation strings, or FIPS 204
//! Table 1 lengths must be mirrored in both places — the two crates are
//! designed to produce the same on-chain-visible bytes despite using
//! different verify backends.

use ckb_hash::{Blake2b, Blake2bBuilder};

// ── parameter ids ─────────────────────────────────────────────────────────────
//
// Sit immediately after SPHINCS+'s 48..=59 so a future unified ParamId enum
// can absorb both without renumbering.

/// ML-DSA parameter identifiers. Encoded as a single byte, packed into the
/// lock flag via `construct_flag` / `destruct_flag`.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum ParamId {
    Mldsa44 = 60,
    Mldsa65 = 61,
    Mldsa87 = 62,
}

impl ParamId {
    pub fn from_u8(v: u8) -> Result<Self, Error> {
        match v {
            60 => Ok(ParamId::Mldsa44),
            61 => Ok(ParamId::Mldsa65),
            62 => Ok(ParamId::Mldsa87),
            _ => Err(Error::InvalidParamId),
        }
    }
}

// ── flag packing ──────────────────────────────────────────────────────────────

/// Pack `(param_id, has_signature)` into a single byte.
/// Layout: `[7..1] = param_id`, `[0] = has_signature`.
pub fn construct_flag(param_id: ParamId, has_signature: bool) -> u8 {
    let value = param_id as u8;
    (value << 1) | u8::from(has_signature)
}

/// Unpack a flag byte. Returns `Err(InvalidParamId)` for unknown param ids.
pub fn destruct_flag(flag: u8) -> Result<(ParamId, bool), Error> {
    let has_signature = flag & 1 != 0;
    let param_id = ParamId::from_u8(flag >> 1)?;
    Ok((param_id, has_signature))
}

// ── personalised blake2b hashers ──────────────────────────────────────────────

/// Blake2b wrapper with domain-separated personalisation. Finalises to 32 bytes.
pub struct Hasher(Blake2b);

impl Hasher {
    /// Personalised hasher for script args derivation.
    /// Personalisation: `b"ckb-mldsa-sct"`. MUST match `mldsa-lock-v2`
    /// and `ckb-fips204-utils::Hasher::script_args_hasher` so that
    /// a pubkey hashed on either side produces the same lock_args byte.
    pub fn script_args_hasher() -> Self {
        Hasher(Blake2bBuilder::new(32).personal(b"ckb-mldsa-sct").build())
    }

    /// Personalised hasher for the ML-DSA signing digest. Feed the
    /// CighashAll stream into this and finalise → the 32-byte message
    /// passed to `ml_dsa::VerifyingKey::verify_with_context`.
    /// Personalisation: `b"ckb-mldsa-msg"`.
    pub fn message_hasher() -> Self {
        Hasher(Blake2bBuilder::new(32).personal(b"ckb-mldsa-msg").build())
    }

    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    pub fn hash(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        self.0.finalize(&mut out);
        out
    }
}

// `io::Write` impl so the streamer in `streamer.rs` can write directly into
// the hasher without an intermediate buffer. Uses ckb-rust-std (sibling of
// ckb-std in 1.x) rather than std::io because we're no_std.
impl ckb_rust_std::io::Write for Hasher {
    fn write(&mut self, data: &[u8]) -> Result<usize, ckb_rust_std::io::Error> {
        self.0.update(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> Result<(), ckb_rust_std::io::Error> {
        Ok(())
    }
}

// ── domain separator ──────────────────────────────────────────────────────────

/// FIPS-204 §5.4 context string. Passed to `ml_dsa::VerifyingKey::verify_with_context`
/// as the `ctx` argument — the crate applies the M' framing internally.
///
/// Maximum ctx length in FIPS 204 is 255 bytes; ours is 14. The ml-dsa crate
/// panics above 255 which won't happen here.
pub const DOMAIN: &[u8] = b"CKB-MLDSA-LOCK";

// ── ML-DSA parameter sizes ────────────────────────────────────────────────────
//
// FIPS 204 §4 Table 1. Matched verbatim in the sibling mldsa-lock-v2 crate.

/// `(pubkey_len, signature_len, secret_key_len)` for a given variant.
pub const fn lengths(param_id: ParamId) -> (usize, usize, usize) {
    match param_id {
        ParamId::Mldsa44 => (1312, 2420, 2560),
        ParamId::Mldsa65 => (1952, 3309, 4032),
        ParamId::Mldsa87 => (2592, 4627, 4896),
    }
}

// ── errors ────────────────────────────────────────────────────────────────────

/// Error codes returned by on-chain verifying. Values chosen to sit above
/// the CKB / ckb-std reserved range.
///
/// Values match `ckb-fips204-utils::Error` so logs look identical across
/// both lock variants — makes grep-friendly failure reports easier to
/// reason about when comparing v2 vs v2-rust runs.
#[repr(i8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidParamId = 40,
    InvalidPubkeyLength = 41,
    InvalidSignatureLength = 42,
    InvalidLockLength = 43,
    InvalidLockArgsLength = 44,
    PubkeyHashMismatch = 45,
    SignatureVerifyFailed = 46,
    ContextTooLong = 47,
}

impl From<Error> for i8 {
    fn from(e: Error) -> i8 {
        e as i8
    }
}
