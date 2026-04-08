//! Lock script entry logic — shared by all three `mldsa{44,65,87}-lock-v2-rust` bins.
//!
//! The verification pipeline is identical in SHAPE to `mldsa-lock-v2/src/entry.rs`
//! — load args, verify prefix, split witness lock into (flag, pk, sig), hash pk
//! and match against args, stream CighashAll into message_hasher, verify —
//! but differs in the final verify call:
//!
//!   mldsa-lock-v2       → build_fips204_final_message() + fips204::verify
//!   mldsa-lock-v2-rust  → ml_dsa::VerifyingKey::verify_with_context(digest, ctx, sig)
//!
//! The ml-dsa crate applies FIPS-204 §5.4 M' framing internally using the ctx
//! argument. We pass our 32-byte blake2b digest as `msg` and our 14-byte DOMAIN
//! as `ctx`. The crate computes M' = 0x00 || len(ctx) || ctx || msg and verifies
//! per Algorithm 3 in the spec. The sibling mldsa-lock-v2 crate double-wraps
//! (non-standard but self-consistent), so the two locks produce DIFFERENT valid
//! signatures for the same key+tx. That's expected: they are separate deployments
//! with separate code_hashes.

use alloc::vec::Vec;

use ckb_std::ckb_constants::Source;
use ckb_std::high_level::{load_script, load_witness_args};

use ml_dsa::{EncodedVerifyingKey, KeyGen, MlDsa44, MlDsa65, MlDsa87, Signature, VerifyingKey};

use crate::helpers::{destruct_flag, lengths, Error, Hasher, ParamId, DOMAIN};
use crate::streamer::generate_ckb_tx_message_all;

/// Entry point for a variant-specific bin. `expected_param_id` is the variant
/// this binary was built for — the walker rejects any witness/args referencing
/// a different variant, so cross-variant spends through the wrong binary fail
/// cleanly instead of producing ambiguous errors.
pub fn run(expected_param_id: ParamId) -> i8 {
    match run_inner(expected_param_id) {
        Ok(()) => 0,
        Err(e) => e as i8,
    }
}

fn run_inner(expected_param_id: ParamId) -> Result<(), Error> {
    // 1. Load script + extract args slice
    let script = load_script().map_err(|_| Error::InvalidLockArgsLength)?;
    let args: Vec<u8> = script.args().raw_data().to_vec();

    // 37 = [0x80, 0x01, 0x01, 0x01, flag, blake2b_256(pk)]
    if args.len() != 37 {
        return Err(Error::InvalidLockArgsLength);
    }
    if args[0] != 0x80 || args[1] != 0x01 || args[2] != 0x01 || args[3] != 0x01 {
        return Err(Error::InvalidLockArgsLength);
    }

    let (arg_param, arg_has_sig) = destruct_flag(args[4])?;
    if arg_has_sig {
        // Args must never carry the sig bit — that's a witness concern.
        return Err(Error::InvalidLockArgsLength);
    }
    if arg_param != expected_param_id {
        return Err(Error::InvalidParamId);
    }

    let expected_pk_hash = &args[5..37];

    // 2. Load first witness of current script group, extract lock field
    let witness_args =
        load_witness_args(0, Source::GroupInput).map_err(|_| Error::InvalidLockLength)?;
    let lock_opt = witness_args.lock();
    let lock_bytes: Vec<u8> = match lock_opt.to_opt() {
        Some(b) => b.raw_data().to_vec(),
        None => return Err(Error::InvalidLockLength),
    };

    // 3. Parse [flag, pk, sig] from lock
    let (pk_len, sig_len, _) = lengths(expected_param_id);
    if lock_bytes.len() != 1 + pk_len + sig_len {
        return Err(Error::InvalidLockLength);
    }

    let (wit_param, wit_has_sig) = destruct_flag(lock_bytes[0])?;
    if !wit_has_sig {
        return Err(Error::InvalidLockLength);
    }
    if wit_param != expected_param_id {
        return Err(Error::InvalidParamId);
    }

    let pk = &lock_bytes[1..1 + pk_len];
    let sig = &lock_bytes[1 + pk_len..];

    // 4. Pubkey hash check — constant-time byte compare against script args
    let pk_hash = {
        let mut h = Hasher::script_args_hasher();
        h.update(pk);
        h.hash()
    };
    if !ct_eq(&pk_hash, expected_pk_hash) {
        return Err(Error::PubkeyHashMismatch);
    }

    // 5. Build signing digest from CighashAll stream
    let digest = {
        let mut h = Hasher::message_hasher();
        generate_ckb_tx_message_all(&mut h).map_err(|_| Error::SignatureVerifyFailed)?;
        h.hash()
    };

    // 6. Verify via ml-dsa — the crate applies FIPS-204 §5.4 M' framing
    //    internally using `ctx = DOMAIN`. No pre-wrapping on our side.
    let verified = match expected_param_id {
        ParamId::Mldsa44 => verify_mldsa_44(pk, &digest, sig)?,
        ParamId::Mldsa65 => verify_mldsa_65(pk, &digest, sig)?,
        ParamId::Mldsa87 => verify_mldsa_87(pk, &digest, sig)?,
    };

    if !verified {
        return Err(Error::SignatureVerifyFailed);
    }

    Ok(())
}

// ── per-variant verify shims ─────────────────────────────────────────────────

fn verify_mldsa_44(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, Error> {
    verify_generic::<MlDsa44>(pk, msg, sig)
}

fn verify_mldsa_65(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, Error> {
    verify_generic::<MlDsa65>(pk, msg, sig)
}

fn verify_mldsa_87(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, Error> {
    verify_generic::<MlDsa87>(pk, msg, sig)
}

fn verify_generic<P: KeyGen>(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, Error> {
    // Verifying-key decode only validates length. Garbage bytes decode
    // successfully into a VerifyingKey (which will then fail verify).
    let enc_vk = EncodedVerifyingKey::<P>::try_from(pk).map_err(|_| Error::InvalidPubkeyLength)?;
    let vk = VerifyingKey::<P>::decode(&enc_vk);

    // Signature::try_from calls Signature::decode which rejects bytes that
    // fail structural validation: Hint::bit_unpack or `z.infinity_norm >=
    // GAMMA1_MINUS_BETA`. For our purposes ANY failure to decode a signature
    // is "signature didn't verify" — the byte count was already validated
    // by the `lock_bytes.len() != 1 + pk_len + sig_len` guard above, so this
    // error map is NOT InvalidSignatureLength (that would be misleading).
    let signature =
        Signature::<P>::try_from(sig).map_err(|_| Error::SignatureVerifyFailed)?;

    Ok(vk.verify_with_context(msg, DOMAIN, &signature))
}

/// Constant-time byte comparison. Returns true iff all bytes match.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}
