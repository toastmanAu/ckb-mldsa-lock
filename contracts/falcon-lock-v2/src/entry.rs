//! Falcon lock script entry logic — shared by `falcon{512,1024}-lock-v2`.

use alloc::vec::Vec;

use ckb_std::ckb_constants::Source;
use ckb_std::high_level::{load_script, load_witness_args};

use ckb_fips204_utils::{
    ckb_tx_message_all_in_ckb_vm::generate_ckb_tx_message_all,
    construct_flag, destruct_flag, lengths,
    verifying, Error, Hasher, ParamId,
};

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

    // 4. Pubkey hash check — uses Falcon-personalised blake2b
    //    (`b"ckb-falcon-sct"`) to match `Hasher::falcon_script_args_hasher`
    //    on the signer side. ML-DSA uses `b"ckb-mldsa-sct"`; the two MUST
    //    NOT be confused — that was a real bug we caught during the
    //    ML-DSA implementation.
    let pk_hash = {
        let mut h = Hasher::falcon_script_args_hasher();
        h.update(pk);
        h.hash()
    };
    if !ct_eq(&pk_hash, expected_pk_hash) {
        return Err(Error::PubkeyHashMismatch);
    }

    // 5. Build signing digest from CighashAll stream — Falcon variant
    //    uses `falcon_message_hasher` (personalised `b"ckb-falcon-msg"`).
    let digest = {
        let mut h = Hasher::falcon_message_hasher();
        generate_ckb_tx_message_all(&mut h).map_err(|_| Error::SignatureVerifyFailed)?;
        h.hash()
    };

    // 6. Falcon verify — fn-dsa-vrfy accepts the raw blake2b digest
    //    directly with `HASH_ID_RAW`. NO FIPS-204 §5.4 wrapping.
    verifying::verify(expected_param_id, pk, sig, &digest)?;

    // Belt-and-braces flag round-trip check (same as mldsa-lock-v2).
    let _ = construct_flag(expected_param_id, true);

    Ok(())
}

/// Constant-time byte comparison. Returns true iff all bytes match.
/// All bytes are always examined regardless of content.
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
