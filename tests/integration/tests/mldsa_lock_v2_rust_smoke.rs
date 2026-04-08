//! Stage 1 structural smoke test for the v2-rust ML-DSA-65 lock binary.
//!
//! Mirrors `mldsa_lock_v2_smoke.rs` but targets the `mldsa-lock-v2-rust`
//! variant, which uses the RustCrypto `ml-dsa` crate instead of `fips204`.
//!
//! Goal: prove the v2-rust contract binary loads into ckb-testtool, parses
//! its 37-byte lock args, parses the witness lock layout, passes the pubkey-
//! hash check, and reaches the actual signature-verify step. A placeholder
//! (all-zero) signature is used — we expect `verify_tx` to fail with
//! `SignatureVerifyFailed` (error code 46 from `helpers::Error`).
//!
//! Key difference from the sibling sibling test: the pubkey is generated via
//! the `ml-dsa` crate (RustCrypto) instead of `fips204`. Both crates
//! implement FIPS 204 serialization — so an ml-dsa-generated pubkey's byte
//! representation is compatible with `ckb-fips204-utils::lock_args` (which
//! hashes whatever bytes it's given with the `ckb-mldsa-sct` personalisation).
//!
//! Error codes (from `mldsa_lock_v2_rust::Error`, values match v2 sibling):
//!
//! ```text
//! 40 InvalidParamId
//! 41 InvalidPubkeyLength
//! 42 InvalidSignatureLength
//! 43 InvalidLockLength
//! 44 InvalidLockArgsLength
//! 45 PubkeyHashMismatch
//! 46 SignatureVerifyFailed  ← expected here
//! 47 ContextTooLong
//! ```

use ckb_testtool::ckb_types::{
    bytes::Bytes,
    core::TransactionBuilder,
    packed::{CellInput, CellOutput, WitnessArgs},
    prelude::*,
};
use ckb_testtool::context::Context;

use ckb_fips204_utils::{construct_flag, lengths, lock_args, ParamId};

// NOTE: this smoke test deliberately does NOT keygen a real ML-DSA keypair.
// The `ml-dsa` crate's git rev uses `signature 3.0.0-rc.10` which expects
// rand_core 0.10's CryptoRng trait — there's no published RNG crate yet
// that implements it, and wiring rand_core + getrandom + signature::rand
// shim layers costs more time than the smoke test is worth. Instead we
// feed a 1952-byte dummy pubkey. The on-chain `EncodedVerifyingKey::try_from`
// only validates LENGTH, and `VerifyingKey::decode` accepts the bytes
// structurally; the final `verify_with_context` returns `false` for garbage
// signatures, which the entry.rs pipeline maps to `SignatureVerifyFailed`
// (error code 46) — the behaviour we want to observe.
//
// Real sign→verify round-trips land in a Stage 2 test which will need a
// host signer using the ml-dsa crate + some compatible RNG source. That's
// separate session scope.

/// ML-DSA verify is cycle-heavy — give the VM plenty of headroom.
const MAX_CYCLES: u64 = 1_000_000_000;

/// Path to the pre-built v2-rust ML-DSA-65 contract binary.
const V2_RUST_MLDSA65_BIN: &str =
    "../../contracts/mldsa-lock-v2-rust/target/riscv64imac-unknown-none-elf/release/mldsa65-lock-v2-rust";

#[test]
fn mldsa65_rust_placeholder_sig_reaches_verify_and_fails() {
    let mut context = Context::default();

    // 1. Load and deploy the v2-rust binary.
    let bin: Bytes = std::fs::read(V2_RUST_MLDSA65_BIN)
        .unwrap_or_else(|e| {
            panic!(
                "failed to read {V2_RUST_MLDSA65_BIN}: {e}. \
                 Build with: cd contracts/mldsa-lock-v2-rust && cargo build --release"
            )
        })
        .into();
    let out_point = context.deploy_cell(bin);

    // 2. Build a 1952-byte dummy pubkey. See module-level comment for why we
    //    don't keygen a real one here. The byte pattern is arbitrary — the
    //    on-chain pubkey-hash check hashes whatever we give it with the
    //    "ckb-mldsa-sct" personalisation and compares to args[5..37], so as
    //    long as the same bytes go into both args and the witness, the hash
    //    match succeeds and we reach the verify step.
    let (pk_len, sig_len, _sk_len) = lengths(ParamId::Mldsa65);
    let vk_bytes: Vec<u8> = (0..pk_len).map(|i| (i & 0xff) as u8).collect();
    assert_eq!(vk_bytes.len(), 1952);

    // 3. Build the canonical 37-byte v2 lock args for this pubkey.
    //    Uses ckb-fips204-utils's lock_args which hashes with the
    //    "ckb-mldsa-sct" personalisation — identical to what the v2-rust
    //    contract's helpers::Hasher::script_args_hasher produces on-chain.
    let args = lock_args(ParamId::Mldsa65, &vk_bytes);
    assert_eq!(args.len(), 37);
    assert_eq!(&args[0..4], &[0x80, 0x01, 0x01, 0x01]);

    // 4. Build the lock script referencing the deployed contract.
    let lock_script = context
        .build_script(&out_point, Bytes::from(args.to_vec()))
        .expect("build_script");

    // 5. Create an input cell locked by our v2-rust script.
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000u64)
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();

    // 6. Output cell.
    let outputs = vec![CellOutput::new_builder()
        .capacity(500u64)
        .lock(lock_script)
        .build()];
    let outputs_data = vec![Bytes::new()];

    // 7. Build the witness lock field: [flag | pk | placeholder_sig].
    let flag = construct_flag(ParamId::Mldsa65, true);
    let mut witness_lock_bytes = Vec::with_capacity(1 + pk_len + sig_len);
    witness_lock_bytes.push(flag);
    witness_lock_bytes.extend_from_slice(&vk_bytes);
    witness_lock_bytes.extend(std::iter::repeat(0u8).take(sig_len));
    assert_eq!(witness_lock_bytes.len(), 1 + pk_len + sig_len);

    let witness_args = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(witness_lock_bytes)).pack())
        .build();

    // 8. Assemble the tx.
    let tx = TransactionBuilder::default()
        .input(input)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .witness(witness_args.as_bytes().pack())
        .build();
    let tx = context.complete_tx(tx);

    // 9. Run the contract.
    let result = context.verify_tx(&tx, MAX_CYCLES);

    match result {
        Ok(cycles) => panic!(
            "expected verify to fail with SignatureVerifyFailed (46), \
             but verify_tx succeeded ({cycles} cycles) — this would mean \
             the contract accepted an all-zero signature, which is a bug."
        ),
        Err(e) => {
            let msg = format!("{e:?}");
            eprintln!("verify_tx failed as expected: {msg}");

            let has_46 = msg.contains("error code 46")
                || msg.contains("ValidationFailure(46")
                || msg.contains("exit code: 46")
                || msg.contains("code: 46")
                || msg.contains("(46)");
            assert!(
                has_46,
                "expected exit code 46 (SignatureVerifyFailed) but got: {msg}\n\n\
                 If the code is in 40..=45, a structural check in entry.rs \
                 rejected our test inputs before reaching verify."
            );
        }
    }
}
