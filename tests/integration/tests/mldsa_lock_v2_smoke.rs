//! Stage 1 structural smoke test for the v2 ML-DSA-65 lock binary.
//!
//! Goal: prove the v2 contract binary loads into ckb-testtool, parses its
//! 37-byte lock args, parses its witness lock layout, passes the pubkey-hash
//! check, and reaches the actual signature verify step. A placeholder (all
//! zero) signature is used intentionally — we expect `verify_tx` to fail with
//! `SignatureVerifyFailed` (error code 46 from `ckb_fips204_utils::Error`).
//!
//! If this test fails with a structural error (codes 40-45), something in the
//! contract's byte-layout checks is wrong and we need to fix that before
//! investing in a host-side `ckb_tx_message_all` port for real sign/verify
//! round-trip tests (Stage 2).
//!
//! Error codes (from `ckb_fips204_utils::Error`):
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
use fips204::ml_dsa_65;
use fips204::traits::{KeyGen, SerDes};

/// ML-DSA verify is cycle-heavy — give the VM plenty of headroom.
const MAX_CYCLES: u64 = 1_000_000_000;

/// Path to the pre-built v2 ML-DSA-65 contract binary, relative to this
/// crate's `Cargo.toml` directory (`tests/integration/`).
const V2_MLDSA65_BIN: &str =
    "../../contracts/mldsa-lock-v2/target/riscv64imac-unknown-none-elf/release/mldsa65-lock-v2";

#[test]
fn mldsa65_placeholder_sig_reaches_verify_and_fails() {
    let mut context = Context::default();

    // 1. Load and deploy the v2 binary.
    let bin: Bytes = std::fs::read(V2_MLDSA65_BIN)
        .unwrap_or_else(|e| {
            panic!(
                "failed to read {V2_MLDSA65_BIN}: {e}. \
                 Build with: cd contracts/mldsa-lock-v2 && cargo build --release"
            )
        })
        .into();
    let out_point = context.deploy_cell(bin);

    // 2. Generate a real ML-DSA-65 keypair — the pubkey hash must match
    //    the hash embedded in the lock args for the contract to reach verify.
    //    `try_keygen` is provided by the `default-rng` feature of fips204.
    let (pk, _sk) = ml_dsa_65::KG::try_keygen().expect("ml_dsa_65 keygen");
    let pk_bytes: [u8; 1952] = pk.into_bytes();

    // 3. Build the canonical 37-byte v2 lock args for this pubkey.
    let args = lock_args(ParamId::Mldsa65, &pk_bytes);
    assert_eq!(args.len(), 37);
    assert_eq!(&args[0..4], &[0x80, 0x01, 0x01, 0x01]);

    // 4. Build the lock script referencing the deployed contract.
    let lock_script = context
        .build_script(&out_point, Bytes::from(args.to_vec()))
        .expect("build_script");

    // 5. Create an input cell locked by our v2 script.
    //    (In ckb-types 1.1.0, u64 has multiple Pack impls — pass it directly
    //    via the blanket Into<Uint64>.)
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

    // 6. Output cell — same lock, doesn't matter for this test.
    let outputs = vec![CellOutput::new_builder()
        .capacity(500u64)
        .lock(lock_script)
        .build()];
    let outputs_data = vec![Bytes::new()];

    // 7. Build the witness lock field: [flag | pk | placeholder_sig].
    //    The contract parses it as exactly these three segments
    //    (contracts/mldsa-lock-v2/src/entry.rs lines 60-74).
    let (pk_len, sig_len, _sk_len) = lengths(ParamId::Mldsa65);
    let flag = construct_flag(ParamId::Mldsa65, true);

    let mut witness_lock_bytes = Vec::with_capacity(1 + pk_len + sig_len);
    witness_lock_bytes.push(flag);
    witness_lock_bytes.extend_from_slice(&pk_bytes);
    witness_lock_bytes.extend(std::iter::repeat(0u8).take(sig_len));
    assert_eq!(witness_lock_bytes.len(), 1 + pk_len + sig_len);

    let witness_args = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(witness_lock_bytes)).pack())
        .build();

    // 8. Assemble the tx and let ckb-testtool fill in cell deps etc.
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

            // The key invariant: we must have reached the signature verify
            // step, not failed earlier in structural checks. Error code 46
            // = SignatureVerifyFailed. Anything in 40..=45 means a structural
            // check caught the placeholder input before verify.
            //
            // ckb-testtool embeds the contract's i8 exit code into the error
            // message. We check for the numeric code rather than parsing the
            // enum variant name because the error string format is not stable.
            let has_46 = msg.contains("error code 46")
                || msg.contains("ValidationFailure(46")
                || msg.contains("exit code: 46")
                || msg.contains("code: 46")
                || msg.contains("(46)");
            assert!(
                has_46,
                "expected exit code 46 (SignatureVerifyFailed) but got: {msg}\n\n\
                 If the code is in 40..=45, a structural check in entry.rs \
                 rejected our test inputs before reaching verify. See the \
                 error-code table at the top of this file."
            );
        }
    }
}
