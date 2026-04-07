//! Stage 2 real sign→verify round-trip test for the v2 ML-DSA-65 lock.
//!
//! Proves the end-to-end signing pipeline: the *exact same* CighashAll byte
//! stream flows through the signer (via `ckb_fips204_utils::signing::sign`)
//! and the verifier (via `verifying::verify` inside `ckb_tx_message_all_in_ckb_vm`),
//! by:
//!
//! 1. Deriving a deterministic ML-DSA-65 keypair from a fixed master seed
//!    via the production HKDF path (`derive_lock_args`).
//! 2. Building a tx with a placeholder witness whose `lock` field is zeroed
//!    but has the correct `[flag | pk | sig]` length layout.
//! 3. Computing CighashAll bytes **host-side** via
//!    `generate_ckb_tx_message_all_host`, which mirrors the on-chain
//!    `generate_ckb_tx_message_all_with_witness` byte-for-byte.
//! 4. Feeding those bytes into `signing::sign()` to get the real signature.
//! 5. Rebuilding the tx with the real witness containing `[flag | pk | sig]`
//!    — `tx_hash` is unchanged because the lock field is not part of the raw
//!    tx, and the CighashAll stream deliberately excludes the lock field of
//!    the first group witness, so replacing it is safe.
//! 6. Running `verify_tx` and asserting it returns `Ok`.
//!
//! If this test passes, the v2 lock is ready for testnet deploy.

use ckb_testtool::ckb_types::{
    bytes::Bytes,
    core::TransactionBuilder,
    packed::{BytesOpt, CellInput, CellOutput, WitnessArgs},
    prelude::*,
};
use ckb_testtool::context::Context;

use ckb_fips204_utils::{
    ckb_tx_message_all_host::generate_ckb_tx_message_all_host,
    construct_flag, lengths,
    signing::{derive_lock_args, sign},
    ParamId,
};

const MAX_CYCLES: u64 = 1_000_000_000;

const V2_MLDSA65_BIN: &str =
    "../../contracts/mldsa-lock-v2/target/riscv64imac-unknown-none-elf/release/mldsa65-lock-v2";

/// Deterministic master seed — fixed so test failures are reproducible.
const TEST_MASTER_SEED: [u8; 32] = [
    0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42,
];
const KEY_INDEX: u32 = 0;

#[test]
fn mldsa65_roundtrip_sign_then_verify_tx() {
    let mut context = Context::default();

    // 1. Deploy v2 binary.
    let bin: Bytes = std::fs::read(V2_MLDSA65_BIN)
        .expect("v2 mldsa65 binary not built")
        .into();
    let out_point = context.deploy_cell(bin);

    // 2. Derive the deterministic keypair + 37-byte lock args from the seed.
    //    The wallet-side `derive_lock_args` uses the same HKDF path
    //    (`"ckb/quantum-purse/ml-dsa/65/0"`) the signer will use later.
    let (pk_bytes, lock_args) = derive_lock_args(&TEST_MASTER_SEED, ParamId::Mldsa65, KEY_INDEX)
        .expect("derive lock args");
    assert_eq!(lock_args.len(), 37);
    let (pk_len, sig_len, _) = lengths(ParamId::Mldsa65);
    assert_eq!(pk_bytes.len(), pk_len);

    // 3. Lock script + input cell referencing it.
    let lock_script = context
        .build_script(&out_point, Bytes::from(lock_args.to_vec()))
        .expect("build_script");

    let input_cell_output = CellOutput::new_builder()
        .capacity(1000u64)
        .lock(lock_script.clone())
        .build();
    let input_cell_data = Bytes::new();
    let input_out_point =
        context.create_cell(input_cell_output.clone(), input_cell_data.clone());
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();

    // 4. Output cell — keep it simple. Same lock.
    let output_cell = CellOutput::new_builder()
        .capacity(500u64)
        .lock(lock_script)
        .build();
    let outputs_data = vec![Bytes::new()];

    // 5. Placeholder witness. The *lock* field has the correct final length
    //    `1 + pk_len + sig_len` but is filled with zeros for now. The
    //    `input_type` and `output_type` fields are absent (`None`) — these
    //    ARE hashed into CighashAll, so they must be finalised before we
    //    compute the digest. The `lock` field is deliberately excluded
    //    from CighashAll for the first group witness, which is exactly why
    //    we can build the tx with a zero placeholder now and splice the real
    //    signature in afterwards.
    let placeholder_lock_bytes = vec![0u8; 1 + pk_len + sig_len];
    let placeholder_witness = WitnessArgs::new_builder()
        .lock(BytesOpt::new_builder()
            .set(Some(Bytes::from(placeholder_lock_bytes).pack()))
            .build())
        .build();

    // 6. Build the tx. ckb-testtool's `complete_tx` fills in cell_deps etc.
    let tx = TransactionBuilder::default()
        .input(input)
        .output(output_cell)
        .outputs_data(outputs_data.pack())
        .witness(placeholder_witness.as_bytes().pack())
        .build();
    let tx = context.complete_tx(tx);

    // 7. Compute CighashAll bytes host-side. Single input → single group →
    //    group_input_indices = [0].
    let resolved_inputs = vec![(input_cell_output, input_cell_data)];
    let mut cighash_all_bytes: Vec<u8> = Vec::new();
    generate_ckb_tx_message_all_host(
        &mut cighash_all_bytes,
        &tx,
        &resolved_inputs,
        &[0usize],
    )
    .expect("generate_ckb_tx_message_all_host");
    assert!(
        !cighash_all_bytes.is_empty(),
        "CighashAll stream is unexpectedly empty"
    );
    eprintln!("CighashAll stream: {} bytes", cighash_all_bytes.len());

    // 8. Sign the CighashAll bytes. `sign()` runs the full signing pipeline:
    //    `build_final_message` (blake2b message hasher + FIPS-204 §5.4 M'
    //    framing) and returns the witness lock bytes [flag | pk | sig].
    let real_witness_lock_bytes = sign(
        &TEST_MASTER_SEED,
        ParamId::Mldsa65,
        KEY_INDEX,
        &cighash_all_bytes,
    )
    .expect("sign failed");

    // Sanity: the returned bytes have the layout the contract expects.
    assert_eq!(real_witness_lock_bytes.len(), 1 + pk_len + sig_len);
    let expected_flag = construct_flag(ParamId::Mldsa65, true);
    assert_eq!(real_witness_lock_bytes[0], expected_flag);
    assert_eq!(&real_witness_lock_bytes[1..1 + pk_len], &pk_bytes[..]);

    // 9. Rebuild the witness with the real lock. tx_hash is unchanged — the
    //    RawTransaction (which is what tx_hash covers) does not include
    //    witnesses. And CighashAll for the first group witness excludes the
    //    `lock` field, so we can overwrite it without invalidating the
    //    signature we just computed.
    let signed_witness = WitnessArgs::new_builder()
        .lock(BytesOpt::new_builder()
            .set(Some(Bytes::from(real_witness_lock_bytes).pack()))
            .build())
        .build();

    // Rebuild the tx with the signed witness in place of the placeholder.
    //
    // We construct it fresh from the resolved tx's inputs/outputs/deps so
    // the new witness shows up at index 0 without mutating a view in place.
    let raw = tx.clone();
    let signed_tx = raw
        .as_advanced_builder()
        .set_witnesses(vec![signed_witness.as_bytes().pack()])
        .build();

    // Same tx_hash (witnesses excluded from the raw tx)?
    assert_eq!(
        signed_tx.hash(),
        tx.hash(),
        "replacing the witness lock changed tx_hash — something is very wrong"
    );

    // 10. Run the real contract against the signed tx. This is the moment
    //     of truth: we've computed CighashAll host-side, signed it, and now
    //     the on-chain streamer runs inside the mocked VM and produces its
    //     own CighashAll bytes. If the two byte streams differ in any
    //     position, `fips204::ml_dsa_65::verify` will return false and the
    //     contract exits with code 46.
    let result = context.verify_tx(&signed_tx, MAX_CYCLES);
    match result {
        Ok(cycles) => {
            eprintln!("verify_tx passed ({cycles} cycles)");
        }
        Err(e) => panic!(
            "verify_tx failed: {e:?}\n\n\
             If the exit code is 46 (SignatureVerifyFailed) then the host-side \
             CighashAll byte stream does NOT match the on-chain stream — there \
             is drift in generate_ckb_tx_message_all_host vs \
             generate_ckb_tx_message_all_with_witness. Diff the two byte \
             streams at a known fixture to find the divergent segment."
        ),
    }

    // 11. Dump the signed tx to /tmp/mldsa65_signed_tx.json so ckb-debugger
    //     can run the same tx through a real CKB-VM instance outside
    //     ckb-testtool, for an independent sanity check (and accurate cycle
    //     count / flamegraph if requested).
    //
    //     Run afterwards:
    //         ckb-debugger --tx-file /tmp/mldsa65_signed_tx.json \
    //                      --script input.0.lock
    let repr_mock = context
        .dump_tx(&signed_tx)
        .expect("dump_tx for ckb-debugger");
    let json = serde_json::to_string_pretty(&repr_mock).expect("json serialize");
    std::fs::write("/tmp/mldsa65_signed_tx.json", json)
        .expect("write /tmp/mldsa65_signed_tx.json");
    eprintln!("signed tx dumped to /tmp/mldsa65_signed_tx.json");
}
