//! Stage 2 sign→verify round-trip test for the Falcon v2 lock variants.
//!
//! Mirrors `mldsa_lock_v2_roundtrip.rs` but for Falcon-512 and Falcon-1024.
//! Differences from the ML-DSA version:
//!
//! - Uses `falcon_signing::derive_lock_args` and `falcon_signing::sign`
//!   (separate from the ML-DSA `signing::*` because Falcon needs hardware
//!   FP for keygen/signing).
//! - No FIPS-204 `M'` framing — the digest from `Hasher::falcon_message_hasher`
//!   is fed directly to `fn-dsa-vrfy` with `HASH_ID_RAW`.
//! - Different lock script binary path.
//! - Different default contract output indices once deployed.
//!
//! Both Falcon-512 and Falcon-1024 are exercised end-to-end inside
//! ckb-testtool's mocked CKB-VM.

use ckb_testtool::ckb_types::{
    bytes::Bytes,
    core::TransactionBuilder,
    packed::{BytesOpt, CellInput, CellOutput, WitnessArgs},
    prelude::*,
};
use ckb_testtool::context::Context;

use ckb_fips204_utils::{
    ckb_tx_message_all_host::generate_ckb_tx_message_all_host,
    construct_flag,
    falcon_signing::{derive_lock_args, sign},
    lengths, ParamId,
};

const MAX_CYCLES: u64 = 1_000_000_000;

const FALCON512_BIN: &str =
    "../../contracts/falcon-lock-v2/target/riscv64imac-unknown-none-elf/release/falcon512-lock-v2";
const FALCON1024_BIN: &str =
    "../../contracts/falcon-lock-v2/target/riscv64imac-unknown-none-elf/release/falcon1024-lock-v2";

const TEST_MASTER_SEED: [u8; 32] = [
    0xf1, 0xc0, 0xed, 0xa5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfa,
];
const KEY_INDEX: u32 = 0;

fn run_falcon_roundtrip(param_id: ParamId, bin_path: &str) {
    let mut context = Context::default();

    // 1. Deploy the variant-specific binary.
    let bin: Bytes = std::fs::read(bin_path)
        .unwrap_or_else(|e| {
            panic!(
                "failed to read {bin_path}: {e}. \
                 Build with: cd contracts/falcon-lock-v2 && cargo build --release"
            )
        })
        .into();
    let out_point = context.deploy_cell(bin);

    // 2. Derive deterministic Falcon keypair + lock args via the wallet
    //    HKDF path. Same seed always produces the same keypair, so this
    //    test is reproducible across runs.
    let (pk_bytes, lock_args) =
        derive_lock_args(&TEST_MASTER_SEED, param_id, KEY_INDEX).expect("derive_lock_args");
    let (pk_len, sig_len, _) = lengths(param_id);
    assert_eq!(pk_bytes.len(), pk_len);
    assert_eq!(lock_args.len(), 37);

    // 3. Lock script + input cell.
    let lock_script = context
        .build_script(&out_point, Bytes::from(lock_args.to_vec()))
        .expect("build_script");

    let input_cell_output = CellOutput::new_builder()
        .capacity(1000u64)
        .lock(lock_script.clone())
        .build();
    let input_cell_data = Bytes::new();
    let input_out_point = context.create_cell(input_cell_output.clone(), input_cell_data.clone());
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();

    let output_cell = CellOutput::new_builder()
        .capacity(500u64)
        .lock(lock_script)
        .build();
    let outputs_data = vec![Bytes::new()];

    // 4. Placeholder witness lock — same trick as the ML-DSA test. The
    //    contract excludes the lock field of the first group witness from
    //    its CighashAll stream, so we can build the tx with all-zero sig
    //    and splice the real one in after computing CighashAll.
    let placeholder_lock_bytes = vec![0u8; 1 + pk_len + sig_len];
    let placeholder_witness = WitnessArgs::new_builder()
        .lock(
            BytesOpt::new_builder()
                .set(Some(Bytes::from(placeholder_lock_bytes).pack()))
                .build(),
        )
        .build();

    // 5. Build + complete the tx.
    let tx = TransactionBuilder::default()
        .input(input)
        .output(output_cell)
        .outputs_data(outputs_data.pack())
        .witness(placeholder_witness.as_bytes().pack())
        .build();
    let tx = context.complete_tx(tx);

    // 6. Compute CighashAll bytes host-side. Single input → group_input_indices = [0].
    let resolved_inputs = vec![(input_cell_output, input_cell_data)];
    let mut cighash_all_bytes: Vec<u8> = Vec::new();
    generate_ckb_tx_message_all_host(&mut cighash_all_bytes, &tx, &resolved_inputs, &[0usize])
        .expect("generate_ckb_tx_message_all_host");
    eprintln!(
        "[{:?}] CighashAll stream: {} bytes",
        param_id,
        cighash_all_bytes.len()
    );

    // 7. Sign via the Falcon signer. The signer applies the same blake2b
    //    personalisation (`b"ckb-falcon-msg"`) the contract uses on its
    //    side and then calls fn-dsa-sign on the resulting 32-byte digest
    //    with `DOMAIN_NONE + HASH_ID_RAW`.
    let real_witness_lock_bytes = sign(&TEST_MASTER_SEED, param_id, KEY_INDEX, &cighash_all_bytes)
        .expect("falcon sign failed");
    assert_eq!(real_witness_lock_bytes.len(), 1 + pk_len + sig_len);
    assert_eq!(real_witness_lock_bytes[0], construct_flag(param_id, true));
    assert_eq!(&real_witness_lock_bytes[1..1 + pk_len], &pk_bytes[..]);
    eprintln!(
        "[{:?}] signed witness lock: {} bytes",
        param_id,
        real_witness_lock_bytes.len()
    );

    // 8. Splice the real signature in and rebuild the tx.
    let signed_witness = WitnessArgs::new_builder()
        .lock(
            BytesOpt::new_builder()
                .set(Some(Bytes::from(real_witness_lock_bytes).pack()))
                .build(),
        )
        .build();
    let signed_tx = tx
        .clone()
        .as_advanced_builder()
        .set_witnesses(vec![signed_witness.as_bytes().pack()])
        .build();
    assert_eq!(signed_tx.hash(), tx.hash());

    // 9. Run the contract. Any drift between the host-side CighashAll
    //    bytes and the on-chain version produces SignatureVerifyFailed.
    let result = context.verify_tx(&signed_tx, MAX_CYCLES);
    match result {
        Ok(cycles) => {
            eprintln!("[{:?}] verify_tx passed ({cycles} cycles)", param_id);
        }
        Err(e) => panic!(
            "[{:?}] verify_tx failed: {e:?}\n\n\
             Falcon CighashAll drift between on-chain and host-side stream.",
            param_id
        ),
    }

    // 10. Dump the signed tx for ckb-debugger / external validation.
    let dump_path = match param_id {
        ParamId::Falcon512 => "/tmp/falcon512_signed_tx.json",
        ParamId::Falcon1024 => "/tmp/falcon1024_signed_tx.json",
        _ => "/tmp/falcon_signed_tx.json",
    };
    let repr_mock = context.dump_tx(&signed_tx).expect("dump_tx");
    let json = serde_json::to_string_pretty(&repr_mock).expect("json serialize");
    std::fs::write(dump_path, json).expect("write dump");
    eprintln!("[{:?}] signed tx dumped to {}", param_id, dump_path);
}

#[test]
fn falcon512_roundtrip_sign_then_verify_tx() {
    run_falcon_roundtrip(ParamId::Falcon512, FALCON512_BIN);
}

#[test]
fn falcon1024_roundtrip_sign_then_verify_tx() {
    run_falcon_roundtrip(ParamId::Falcon1024, FALCON1024_BIN);
}
