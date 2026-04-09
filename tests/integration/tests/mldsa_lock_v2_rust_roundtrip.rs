//! Stage 2 real sign→verify round-trip tests for all three v2-rust ML-DSA
//! variants (44 / 65 / 87).
//!
//! Mirrors `mldsa_lock_v2_roundtrip.rs` but targets the RustCrypto `ml-dsa`
//! backend. Key difference from the v2 sibling: we DO NOT route the signer
//! through `ckb_fips204_utils::signing::sign`, because that path double-wraps
//! the M' framing (explicit wrapper + fips204 internal wrapper). The v2-rust
//! contract calls `vk.verify_with_context(digest, DOMAIN, sig)` which applies
//! FIPS-204 §5.4 M' framing exactly once with `ctx = DOMAIN`. The matching
//! signer call is `sk.sign_deterministic(&digest, DOMAIN)`.
//!
//! Pipeline (per variant):
//!   1. Deterministic keygen: `<MlDsaX as KeyGen>::from_seed(&seed)`
//!   2. pk_bytes = sk.verifying_key().encode()
//!   3. lock_args = personalised-blake2b("ckb-mldsa-sct", pk_bytes)[..32]
//!      wrapped with the 4-byte header + flag byte. Use ckb-fips204-utils
//!      `lock_args` helper — its personalisation string is identical to the
//!      on-chain contract's `Hasher::script_args_hasher`.
//!   4. Build tx w/ placeholder witness lock, run `generate_ckb_tx_message_all_host`
//!      to get the CighashAll stream, hash it through
//!      `Hasher::message_hasher()` → 32-byte digest
//!   5. sig = sk.signing_key().sign_deterministic(&digest, DOMAIN).encode()
//!   6. Splice `[flag | pk | sig]` into witness lock, verify_tx
//!
//! All three tests dump their signed tx to `/tmp/mldsa{44,65,87}_rust_signed_tx.json`
//! for independent ckb-debugger validation.

use ckb_testtool::ckb_types::{
    bytes::Bytes,
    core::TransactionBuilder,
    packed::{BytesOpt, CellInput, CellOutput, WitnessArgs},
    prelude::*,
};
use ckb_testtool::context::Context;

use ckb_fips204_utils::{
    ckb_tx_message_all_host::generate_ckb_tx_message_all_host,
    construct_flag, lengths, lock_args, Hasher, ParamId,
};

#[allow(unused_imports)]
use ml_dsa::signature::Keypair;
#[allow(unused_imports)]
use ml_dsa::{B32, EncodedSignature, KeyGen, MlDsa44, MlDsa65, MlDsa87};

/// Domain separator — MUST match `mldsa_lock_v2_rust::helpers::DOMAIN`.
const DOMAIN: &[u8] = b"CKB-MLDSA-LOCK";

const MAX_CYCLES: u64 = 1_000_000_000;

const V2_RUST_MLDSA44_BIN: &str =
    "../../contracts/mldsa-lock-v2-rust/target/riscv64imac-unknown-none-elf/release/mldsa44-lock-v2-rust";
const V2_RUST_MLDSA65_BIN: &str =
    "../../contracts/mldsa-lock-v2-rust/target/riscv64imac-unknown-none-elf/release/mldsa65-lock-v2-rust";
const V2_RUST_MLDSA87_BIN: &str =
    "../../contracts/mldsa-lock-v2-rust/target/riscv64imac-unknown-none-elf/release/mldsa87-lock-v2-rust";

/// Macro generates a concrete-typed round-trip test per variant.
///
/// A generic `fn<P: KeyGen>` version was attempted but the ml-dsa trait
/// hierarchy doesn't expose `encode` / `signing_key` on the associated types
/// produced by `KeyGen::KeyPair`; the methods only resolve on the concrete
/// `MlDsa44/65/87` types. Macro expansion sidesteps this cleanly.
macro_rules! roundtrip_test {
    (
        $fn_name:ident,
        $MlDsa:ty,
        $param_id:expr,
        $variant_tag:expr,
        $bin_path:expr,
        $dump_path:expr
    ) => {
        #[test]
        fn $fn_name() {
            let mut context = Context::default();

            // 1. Deploy v2-rust binary for this variant.
            let bin: Bytes = std::fs::read($bin_path)
                .unwrap_or_else(|e| {
                    panic!(
                        "failed to read {}: {}. Build with: \
                         cd contracts/mldsa-lock-v2-rust && \
                         cargo build --release --no-default-features \
                         --features variant-{}",
                        $bin_path, e, &$variant_tag[5..]
                    )
                })
                .into();
            let out_point = context.deploy_cell(bin);

            // 2. Deterministic keygen from a fixed seed.
            let seed: B32 = B32::from([0x42u8; 32]);
            let sk = <$MlDsa as KeyGen>::from_seed(&seed);
            let vk = sk.verifying_key();
            let pk_bytes: Vec<u8> = vk.encode().to_vec();

            let (pk_len, sig_len, _) = lengths($param_id);
            assert_eq!(
                pk_bytes.len(),
                pk_len,
                "{}: encoded vk length mismatch",
                $variant_tag
            );

            // 3. Build 37-byte lock args.
            let args = lock_args($param_id, &pk_bytes);
            assert_eq!(args.len(), 37);

            let lock_script = context
                .build_script(&out_point, Bytes::from(args.to_vec()))
                .expect("build_script");

            // 4. Input cell locked by our script.
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

            // 5. Output cell.
            let output_cell = CellOutput::new_builder()
                .capacity(500u64)
                .lock(lock_script)
                .build();
            let outputs_data = vec![Bytes::new()];

            // 6. Placeholder witness.
            let placeholder_lock_bytes = vec![0u8; 1 + pk_len + sig_len];
            let placeholder_witness = WitnessArgs::new_builder()
                .lock(
                    BytesOpt::new_builder()
                        .set(Some(Bytes::from(placeholder_lock_bytes).pack()))
                        .build(),
                )
                .build();

            let tx = TransactionBuilder::default()
                .input(input)
                .output(output_cell)
                .outputs_data(outputs_data.pack())
                .witness(placeholder_witness.as_bytes().pack())
                .build();
            let tx = context.complete_tx(tx);

            // 7. Host-side CighashAll stream.
            let resolved_inputs = vec![(input_cell_output, input_cell_data)];
            let mut cighash_all_bytes: Vec<u8> = Vec::new();
            generate_ckb_tx_message_all_host(
                &mut cighash_all_bytes,
                &tx,
                &resolved_inputs,
                &[0usize],
            )
            .expect("generate_ckb_tx_message_all_host");
            assert!(!cighash_all_bytes.is_empty());
            eprintln!(
                "[{}] CighashAll stream: {} bytes",
                $variant_tag,
                cighash_all_bytes.len()
            );

            // 8. Hash through message_hasher → 32-byte digest.
            let mut mh = Hasher::message_hasher();
            mh.update(&cighash_all_bytes);
            let digest: [u8; 32] = mh.hash();
            eprintln!("[{}] digest: {}", $variant_tag, hex::encode(digest));

            // 9. Sign with context = DOMAIN.
            let sig = sk
                .signing_key()
                .sign_deterministic(&digest, DOMAIN)
                .expect("sign_deterministic");
            let sig_bytes_arr: EncodedSignature<$MlDsa> = sig.encode();
            let sig_bytes: Vec<u8> = sig_bytes_arr.to_vec();
            assert_eq!(
                sig_bytes.len(),
                sig_len,
                "{}: encoded sig length mismatch",
                $variant_tag
            );

            // 10. Splice [flag | pk | sig] into the witness lock.
            let flag = construct_flag($param_id, true);
            let mut real_witness_lock_bytes: Vec<u8> =
                Vec::with_capacity(1 + pk_len + sig_len);
            real_witness_lock_bytes.push(flag);
            real_witness_lock_bytes.extend_from_slice(&pk_bytes);
            real_witness_lock_bytes.extend_from_slice(&sig_bytes);

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

            assert_eq!(
                signed_tx.hash(),
                tx.hash(),
                "replacing the witness lock changed tx_hash — something is very wrong"
            );

            // 11. Run the v2-rust contract.
            match context.verify_tx(&signed_tx, MAX_CYCLES) {
                Ok(cycles) => {
                    eprintln!(
                        "[{}] v2-rust verify_tx passed ({} cycles)",
                        $variant_tag, cycles
                    );
                }
                Err(e) => panic!(
                    "[{}] v2-rust verify_tx failed: {:?}",
                    $variant_tag, e
                ),
            }

            // 12. Dump for ckb-debugger independent validation.
            let repr_mock = context
                .dump_tx(&signed_tx)
                .expect("dump_tx for ckb-debugger");
            let json = serde_json::to_string_pretty(&repr_mock).expect("json serialize");
            std::fs::write($dump_path, json)
                .unwrap_or_else(|e| panic!("write {}: {}", $dump_path, e));
            eprintln!("[{}] signed tx dumped to {}", $variant_tag, $dump_path);
        }
    };
}

roundtrip_test!(
    mldsa44_rust_roundtrip_sign_then_verify_tx,
    MlDsa44,
    ParamId::Mldsa44,
    "mldsa44",
    V2_RUST_MLDSA44_BIN,
    "/tmp/mldsa44_rust_signed_tx.json"
);

roundtrip_test!(
    mldsa65_rust_roundtrip_sign_then_verify_tx,
    MlDsa65,
    ParamId::Mldsa65,
    "mldsa65",
    V2_RUST_MLDSA65_BIN,
    "/tmp/mldsa65_rust_signed_tx.json"
);

roundtrip_test!(
    mldsa87_rust_roundtrip_sign_then_verify_tx,
    MlDsa87,
    ParamId::Mldsa87,
    "mldsa87",
    V2_RUST_MLDSA87_BIN,
    "/tmp/mldsa87_rust_signed_tx.json"
);
