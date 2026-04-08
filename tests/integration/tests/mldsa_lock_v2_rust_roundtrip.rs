//! Stage 2 real sign→verify round-trip test for the v2-rust ML-DSA-65 lock.
//!
//! Mirrors `mldsa_lock_v2_roundtrip.rs` but targets the RustCrypto `ml-dsa`
//! backend. Key difference from the v2 sibling: we DO NOT route the signer
//! through `ckb_fips204_utils::signing::sign`, because that path double-wraps
//! the M' framing (explicit wrapper + fips204 internal wrapper). The v2-rust
//! contract calls `vk.verify_with_context(digest, DOMAIN, sig)` which applies
//! FIPS-204 §5.4 M' framing exactly once with `ctx = DOMAIN`. The matching
//! signer call is `sk.sign_deterministic(&digest, DOMAIN)`.
//!
//! Pipeline:
//!   1. Deterministic keygen: `ExpandedSigningKey::<MlDsa65>::from_seed(&seed)`
//!   2. pk_bytes = sk.verifying_key().encode()
//!   3. lock_args = personalised-blake2b("ckb-mldsa-sct", pk_bytes)[..32]
//!      wrapped with the 4-byte header + flag byte. Use ckb-fips204-utils
//!      `lock_args` helper — its personalisation string is identical to the
//!      on-chain contract's `Hasher::script_args_hasher`.
//!   4. Build tx w/ placeholder witness lock, run `generate_ckb_tx_message_all_host`
//!      to get the CighashAll stream, hash it through
//!      `Hasher::message_hasher()` → 32-byte digest
//!   5. sig = sk.sign_deterministic(&digest, DOMAIN).encode()
//!   6. Splice `[flag | pk | sig]` into witness lock, verify_tx
//!
//! If this passes, the v2-rust lock is ready for testnet deploy.

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

use ml_dsa::{B32, EncodedSignature, KeyGen, MlDsa65};
use ml_dsa::signature::Keypair;

/// Domain separator — MUST match `mldsa_lock_v2_rust::helpers::DOMAIN`.
const DOMAIN: &[u8] = b"CKB-MLDSA-LOCK";

const MAX_CYCLES: u64 = 1_000_000_000;

const V2_RUST_MLDSA65_BIN: &str =
    "../../contracts/mldsa-lock-v2-rust/target/riscv64imac-unknown-none-elf/release/mldsa65-lock-v2-rust";

#[test]
fn mldsa65_rust_roundtrip_sign_then_verify_tx() {
    let mut context = Context::default();

    // 1. Deploy v2-rust binary.
    let bin: Bytes = std::fs::read(V2_RUST_MLDSA65_BIN)
        .unwrap_or_else(|e| {
            panic!(
                "failed to read {V2_RUST_MLDSA65_BIN}: {e}. \
                 Build with: cd contracts/mldsa-lock-v2-rust && cargo build --release"
            )
        })
        .into();
    let out_point = context.deploy_cell(bin);

    // 2. Deterministic keygen from a fixed seed. MlDsa65::key_gen_internal
    //    is called via `KeyGen::key_gen_internal(&seed)` which returns a
    //    KeyPair; we extract the signing + verifying keys from it.
    let seed: B32 = B32::from([0x42u8; 32]);
    // `KeyGen::from_seed` is the public name for ML-DSA.KeyGen_internal
    // (see ml_dsa::KeyGen trait). Returns `SigningKey<MlDsa65>`.
    let sk = <MlDsa65 as KeyGen>::from_seed(&seed);
    let vk = sk.verifying_key();
    let pk_bytes: Vec<u8> = vk.encode().to_vec();

    let (pk_len, sig_len, _) = lengths(ParamId::Mldsa65);
    assert_eq!(pk_bytes.len(), pk_len, "encoded vk length mismatch");

    // 3. Build 37-byte lock args — personalisation "ckb-mldsa-sct" matches
    //    the on-chain Hasher::script_args_hasher in v2-rust byte-for-byte.
    let args = lock_args(ParamId::Mldsa65, &pk_bytes);
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

    // 6. Placeholder witness — correct length, zero bytes. The lock field
    //    is deliberately excluded from CighashAll for the first group
    //    witness, so it's safe to splice in the real signature after the
    //    digest is computed.
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

    // 7. Host-side CighashAll stream — same generator the v2 sibling uses.
    let resolved_inputs = vec![(input_cell_output, input_cell_data)];
    let mut cighash_all_bytes: Vec<u8> = Vec::new();
    generate_ckb_tx_message_all_host(&mut cighash_all_bytes, &tx, &resolved_inputs, &[0usize])
        .expect("generate_ckb_tx_message_all_host");
    assert!(!cighash_all_bytes.is_empty());
    eprintln!("CighashAll stream: {} bytes", cighash_all_bytes.len());

    // 8. Hash the CighashAll stream through the personalised message_hasher
    //    to get the 32-byte digest that the on-chain entry.rs passes as `msg`
    //    to `verify_with_context`. Personalisation "ckb-mldsa-msg".
    let mut mh = Hasher::message_hasher();
    mh.update(&cighash_all_bytes);
    let digest: [u8; 32] = mh.hash();
    eprintln!("digest: {}", hex::encode(digest));

    // 9. Sign with context = DOMAIN. `sign_deterministic(M, ctx)` applies
    //    FIPS-204 §5.4 M' framing internally — the same framing the on-chain
    //    `verify_with_context` applies. Empty randomness → fully deterministic.
    // `sign_deterministic(M, ctx)` is on ExpandedSigningKey, reached via
    // `SigningKey::signing_key()`. Applies FIPS-204 §5.4 M' framing once
    // with `ctx = DOMAIN` — exact mirror of `verify_with_context`.
    let sig = sk
        .signing_key()
        .sign_deterministic(&digest, DOMAIN)
        .expect("sign_deterministic");
    let sig_bytes_arr: EncodedSignature<MlDsa65> = sig.encode();
    let sig_bytes: Vec<u8> = sig_bytes_arr.to_vec();
    assert_eq!(sig_bytes.len(), sig_len, "encoded sig length mismatch");

    // 10. Splice [flag | pk | sig] into the witness lock.
    let flag = construct_flag(ParamId::Mldsa65, true);
    let mut real_witness_lock_bytes: Vec<u8> = Vec::with_capacity(1 + pk_len + sig_len);
    real_witness_lock_bytes.push(flag);
    real_witness_lock_bytes.extend_from_slice(&pk_bytes);
    real_witness_lock_bytes.extend_from_slice(&sig_bytes);
    assert_eq!(real_witness_lock_bytes.len(), 1 + pk_len + sig_len);

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

    // 11. Run the v2-rust contract. This is the moment of truth.
    let result = context.verify_tx(&signed_tx, MAX_CYCLES);
    match result {
        Ok(cycles) => {
            eprintln!("v2-rust verify_tx passed ({cycles} cycles)");
        }
        Err(e) => panic!(
            "v2-rust verify_tx failed: {e:?}\n\n\
             If the exit code is 46 (SignatureVerifyFailed) then either:\n\
             (a) host-side CighashAll differs from on-chain stream, or\n\
             (b) host-side digest personalisation differs from on-chain \
                 Hasher::message_hasher, or\n\
             (c) DOMAIN bytes differ between this file and entry.rs.\n\
             Dump the digest + sig and diff against an independent impl."
        ),
    }

    // 12. Dump for ckb-debugger independent sanity check.
    let repr_mock = context
        .dump_tx(&signed_tx)
        .expect("dump_tx for ckb-debugger");
    let json = serde_json::to_string_pretty(&repr_mock).expect("json serialize");
    std::fs::write("/tmp/mldsa65_rust_signed_tx.json", json)
        .expect("write /tmp/mldsa65_rust_signed_tx.json");
    eprintln!("signed tx dumped to /tmp/mldsa65_rust_signed_tx.json");
}
