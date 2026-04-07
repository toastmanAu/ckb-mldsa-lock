//! mldsa65_spend_test — testnet smoke-test helper for the v2 ML-DSA-65 lock.
//!
//! Two modes:
//!
//!   derive-address   — given a seed, derive the v2 ML-DSA-65 lock args and
//!                      print the testnet CKB full-format address. Use the
//!                      printed address with `ckb-cli wallet transfer
//!                      --to-address <addr> --capacity <ckb>` to fund it.
//!
//!   spend            — given a seed and an already-funded (input_tx, index)
//!                      cell locked by the v2 ML-DSA-65 script, build a
//!                      spending tx to `--to`, sign it via the production
//!                      signer+host-side CighashAll, broadcast to the CKB
//!                      testnet RPC, and poll until the tx is committed.
//!
//! This is the end-to-end real-network proof-of-life for the v2 lock: the
//! same sign/verify pipeline proven in the Stage 2 round-trip test, now
//! running against a real block-producing testnet instead of ckb-testtool.
//!
//! ## Defaults
//!
//! - `--rpc`:        https://testnet.ckb.dev
//! - `--code-hash`:  mldsa65-lock-v2 type_id from the 2026-04-08 deploy
//! - `--deploy-tx`:  deploy tx that holds the mldsa65-lock-v2 code cell
//! - `--deploy-idx`: 1 (mldsa65-lock-v2 is output index 1 in the deploy tx)
//! - `--fee`:        100000 shannons (1_000_000 is a safe upper bound)
//!
//! ## Usage
//!
//! ```text
//! # 1. derive the v2 address from a test seed
//! cargo run --release --bin mldsa65_spend_test -- derive-address \
//!     --seed 42000000000000000000000000000000000000000000000000000000000000fe
//!
//! # 2. fund the printed address with ckb-cli (uses the deploy wallet)
//! ckb-cli --url https://testnet.ckb.dev wallet transfer \
//!     --from-account 0xa776bf02d19cafa3749d906cc2c9ab1cf1e80ff7 \
//!     --to-address <printed v2 address> \
//!     --capacity 500 --fee-rate 1000
//!
//! # 3. note the output (tx_hash + output index of the v2 cell)
//! # 4. spend it
//! cargo run --release --bin mldsa65_spend_test -- spend \
//!     --seed 42000000000000000000000000000000000000000000000000000000000000fe \
//!     --input-tx <funding tx hash>:<v2 output index> \
//!     --to <destination address>
//! ```

use std::process::ExitCode;

use ckb_fips204_utils::{
    ckb_tx_message_all_host::generate_ckb_tx_message_all_host, is_falcon, lengths, ParamId,
};
use ckb_jsonrpc_types as json_types;
use ckb_types::{
    bytes::Bytes,
    core::{DepType, ScriptHashType, TransactionBuilder},
    h256,
    packed::{Byte32, BytesOpt, CellDep, CellInput, CellOutput, OutPoint, Script, WitnessArgs},
    prelude::*,
    H256,
};

// ── defaults baked in from the 2026-04-08 testnet deploy ────────────────────

const DEFAULT_RPC: &str = "https://testnet.ckb.dev";

// This is the HASH of the type script `{code_hash: TYPE_ID_CODE_HASH,
// hash_type: type, args: <discriminator>}` that lives on the deployed code
// cell at deploy_tx:1. When consumer lock scripts use `hash_type: "type"`,
// they must set `code_hash` to this value — NOT to the type script's args.
// The on-chain `type.args` value `0xece0f0e37a3ae5029e3558102e59f34d1b47a5b2fa18c41b192cdd8d435915d7`
// is the TYPE_ID discriminator, a completely different thing.
// Per-variant code_hash (hash of the deployed cell's type script) and deploy
// cell output index. Each is keyed on the ParamId variant ordering: 44, 65, 87.
// Correct values from the 2026-04-08 testnet deploy
// tx 0xb1a05b5000cecdcb51a1518e96cb13d81a1b28cea21d861a64081430cb35ae88.
const MLDSA44_LOCK_V2_CODE_HASH: H256 =
    h256!("0x1e9798b5545214d7c6bf9a23564847b671c40f3f91536608e7c2eadf782ba237");
const MLDSA65_LOCK_V2_CODE_HASH: H256 =
    h256!("0xda3e5dc140c25b62ba0697fa83dc866e6c8e29eba4d9d91df5735bf4f06960a7");
const MLDSA87_LOCK_V2_CODE_HASH: H256 =
    h256!("0x37dc2a33c484de9b2378a07f926e78083e53a0322bc05e78681bb47510607e15");

// Falcon variants deployed 2026-04-08 session 7 (tx 0x0e15396cff81e3... at
// block 20,691,215). Same rule as the ML-DSA constants: these are SCRIPT
// HASHES (from `gen-txs` pre-broadcast output), NOT the TYPE_ID
// discriminators visible as `tx.outputs[i].type.args` post-broadcast.
const FALCON512_LOCK_V2_CODE_HASH: H256 =
    h256!("0xbf949c7980454296ca2d537471fd86b746f5fa86df50533644d10c9b06a2fbd4");
const FALCON1024_LOCK_V2_CODE_HASH: H256 =
    h256!("0xbf26aaceee7237aad36e984c04917dc0d94ee46d6a84965063509729716cfd10");

/// The 2026-04-08 deploy tx that holds the v2 cells.
const DEFAULT_DEPLOY_TX: H256 =
    h256!("0xb1a05b5000cecdcb51a1518e96cb13d81a1b28cea21d861a64081430cb35ae88");

/// The Falcon deploy tx (session 7).
const DEFAULT_FALCON_DEPLOY_TX: H256 =
    h256!("0x0e15396cff81e32b8abbcb37f9cbdce87b7edc60fc4150220c081bf85822bbc0");

/// Default tx fee in shannons. 100_000 shannons = 0.001 CKB — generous
/// headroom over the real cost of a single-input single-output v2 spend.
const DEFAULT_FEE_SHANNONS: u64 = 100_000;

/// ckb-std reports cycles in increments of roughly 10x expected for a real
/// tx; we cap at 1B for safety.
const POLL_INTERVAL_SECS: u64 = 3;
const POLL_MAX_ATTEMPTS: u32 = 30; // 30 * 3s = 90s

// ── CLI ─────────────────────────────────────────────────────────────────────

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("{}", USAGE);
        return ExitCode::from(2);
    }

    let mode = args[1].as_str();
    let mut opts = parse_opts(&args[2..]);

    let result = match mode {
        "derive-address" => cmd_derive_address(&mut opts),
        "spend" => cmd_spend(&mut opts),
        "-h" | "--help" => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        other => {
            eprintln!("unknown mode: {other}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

const USAGE: &str = "\
mldsa65_spend_test — testnet helper for ckb-mldsa-lock v2

USAGE:
    mldsa65_spend_test <MODE> [OPTIONS]

MODES:
    derive-address      Print the v2 ML-DSA-65 testnet address for a seed
    spend               Build + sign + broadcast a spend from a v2-locked cell

COMMON OPTIONS:
    --seed <hex>        32-byte hex seed (required)
    --param-id <n>      44 | 65 | 87 — which ML-DSA variant (default 65)
    --index <n>         HKDF account index (default 0)
    --rpc <url>         CKB RPC endpoint (default https://testnet.ckb.dev)
    --code-hash <hex>   v2 lock code_hash (default: baked in for --param-id)

SPEND-ONLY OPTIONS:
    --input-tx <hash>:<index>   v2-locked cell to spend (required)
    --to <hex>                  destination lock_arg (32+ hex chars); uses the
                                same code_hash/hash_type as --recipient-code-hash
    --recipient-code-hash <hex> lock code_hash for the recipient (default:
                                secp256k1_blake160_sighash_all mainnet type_id)
    --recipient-hash-type <t>   type|data|data1 (default: type)
    --deploy-tx <hash>          mldsa65 code cell dep tx (default: baked in)
    --deploy-idx <n>            mldsa65 code cell dep output index (default: 1)
    --fee <shannons>            tx fee in shannons (default: 100000 = 0.001 CKB)
";

#[derive(Default)]
struct Opts {
    seed: Option<String>,
    index: u32,
    rpc: String,
    param_id: String,
    code_hash: Option<String>,
    deploy_tx: Option<String>,
    deploy_idx: Option<u32>,
    input_tx: Option<String>,
    to: Option<String>,
    to_capacity_ckb: Option<u64>,
    recipient_code_hash: String,
    recipient_hash_type: String,
    fee: u64,
}

fn parse_opts(args: &[String]) -> Opts {
    let mut o = Opts {
        index: 0,
        rpc: DEFAULT_RPC.to_string(),
        param_id: "65".to_string(),
        code_hash: None,
        deploy_tx: None,
        deploy_idx: None,
        // secp256k1_blake160_sighash_all type_id on both testnet and mainnet
        recipient_code_hash:
            "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8".to_string(),
        recipient_hash_type: "type".to_string(),
        fee: DEFAULT_FEE_SHANNONS,
        ..Default::default()
    };
    let mut i = 0;
    while i < args.len() {
        let k = args[i].as_str();
        let next = || args.get(i + 1).cloned();
        match k {
            "--seed" => {
                o.seed = next();
                i += 2;
            }
            "--index" => {
                o.index = next().and_then(|v| v.parse().ok()).unwrap_or(0);
                i += 2;
            }
            "--rpc" => {
                o.rpc = next().unwrap_or_default();
                i += 2;
            }
            "--param-id" => {
                o.param_id = next().unwrap_or_default();
                i += 2;
            }
            "--code-hash" => {
                o.code_hash = next();
                i += 2;
            }
            "--deploy-tx" => {
                o.deploy_tx = next();
                i += 2;
            }
            "--deploy-idx" => {
                o.deploy_idx = next().and_then(|v| v.parse().ok());
                i += 2;
            }
            "--input-tx" => {
                o.input_tx = next();
                i += 2;
            }
            "--to" => {
                o.to = next();
                i += 2;
            }
            "--to-capacity" => {
                o.to_capacity_ckb = next().and_then(|v| v.parse().ok());
                i += 2;
            }
            "--recipient-code-hash" => {
                o.recipient_code_hash = next().unwrap_or_default();
                i += 2;
            }
            "--recipient-hash-type" => {
                o.recipient_hash_type = next().unwrap_or_default();
                i += 2;
            }
            "--fee" => {
                o.fee = next().and_then(|v| v.parse().ok()).unwrap_or(DEFAULT_FEE_SHANNONS);
                i += 2;
            }
            _ => {
                eprintln!("unknown option: {k}");
                i += 1;
            }
        }
    }
    o
}

// ── derive-address mode ─────────────────────────────────────────────────────

fn cmd_derive_address(opts: &mut Opts) -> Result<(), String> {
    let seed = require_seed(opts)?;
    let param_id = parse_param_id(&opts.param_id)?;
    let code_hash_str = resolve_code_hash(opts, param_id);
    let code_hash = parse_h256(&code_hash_str, "--code-hash")?;

    let (_pk_bytes, lock_args) = if is_falcon(param_id) {
        ckb_fips204_utils::falcon_signing::derive_lock_args(&seed, param_id, opts.index)
            .map_err(|e| format!("falcon derive_lock_args failed: {e}"))?
    } else {
        ckb_fips204_utils::signing::derive_lock_args(&seed, param_id, opts.index)
            .map_err(|e| format!("ml-dsa derive_lock_args failed: {e}"))?
    };

    // Build the CKB address from (code_hash, hash_type=type, args=lock_args).
    let address = encode_testnet_full_address(&code_hash, HashTypeByte::Type, &lock_args);

    println!("seed:      0x{}", hex::encode(seed));
    println!("index:     {}", opts.index);
    println!("lock_args: 0x{}", hex::encode(lock_args));
    println!("code_hash: 0x{}", hex::encode(code_hash.as_bytes()));
    println!("address:   {address}");
    println!();
    println!("fund with:");
    println!("  ckb-cli --url {} wallet transfer \\", opts.rpc);
    println!("      --from-account 0xa776bf02d19cafa3749d906cc2c9ab1cf1e80ff7 \\");
    println!("      --to-address {address} \\");
    println!("      --capacity 500 --fee-rate 1000");
    Ok(())
}

// ── spend mode ──────────────────────────────────────────────────────────────

fn cmd_spend(opts: &mut Opts) -> Result<(), String> {
    let seed = require_seed(opts)?;
    let param_id = parse_param_id(&opts.param_id)?;
    let code_hash_str = resolve_code_hash(opts, param_id);
    let code_hash = parse_h256(&code_hash_str, "--code-hash")?;
    // For Falcon variants, default the deploy tx to the Falcon deploy if
    // the caller didn't override it. ML-DSA variants default to the
    // session-4 ML-DSA deploy tx.
    let deploy_tx_str = opts
        .deploy_tx
        .clone()
        .unwrap_or_else(|| format!("{:#x}", default_deploy_tx(param_id)));
    let deploy_tx = parse_h256(&deploy_tx_str, "--deploy-tx")?;
    let deploy_idx = opts.deploy_idx.unwrap_or_else(|| default_deploy_idx(param_id));
    let input_spec = opts
        .input_tx
        .as_ref()
        .ok_or("--input-tx <hash>:<index> required")?;
    let to_args = opts.to.as_ref().ok_or("--to <hex> required")?;
    let recipient_code_hash = parse_h256(&opts.recipient_code_hash, "--recipient-code-hash")?;
    let recipient_hash_type = parse_hash_type(&opts.recipient_hash_type)?;

    // Parse "<tx_hash>:<index>"
    let (input_tx_hex, input_idx) = input_spec
        .split_once(':')
        .ok_or("--input-tx must be <hash>:<index>")?;
    let input_tx = parse_h256(input_tx_hex, "--input-tx tx_hash")?;
    let input_idx: u32 = input_idx
        .trim_start_matches("0x")
        .parse()
        .map_err(|_| format!("invalid --input-tx index: {input_idx}"))?;

    // 1. Derive the v2 keypair + lock script for the selected variant.
    let (pk_bytes, lock_args) = if is_falcon(param_id) {
        ckb_fips204_utils::falcon_signing::derive_lock_args(&seed, param_id, opts.index)
            .map_err(|e| format!("falcon derive_lock_args: {e}"))?
    } else {
        ckb_fips204_utils::signing::derive_lock_args(&seed, param_id, opts.index)
            .map_err(|e| format!("ml-dsa derive_lock_args: {e}"))?
    };
    let (pk_len, sig_len, _) = lengths(param_id);

    let v2_lock_script = Script::new_builder()
        .code_hash(Byte32::from_slice(code_hash.as_bytes()).unwrap())
        .hash_type(ScriptHashType::Type)
        .args({
            let b: ckb_types::packed::Bytes = Bytes::from(lock_args.to_vec()).pack();
            b
        })
        .build();

    eprintln!("derived v2 lock script:");
    eprintln!("  code_hash: 0x{}", hex::encode(code_hash.as_bytes()));
    eprintln!("  hash_type: type");
    eprintln!("  lock_args: 0x{}", hex::encode(lock_args));

    // 2. Fetch the input cell via RPC so we know its exact capacity and
    //    resolved (CellOutput, Bytes) for the host-side CighashAll.
    eprintln!("\nfetching input cell from {}...", opts.rpc);
    let (input_cell_output, input_cell_data, input_lock_hash) =
        rpc_fetch_cell(&opts.rpc, &input_tx, input_idx)?;
    let input_capacity_shannons: u64 = input_cell_output.capacity().unpack();
    eprintln!(
        "  capacity: {} CKB ({} shannons)",
        input_capacity_shannons as f64 / 1e8,
        input_capacity_shannons
    );
    eprintln!("  lock_hash: 0x{}", hex::encode(input_lock_hash));

    // Sanity: the fetched cell must actually be locked by our v2 script.
    let expected_lock_hash: [u8; 32] = v2_lock_script.calc_script_hash().unpack();
    if input_lock_hash != expected_lock_hash {
        return Err(format!(
            "input cell lock_hash mismatch!\n  \
             expected (from seed → v2 script): 0x{}\n  \
             actual (from RPC):                0x{}\n\
             Did you fund the right address?",
            hex::encode(expected_lock_hash),
            hex::encode(input_lock_hash)
        ));
    }

    // 3. Build the output(s).
    //
    // Without --to-capacity: single output sends (input_capacity - fee) to
    // the recipient.
    //
    // With --to-capacity <CKB>: two outputs — recipient gets the specified
    // amount, change (input - recipient - fee) goes back to the SOURCE v2
    // lock so follow-up spends from the same address are possible without
    // another faucet trip. Both outputs must individually meet the CKB min
    // capacity rule (~78 CKB for a 37-byte-args cell).
    let to_args_bytes = parse_hex_arg(to_args, "--to")?;
    let recipient_lock = Script::new_builder()
        .code_hash(Byte32::from_slice(recipient_code_hash.as_bytes()).unwrap())
        .hash_type(recipient_hash_type)
        .args({
            let b: ckb_types::packed::Bytes = Bytes::from(to_args_bytes).pack();
            b
        })
        .build();

    let (output_cells, outputs_data): (Vec<CellOutput>, Vec<ckb_types::bytes::Bytes>) =
        if let Some(to_ckb) = opts.to_capacity_ckb {
            let to_shannons = to_ckb
                .checked_mul(100_000_000)
                .ok_or("--to-capacity overflows u64")?;
            let change_shannons = input_capacity_shannons
                .checked_sub(to_shannons)
                .and_then(|v| v.checked_sub(opts.fee))
                .ok_or("input capacity < --to-capacity + fee")?;

            let recipient_cell = CellOutput::new_builder()
                .capacity(to_shannons)
                .lock(recipient_lock)
                .build();
            let change_cell = CellOutput::new_builder()
                .capacity(change_shannons)
                .lock(v2_lock_script.clone())
                .build();
            eprintln!(
                "\noutput[0]: {} CKB ({} shannons) → recipient 0x{}",
                to_shannons as f64 / 1e8,
                to_shannons,
                &to_args[..std::cmp::min(20, to_args.len())]
            );
            eprintln!(
                "output[1]: {} CKB ({} shannons) → CHANGE (same v2 lock)",
                change_shannons as f64 / 1e8,
                change_shannons
            );
            (
                vec![recipient_cell, change_cell],
                vec![Bytes::new(), Bytes::new()],
            )
        } else {
            let output_capacity = input_capacity_shannons
                .checked_sub(opts.fee)
                .ok_or("fee exceeds input capacity")?;
            let cell = CellOutput::new_builder()
                .capacity(output_capacity)
                .lock(recipient_lock)
                .build();
            eprintln!(
                "\noutput: {} CKB ({} shannons) → recipient 0x{}",
                output_capacity as f64 / 1e8,
                output_capacity,
                &to_args[..std::cmp::min(20, to_args.len())]
            );
            (vec![cell], vec![Bytes::new()])
        };
    eprintln!("fee:    {} shannons", opts.fee);

    // 4. Build the cell dep pointing at the variant's v2 code cell.
    let deploy_cell_dep = CellDep::new_builder()
        .out_point(
            OutPoint::new_builder()
                .tx_hash(Byte32::from_slice(deploy_tx.as_bytes()).unwrap())
                .index(deploy_idx)
                .build(),
        )
        .dep_type(DepType::Code)
        .build();

    // 5. Build the unsigned tx with a placeholder witness lock of the right
    //    shape (zero-filled, length 1 + pk + sig). The `lock` field is
    //    excluded from the CighashAll stream so the placeholder doesn't
    //    affect the digest; we splice the real signature in step 8.
    let input = CellInput::new_builder()
        .previous_output(
            OutPoint::new_builder()
                .tx_hash(Byte32::from_slice(input_tx.as_bytes()).unwrap())
                .index(input_idx)
                .build(),
        )
        .build();

    let placeholder_lock_bytes = vec![0u8; 1 + pk_len + sig_len];
    let placeholder_witness = WitnessArgs::new_builder()
        .lock(
            BytesOpt::new_builder()
                .set(Some(Bytes::from(placeholder_lock_bytes).pack()))
                .build(),
        )
        .build();

    let tx = TransactionBuilder::default()
        .cell_dep(deploy_cell_dep)
        .input(input)
        .outputs(output_cells)
        .outputs_data(outputs_data.into_iter().map(|b| b.pack()).collect::<Vec<_>>())
        .witness(placeholder_witness.as_bytes().pack())
        .build();

    // 6. Compute CighashAll host-side — same path as the Stage 2 round-trip.
    let resolved_inputs = vec![(input_cell_output, input_cell_data)];
    let mut cighash_all_bytes: Vec<u8> = Vec::new();
    generate_ckb_tx_message_all_host(&mut cighash_all_bytes, &tx, &resolved_inputs, &[0usize])
        .map_err(|e| format!("generate_ckb_tx_message_all_host: {e:?}"))?;
    eprintln!("\nCighashAll stream: {} bytes", cighash_all_bytes.len());

    // 7. Sign with the chosen variant — Falcon uses a separate signer
    //    because it has a different message pipeline (no FIPS-204 M')
    //    and needs hardware FP for keygen.
    let real_witness_lock_bytes = if is_falcon(param_id) {
        ckb_fips204_utils::falcon_signing::sign(&seed, param_id, opts.index, &cighash_all_bytes)
            .map_err(|e| format!("falcon sign: {e}"))?
    } else {
        ckb_fips204_utils::signing::sign(&seed, param_id, opts.index, &cighash_all_bytes)
            .map_err(|e| format!("ml-dsa sign: {e}"))?
    };
    assert_eq!(real_witness_lock_bytes.len(), 1 + pk_len + sig_len);
    assert_eq!(
        &real_witness_lock_bytes[1..1 + pk_len],
        &pk_bytes[..],
        "signer emitted different pubkey than derive_lock_args — impossible"
    );
    eprintln!("signed. witness lock: {} bytes", real_witness_lock_bytes.len());

    // 8. Splice the real signature into witnesses[0].lock.
    let signed_witness = WitnessArgs::new_builder()
        .lock(
            BytesOpt::new_builder()
                .set(Some(Bytes::from(real_witness_lock_bytes).pack()))
                .build(),
        )
        .build();
    let signed_tx = tx
        .as_advanced_builder()
        .set_witnesses(vec![signed_witness.as_bytes().pack()])
        .build();

    let tx_hash: [u8; 32] = signed_tx.hash().unpack();
    eprintln!("\nsigned tx_hash: 0x{}", hex::encode(tx_hash));

    // 9. Broadcast via RPC.
    eprintln!("broadcasting...");
    let broadcast_tx_hash = rpc_send_transaction(&opts.rpc, &signed_tx)?;
    eprintln!("  → 0x{}", hex::encode(broadcast_tx_hash));
    if broadcast_tx_hash != tx_hash {
        return Err(format!(
            "RPC returned a different tx_hash than we computed. ours: 0x{}, theirs: 0x{}",
            hex::encode(tx_hash),
            hex::encode(broadcast_tx_hash)
        ));
    }

    // 10. Poll until committed.
    eprintln!("\npolling for commit (interval {POLL_INTERVAL_SECS}s, max {POLL_MAX_ATTEMPTS} attempts)...");
    for i in 1..=POLL_MAX_ATTEMPTS {
        std::thread::sleep(std::time::Duration::from_secs(POLL_INTERVAL_SECS));
        let (status, block_number) = rpc_get_tx_status(&opts.rpc, &tx_hash)?;
        eprintln!("  [{i}/{POLL_MAX_ATTEMPTS}] status: {status}{}",
            block_number.map(|b| format!(" block={b}")).unwrap_or_default());
        if status == "committed" {
            eprintln!("\n✅ committed");
            println!("tx_hash: 0x{}", hex::encode(tx_hash));
            if let Some(b) = block_number {
                println!("block:   {b}");
            }
            return Ok(());
        }
        if status == "rejected" {
            return Err(format!("tx rejected by node (hash 0x{})", hex::encode(tx_hash)));
        }
    }
    Err(format!(
        "tx did not commit within {} seconds (hash 0x{})",
        POLL_INTERVAL_SECS * POLL_MAX_ATTEMPTS as u64,
        hex::encode(tx_hash)
    ))
}

// ── RPC helpers ─────────────────────────────────────────────────────────────

fn rpc_fetch_cell(
    rpc: &str,
    tx_hash: &H256,
    output_idx: u32,
) -> Result<(CellOutput, Bytes, [u8; 32]), String> {
    // verbosity 0x2 = full JSON transaction view (0x0 returns hex-serialized
    // bytes which we don't want; 0x1 returns status only).
    let req = serde_json::json!({
        "id": 1,
        "jsonrpc": "2.0",
        "method": "get_transaction",
        "params": [format!("{tx_hash:#x}"), "0x2"],
    });
    let resp: serde_json::Value = ureq::post(rpc)
        .send_json(req)
        .map_err(|e| format!("RPC get_transaction: {e}"))?
        .into_json()
        .map_err(|e| format!("RPC parse: {e}"))?;
    let tx = resp.get("result").and_then(|r| r.get("transaction")).cloned().ok_or_else(|| {
        format!(
            "get_transaction returned no transaction for {tx_hash:#x} — is it actually on-chain?\nfull response: {}",
            resp
        )
    })?;
    // verbosity=2 returns a TransactionView (which wraps the inner Transaction
    // plus a hash field); Transaction alone rejects the `hash` key.
    let jtx: json_types::TransactionView = serde_json::from_value(tx)
        .map_err(|e| format!("parse json transaction: {e}"))?;
    let outputs = &jtx.inner.outputs;
    let outputs_data = &jtx.inner.outputs_data;
    if output_idx as usize >= outputs.len() {
        return Err(format!(
            "output index {output_idx} out of range (tx has {} outputs)",
            outputs.len()
        ));
    }
    let output: CellOutput = outputs[output_idx as usize].clone().into();
    let data: Bytes = outputs_data[output_idx as usize].clone().into_bytes();
    let lock_hash: [u8; 32] = output.calc_lock_hash().unpack();
    Ok((output, data, lock_hash))
}

fn rpc_send_transaction(
    rpc: &str,
    tx: &ckb_types::core::TransactionView,
) -> Result<[u8; 32], String> {
    let jtx: json_types::Transaction = tx.data().into();
    let req = serde_json::json!({
        "id": 1,
        "jsonrpc": "2.0",
        "method": "send_transaction",
        "params": [jtx, "passthrough"],
    });
    let resp: serde_json::Value = ureq::post(rpc)
        .send_json(req)
        .map_err(|e| format!("RPC send_transaction: {e}"))?
        .into_json()
        .map_err(|e| format!("RPC parse: {e}"))?;
    if let Some(err) = resp.get("error") {
        return Err(format!("send_transaction error: {err}"));
    }
    let tx_hash_hex = resp
        .get("result")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("send_transaction returned no result: {resp}"))?;
    let tx_hash_hex = tx_hash_hex.trim_start_matches("0x");
    let bytes = hex::decode(tx_hash_hex).map_err(|e| format!("bad tx_hash hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("tx_hash not 32 bytes: {tx_hash_hex}"));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn rpc_get_tx_status(rpc: &str, tx_hash: &[u8; 32]) -> Result<(String, Option<u64>), String> {
    let req = serde_json::json!({
        "id": 1,
        "jsonrpc": "2.0",
        "method": "get_transaction",
        "params": [format!("0x{}", hex::encode(tx_hash))],
    });
    let resp: serde_json::Value = ureq::post(rpc)
        .send_json(req)
        .map_err(|e| format!("RPC get_transaction: {e}"))?
        .into_json()
        .map_err(|e| format!("RPC parse: {e}"))?;
    let status_obj = resp
        .get("result")
        .and_then(|r| r.get("tx_status"))
        .ok_or_else(|| format!("no tx_status in response: {resp}"))?;
    let status = status_obj
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let block_number = status_obj
        .get("block_number")
        .and_then(|v| v.as_str())
        .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok());
    Ok((status, block_number))
}

// ── address encoding (RFC 0021 full format) ─────────────────────────────────

#[derive(Copy, Clone)]
enum HashTypeByte {
    #[allow(dead_code)]
    Data = 0,
    Type = 1,
    #[allow(dead_code)]
    Data1 = 2,
    #[allow(dead_code)]
    Data2 = 4,
}

fn encode_testnet_full_address(code_hash: &H256, hash_type: HashTypeByte, args: &[u8]) -> String {
    // RFC 0021 full format:
    //   format = 0x00
    //   payload = format || code_hash(32) || hash_type(1) || args
    //   bech32m(hrp="ckt", payload)
    let mut payload = Vec::with_capacity(1 + 32 + 1 + args.len());
    payload.push(0x00); // format type: full
    payload.extend_from_slice(code_hash.as_bytes());
    payload.push(hash_type as u8);
    payload.extend_from_slice(args);

    let hrp = bech32::Hrp::parse("ckt").expect("valid hrp");
    bech32::encode::<bech32::Bech32m>(hrp, &payload).expect("bech32 encode")
}

// ── small helpers ───────────────────────────────────────────────────────────

fn require_seed(opts: &Opts) -> Result<[u8; 32], String> {
    let seed_hex = opts.seed.as_ref().ok_or("--seed <hex> required (64 hex chars)")?;
    let seed_hex = seed_hex.trim_start_matches("0x");
    let bytes = hex::decode(seed_hex).map_err(|e| format!("invalid --seed hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("--seed must be 32 bytes (64 hex), got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_h256(s: &str, field: &str) -> Result<H256, String> {
    let s = s.trim_start_matches("0x");
    let bytes = hex::decode(s).map_err(|e| format!("{field}: invalid hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("{field}: expected 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out.into())
}

fn parse_hex_arg(s: &str, field: &str) -> Result<Vec<u8>, String> {
    let s = s.trim_start_matches("0x");
    hex::decode(s).map_err(|e| format!("{field}: invalid hex: {e}"))
}

fn parse_param_id(s: &str) -> Result<ParamId, String> {
    match s {
        "44" => Ok(ParamId::Mldsa44),
        "65" => Ok(ParamId::Mldsa65),
        "87" => Ok(ParamId::Mldsa87),
        "falcon512" | "f512" | "512" => Ok(ParamId::Falcon512),
        "falcon1024" | "f1024" | "1024" => Ok(ParamId::Falcon1024),
        other => Err(format!(
            "--param-id must be 44, 65, 87, falcon512, or falcon1024 (got {other})"
        )),
    }
}

fn resolve_code_hash(opts: &Opts, param_id: ParamId) -> String {
    if let Some(explicit) = &opts.code_hash {
        return explicit.clone();
    }
    match param_id {
        ParamId::Mldsa44 => format!("{MLDSA44_LOCK_V2_CODE_HASH:#x}"),
        ParamId::Mldsa65 => format!("{MLDSA65_LOCK_V2_CODE_HASH:#x}"),
        ParamId::Mldsa87 => format!("{MLDSA87_LOCK_V2_CODE_HASH:#x}"),
        ParamId::Falcon512 => format!("{FALCON512_LOCK_V2_CODE_HASH:#x}"),
        ParamId::Falcon1024 => format!("{FALCON1024_LOCK_V2_CODE_HASH:#x}"),
    }
}

/// Per-variant default deploy cell output index + deploy tx.
///
/// ML-DSA variants are in tx b1a05b50 (session 4): 44@0, 65@1, 87@2.
/// Falcon variants are in tx 0e15396c (session 7): 512@0, 1024@1.
fn default_deploy_idx(param_id: ParamId) -> u32 {
    match param_id {
        ParamId::Mldsa44 => 0,
        ParamId::Mldsa65 => 1,
        ParamId::Mldsa87 => 2,
        ParamId::Falcon512 => 0,
        ParamId::Falcon1024 => 1,
    }
}

/// Per-variant default deploy tx hash. Falcon variants live in a different
/// deploy tx than the ML-DSA variants.
fn default_deploy_tx(param_id: ParamId) -> H256 {
    match param_id {
        ParamId::Mldsa44 | ParamId::Mldsa65 | ParamId::Mldsa87 => DEFAULT_DEPLOY_TX,
        ParamId::Falcon512 | ParamId::Falcon1024 => DEFAULT_FALCON_DEPLOY_TX,
    }
}

fn parse_hash_type(s: &str) -> Result<ScriptHashType, String> {
    match s {
        "type" => Ok(ScriptHashType::Type),
        "data" => Ok(ScriptHashType::Data),
        "data1" => Ok(ScriptHashType::Data1),
        "data2" => Ok(ScriptHashType::Data2),
        other => Err(format!("unknown hash type: {other}")),
    }
}
