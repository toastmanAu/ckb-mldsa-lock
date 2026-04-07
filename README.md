# ckb-mldsa-lock — Post-Quantum Lock Scripts for CKB

Five post-quantum signature lock scripts for [CKB (Nervos Network)](https://nervos.org), all deployed and smoke-tested on testnet.

| Family | Variant | NIST level | Witness lock | CKB-VM cycles | Live on testnet |
|---|---|---|---|---|---|
| **ML-DSA** (FIPS 204) | mldsa44 | 2 | 3,733 B | (unmeasured) | ✅ |
| | mldsa65 | 3 | 5,262 B | 9.8M | ✅ |
| | mldsa87 | 5 | 7,220 B | (unmeasured) | ✅ |
| **Falcon / FN-DSA** (FIPS 206 draft) | falcon512 | 1 | **1,564 B** | **1.97M** | ✅ |
| | falcon1024 | 5 | 3,074 B | 3.01M | ✅ |

> **Testnet only.** Not audited. Do not use for real funds. The Falcon variants depend on the FIPS 206 *draft* — wire format may change before standardisation.

---

## Why this exists

[CKB's lock-script model](https://docs.nervos.org/docs/script/script-template/) lets the security logic of every cell be replaced without a hard fork. That makes it one of the few production blockchains where you can deploy a post-quantum lock today, point new wallets at it, and migrate funds to PQ-locked cells at your own pace — no consensus changes required.

This repo provides two sibling lock script families covering all the post-quantum signature schemes NIST standardised in the 2024 PQC round:

- **`mldsa-lock-v2`** — three binaries for the three ML-DSA parameter sets (44/65/87, FIPS 204)
- **`falcon-lock-v2`** — two binaries for the two Falcon parameter sets (512/1024, FIPS 206 draft)

Both families share a single supporting Rust crate (`ckb-fips204-utils` in [quantumpurse/key-vault-wasm](https://github.com/QuantumPurse/key-vault-wasm), branch `feat/mldsa65-cighash`) which provides the CighashAll streamer, message wrapping, key derivation, and a host-side signer for wallets. Verification is structurally identical across all five variants — only the verify-arm differs.

There's also a deprecated v1 C lock (`contracts/mldsa-lock/`) that was the original ML-DSA-65 deployment. It stays on testnet for historical compatibility but has a documented witness-coverage gap (HIGH-1) and is superseded by the v2 Rust binaries.

---

## Live deployment (CKB testnet)

### v2 lock scripts — use these as `code_hash` in consumer lock scripts

`hash_type: "type"` for all variants.

| Variant | code_hash |
|---|---|
| mldsa44-lock-v2 | `0x1e9798b5545214d7c6bf9a23564847b671c40f3f91536608e7c2eadf782ba237` |
| mldsa65-lock-v2 | `0xda3e5dc140c25b62ba0697fa83dc866e6c8e29eba4d9d91df5735bf4f06960a7` |
| mldsa87-lock-v2 | `0x37dc2a33c484de9b2378a07f926e78083e53a0322bc05e78681bb47510607e15` |
| falcon512-lock-v2 | `0xbf949c7980454296ca2d537471fd86b746f5fa86df50533644d10c9b06a2fbd4` |
| falcon1024-lock-v2 | `0xbf26aaceee7237aad36e984c04917dc0d94ee46d6a84965063509729716cfd10` |

**Important**: these are the SCRIPT HASHES (`Script::calc_script_hash`), not the TYPE_ID discriminators visible as `tx.outputs[i].type.args` in the deploy txs. Using the discriminators as `code_hash` produces unspendable cells.

### Deploy transactions

| Family | Deploy tx | Block | Cell deps |
|---|---|---|---|
| ML-DSA (3 variants) | `0xb1a05b5000cecdcb51a1518e96cb13d81a1b28cea21d861a64081430cb35ae88` | 20,690,678 | mldsa44 @ output 0, mldsa65 @ output 1, mldsa87 @ output 2 |
| Falcon (2 variants) | `0x0e15396cff81e32b8abbcb37f9cbdce87b7edc60fc4150220c081bf85822bbc0` | 20,691,215 | falcon512 @ output 0, falcon1024 @ output 1 |

When building a transaction that spends a v2-locked cell, add the relevant deploy tx output as a `cell_dep` with `dep_type: code`.

### First on-chain spends (proof of life)

Each variant has been signed off-chain and verified by a real testnet miner:

| Variant | Spend tx | Block |
|---|---|---|
| mldsa44 | `0x4c9d90cb8bc735d6ad67d151fb6c2d28397272a7fcf06e89c06a726ff32c40dc` | 20,690,752 |
| mldsa65 | `0x13dd23f46a029006a74877f55b51c6082a552b9c9cfb7ceec906f9f3cd6d7176` | 20,690,623 |
| mldsa87 | `0x62be8df0e64569d28c6575a3e92950ed4a62f53c1beffcc71d4ce53107509970` | 20,690,772 |
| falcon512 | `0x94c202157b8e8cf214b05005bf198d3f2267355861c080f0d35d9e44eb841079` | 20,691,270 |
| falcon1024 | `0x4713bf6e88d51a297943a98be575936e25d5487aa97d964b22eef3a4dd1313b1` | 20,691,281 |

### Legacy v1 (deprecated)

The original C lock at type_id `0x8984f4230ded4ac1f5efee2b67fef45fcda08bd6344c133a2f378e2f469d310d` (deploy tx `0xba4a6560...`, block ~20,668,800) remains on testnet but should not be used for new cells. It is ML-DSA-65 only, has a known sighash coverage gap, and is owned by a wallet whose key is no longer accessible (hence the v2 redeploy under a fresh owner).

---

## How a v2 lock script works

The on-chain verification flow is identical for all five variants — only the verify routine differs (`fips204::ml_dsa_*::verify` vs `fn_dsa_vrfy::VerifyingKey512/1024::verify`).

```
1. Load script.args (37 bytes) → validate prefix [0x80, 0x01, 0x01, 0x01, flag]
2. Unpack flag → (param_id, has_sig=false)  ← reject if has_sig
3. Load witnesses[0] as WitnessArgs → extract lock field
4. Parse lock = [flag, pubkey, signature]
   - flag must match expected_param_id, has_sig must be true
   - pubkey/signature lengths come from `lengths(param_id)` table
5. Recompute pubkey hash with personalised blake2b
   - ML-DSA: personal = b"ckb-mldsa-sct"
   - Falcon: personal = b"ckb-falcon-sct"
   Compare against script.args[5..37]  (constant-time)
6. Stream the CKB CighashAll bytes into a personalised blake2b
   - ML-DSA: personal = b"ckb-mldsa-msg" → 32-byte digest →
     wrap with FIPS-204 §5.4 M' framing (DOMAIN = b"CKB-MLDSA-LOCK")
   - Falcon: personal = b"ckb-falcon-msg" → 32-byte digest →
     fed directly with DOMAIN_NONE + HASH_ID_RAW (no M' wrapping)
7. Verify the signature against the digest
```

### Lock args (37 bytes, identical across all v2 variants)

```
[0]    0x80                       multisig header marker
[1]    0x01                       require_first_n
[2]    0x01                       threshold
[3]    0x01                       pubkey count
[4]    flag = (param_id << 1) | 0  (no embedded sig in args)
[5..37] blake2b_256(pubkey)        domain-separated personal
```

The first 5 bytes match the SPHINCS+ single-sig prefix exactly. Future unified multisig walkers can parse all PQ schemes without branching on the args header.

### Witness lock layout

```
[0]              flag = (param_id << 1) | 1   (signature present)
[1..1+pk_len]    public key
[1+pk_len..]     signature
```

| Variant | pk | sig | total witness lock |
|---|---|---|---|
| mldsa44 | 1,312 | 2,420 | 3,733 |
| mldsa65 | 1,952 | 3,309 | 5,262 |
| mldsa87 | 2,592 | 4,627 | 7,220 |
| falcon512 | 897 | 666 | 1,564 |
| falcon1024 | 1,793 | 1,280 | 3,074 |

### ParamId encoding

```rust
ParamId::Mldsa44   = 60
ParamId::Mldsa65   = 61
ParamId::Mldsa87   = 62
ParamId::Falcon512 = 63
ParamId::Falcon1024 = 64
```

Sits immediately after the SPHINCS+ range (48..=59) so a future unified multisig lock can absorb everything.

---

## Repository structure

```
ckb-mldsa-lock/
├── contracts/
│   ├── mldsa-lock/          (DEPRECATED) v1 C lock — ML-DSA-65 only
│   ├── mldsa-lock-v2/       v2 Rust contract for ML-DSA-{44,65,87}
│   │   ├── src/             lib.rs + entry.rs (shared logic)
│   │   ├── bin/             {mldsa44,mldsa65,mldsa87}.rs (6-line stubs)
│   │   ├── ckb-contract.ld  Page-aligned linker script
│   │   └── .cargo/config.toml  -C target-feature=-a (no atomics)
│   └── falcon-lock-v2/      v2 Rust contract for Falcon-{512,1024}
│       ├── src/             lib.rs + entry.rs (Falcon-specific entry)
│       └── bin/             {falcon512,falcon1024}.rs
├── crates/
│   ├── sdk-rust/            Legacy v1 SDK (ML-DSA-65 only) — kept for v1 cells
│   └── molecule-types/      Legacy v1 witness types
├── tests/integration/       ckb-testtool tests + testnet smoke-test helper
│   ├── tests/               Stage 1 + Stage 2 round-trip tests for both families
│   └── src/bin/             mldsa65_spend_test — multi-variant testnet helper
├── deploy/
│   ├── deployment.toml      Active deploy config (5 v2 cells)
│   ├── deployment-info.json Per-deploy unsigned tx + signatures (gitignored)
│   └── migrations/          Per-deploy migration records (gitignored)
├── docs/
│   ├── falcon-investigation-2026-04-08.md  Falcon crate survey + cycle analysis
│   ├── benchmark-report.md
│   └── graph-usage-records.md
└── README.md                this file
```

The supporting `ckb-fips204-utils` Rust crate lives in a sibling repo at [quantumpurse/key-vault-wasm](https://github.com/QuantumPurse/key-vault-wasm) on the `feat/mldsa65-cighash` branch.

---

## Quickstart — spend a v2-locked cell

The integration crate ships a single multi-variant helper binary, `mldsa65_spend_test`, that derives a v2 address from a seed, fetches the input cell via RPC, signs host-side, and broadcasts to the network. It supports all five variants via `--param-id`.

### Build

```bash
cd tests/integration
cargo build --release --bin mldsa65_spend_test
```

### Derive an address

```bash
./target/release/mldsa65_spend_test derive-address \
    --param-id mldsa65 \
    --seed 4200000000000000000000000000000000000000000000000000000000000042
```

`--param-id` accepts `44`, `65`, `87`, `falcon512`, or `falcon1024` (and a few aliases). The seed is a 32-byte hex string used as the HKDF master seed for the wallet-side keypair derivation. The helper prints the derived CKB testnet address and a ready-to-paste `ckb-cli wallet transfer` command for funding it from a sighash wallet.

### Spend a v2-locked cell

After funding the address (faucet, ckb-cli transfer, or another v2 spend):

```bash
./target/release/mldsa65_spend_test spend \
    --param-id falcon512 \
    --seed f512000000000000000000000000000000000000000000000000000000000012 \
    --input-tx 0x604e97e7...:0 \
    --to 0xa776bf02d19cafa3749d906cc2c9ab1cf1e80ff7
```

What this does:

1. Derives the keypair from `--seed` + `--param-id`
2. Fetches the input cell at `--input-tx` via the testnet RPC (`https://testnet.ckb.dev` by default)
3. Verifies the input cell's lock script matches the expected v2 lock
4. Builds an unsigned tx: input → output spending `(input_capacity − fee)` to the recipient (defaults to a secp256k1_blake160 sighash with the supplied lock_arg)
5. Computes CighashAll **host-side** via `generate_ckb_tx_message_all_host` (a byte-for-byte port of the on-chain streamer)
6. Signs with the appropriate signer (`signing::sign` for ML-DSA, `falcon_signing::sign` for Falcon)
7. Splices the real signature into `witnesses[0].lock`
8. POSTs `send_transaction` to the RPC
9. Polls `get_transaction` until status = `committed`

For v2-to-v2 transfers (e.g. spending an mldsa44 cell into a Falcon-locked cell), pass `--to-capacity <CKB>`, `--recipient-code-hash`, and `--recipient-hash-type type`. The helper produces a 2-output spend with the change going back to the source v2 lock.

---

## Build the contracts from source

### Prerequisites

- **Rust nightly-2025-01-01** with `rust-src` component (used for `build-std`)
- **`ckb-debugger`** v1.1.1+ for independent contract validation
- **`ckb-cli`** v2.0.0+ for testnet interaction
- For the legacy v1 C lock only: `riscv64-unknown-elf-gcc`

```bash
rustup toolchain install nightly-2025-01-01
rustup component add rust-src --toolchain nightly-2025-01-01-x86_64-unknown-linux-gnu
```

### Build the v2 contracts

```bash
# ML-DSA (44/65/87)
cd contracts/mldsa-lock-v2 && cargo build --release
ls target/riscv64imac-unknown-none-elf/release/mldsa{44,65,87}-lock-v2
# 49,904 bytes each

# Falcon (512/1024)
cd ../falcon-lock-v2 && cargo build --release
ls target/riscv64imac-unknown-none-elf/release/falcon{512,1024}-lock-v2
# 45,808 bytes each
```

Both crates target `riscv64imac-unknown-none-elf` with `-C target-feature=-a` (CKB-VM does not implement the RISC-V A-extension; including atomics produces `InvalidInstruction` traps at runtime). The linker script forces `.rodata` to a 4 KB page boundary so that no page is shared between the R-X `.text` segment and the R-only `.rodata` segment — without this CKB-VM halts with `MemWriteOnFreezedPage` during cell loading.

### Run the in-process tests

```bash
cd tests/integration
cargo test --release
```

Five tests:

- **`mldsa65_placeholder_sig_reaches_verify_and_fails`** — Stage 1 structural smoke test for the v2 mldsa65 contract
- **`mldsa65_roundtrip_sign_then_verify_tx`** — full sign→verify round-trip via ckb-testtool, includes a tx dump for ckb-debugger
- **`falcon512_roundtrip_sign_then_verify_tx`** — ditto for Falcon-512
- **`falcon1024_roundtrip_sign_then_verify_tx`** — ditto for Falcon-1024
- (mldsa44 / mldsa87 round-trips are covered by the testnet smoke spends, not the in-process suite)

### Run independent ckb-debugger validation

After running `cargo test --release`, the round-trip tests dump signed mock transactions to `/tmp/`:

```bash
ckb-debugger --tx-file /tmp/mldsa65_signed_tx.json --script input.0.lock
# Run result: 0
# All cycles: 10236259(9.8M)

ckb-debugger --tx-file /tmp/falcon512_signed_tx.json --script input.0.lock
# Run result: 0
# All cycles: 1968540(1.9M)

ckb-debugger --tx-file /tmp/falcon1024_signed_tx.json --script input.0.lock
# Run result: 0
# All cycles: 3011097(2.9M)
```

---

## Crypto choices and rationale

### Domain separation

Every blake2b hash in the pipeline uses a personalised variant so that no two computations on the same bytes can collide between layers or between schemes:

| Use | Personal |
|---|---|
| ML-DSA pubkey hash (script args) | `b"ckb-mldsa-sct"` |
| ML-DSA signing digest | `b"ckb-mldsa-msg"` |
| Falcon pubkey hash | `b"ckb-falcon-sct"` |
| Falcon signing digest | `b"ckb-falcon-msg"` |

The on-chain contracts re-compute the pubkey hash with the same personalisation when they verify a spend — any drift between the signer's `lock_args()` helper and the on-chain `Hasher::*_script_args_hasher()` would silently produce `PubkeyHashMismatch` (error code 45) at every spend. This was a real bug we caught during the v2 ML-DSA development; it's documented in the commit history and now covered by tests.

### CighashAll streamer

The signing message is *not* the bare `tx_hash`. It is a **CighashAll** stream — every input cell's full bytes, every input cell's data, the first group witness's `input_type` and `output_type` slices (lock field excluded so we can splice the signature in afterwards), and every other witness — fed incrementally into the personalised blake2b. This is the same algorithm xxuejie implemented in `xxuejie/ckb-tx-message-all-test-vector-utils` and what `ckb-fips205-utils` (SPHINCS+) uses.

The on-chain streamer lives in `ckb_fips204_utils::ckb_tx_message_all_in_ckb_vm` and uses CKB-VM syscalls. The host-side mirror lives in `ckb_fips204_utils::ckb_tx_message_all_host` (gated behind the `host-hashing` feature) and takes a `ckb-types::core::TransactionView` plus resolved input cells. Both produce byte-identical output — verified by the round-trip tests above and by the on-chain testnet spends.

### Falcon vs ML-DSA pipeline difference

Falcon does **not** use FIPS-204 §5.4 `M'` wrapping. After the personalised blake2b digest is computed, it is fed directly to `fn-dsa-vrfy::verify(sig, &DOMAIN_NONE, &HASH_ID_RAW, digest)`. Domain separation is provided entirely by the personalisation (`b"ckb-falcon-msg"`). This is one fewer step than ML-DSA and is part of why Falcon witnesses are smaller and verify faster.

### Why two crates upstream

The Rust support code for both lock families is in a single crate, **`ckb-fips204-utils`** at [quantumpurse/key-vault-wasm](https://github.com/QuantumPurse/key-vault-wasm) on branch `feat/mldsa65-cighash`. The crate name is historical (it started as a FIPS-204-only ML-DSA helper) but it now also carries Falcon support behind the optional `falcon` feature. Renaming would break the upstream PR diff so the name will stay until v0.3.

Feature flags:

| Feature | Pulls in | Targets |
|---|---|---|
| `default` | std + verifying + signing | host / wasm32 |
| `verifying` | (just the verify match arms) | any |
| `signing` | hkdf + sha2 + zeroize | std-only |
| `ckb-vm` | ckb-std + ckb-gen-types + molecule | riscv64imac no_std |
| `host-hashing` | ckb-types | std-only |
| `falcon` | fn-dsa-vrfy + fn-dsa-comm | any (no_std clean) |
| `falcon-signing` | fn-dsa-sign + fn-dsa-kgen | std + hardware FP |

The contract crates use `default-features = false, features = ["verifying", "ckb-vm"]` for ML-DSA and `+ "falcon"` for the Falcon contract. The integration test crate uses everything.

---

## Cycle and witness budget summary

| Variant | Witness lock (B) | Verify cycles | Cycle headroom (vs 70M / script) |
|---|---|---|---|
| **falcon512** | **1,564** | **1.97M** | **35×** |
| falcon1024 | 3,074 | 3.01M | 23× |
| mldsa44 | 3,733 | (estimated <8M) | >8× |
| mldsa65 | 5,262 | 9.8M | 7× |
| mldsa87 | 7,220 | (estimated <12M) | >5× |

For a single spend transaction, **Falcon-512 is the leanest PQ option** by both metrics — 3.4× smaller witness and 5× faster verify than ML-DSA-65. The trade-off is that Falcon depends on a draft standard (FIPS 206 was not final at the time `fn-dsa` v0.3 shipped). ML-DSA-44 is the leanest *standardised* option.

For multisig, the witness savings compound — every additional cosigner adds another full pk + sig pair.

---

## Investigation + design history

This repo grew through a dense session-by-session implementation. The trail is in `~/.claude/projects/-home-phill/memory/project_ckb_mldsa_lock_v2.md` (private to the original developer's machine) but the commit history is the canonical record. Notable findings:

- **Linker page-sharing bug** (`58ee39c`): CKB-VM loads ELF segments at 4 KB page granularity and freezes them as it goes. If `.rodata` shares a page with `.text`, the second LOAD's write into the now-frozen page produces `MemWriteOnFreezedPage` *before any contract code runs*. Fix: `. = ALIGN(0x1000)` before `.rodata` in the linker script.
- **A-extension codegen bug** (`58ee39c`): Target triple `riscv64imac-unknown-none-elf` allows rustc to emit RISC-V Atomic Memory Operations. CKB-VM does not implement the A extension. Fix: `-C target-feature=-a` in `.cargo/config.toml`.
- **`lock_args` hash domain mismatch** (`1d0731e` in key-vault-wasm): The `lock_args()` helper used `ckb_hash::blake2b_256` (default personal) while the on-chain contract used `Hasher::script_args_hasher()` (custom personal). Every spend would have failed with `PubkeyHashMismatch` after deploy. Fix: both sides use the same personalised hasher.
- **TYPE_ID discriminator vs script hash confusion** (`02a948a`): The value `gen-txs` prints as `type_id` in its summary IS the script hash (correct, what consumers use as `code_hash`). The value visible in `tx.outputs[i].type.args` after broadcast is the TYPE_ID *discriminator* (a different 32 bytes). Confusing them produces unspendable cells. We confused them once during development; the wrong-address cell is permanently stuck on testnet.
- **Falcon `fn-dsa-vrfy` viability** (`docs/falcon-investigation-2026-04-08.md`): Investigation found that Thomas Pornin's `fn-dsa-vrfy` 0.3.0 builds cleanly for `riscv64imac-unknown-none-elf` with our exact rustflags. Pure integer NTT verify, no FP, no `libc`, no allocator required. Other candidates (`pqcrypto-falcon`, `falcon-rs`, `falcon512_rs`) all failed at least one of those constraints.

---

## Known limitations

1. **All variants are testnet only.** Not audited. No mainnet deploy planned without an audit.
2. **Falcon depends on a draft standard.** FIPS 206 was not finalized at the time `fn-dsa` 0.3.0 shipped. Falcon key encoding may shift before v1.0 — pin the dependency.
3. **Falcon signing requires hardware double-precision FP.** Wallet-side signing works on host (x86_64, ARM64) and wasm32 (browser). It does NOT work on CKB-VM, ESP32-P4 (single-precision FP only), or any bare-metal RV32IMC / RV64IMC target. Falcon *verification* works everywhere.
4. **The v1 C lock has a sighash gap.** It only covers `tx_hash`, not all witnesses (HIGH-1). It is left deployed for historical compatibility but should not be used for new cells.
5. **No multisig walker.** The 37-byte lock args layout is multisig-compatible (the first 5 bytes match the SPHINCS+ multisig prefix exactly) but the v2 contracts only verify single-sig spends. A future multisig walker could parse all PQ schemes uniformly.
6. **The deploy wallet's password is documented in the commit messages of session 4.** This is testnet so it doesn't matter, but anyone reading the history will see how the original deploy wallet got locked out.

---

## Acknowledgements

- **[Thomas Pornin](https://github.com/pornin)** — Falcon designer and author of `fn-dsa-vrfy` / `fn-dsa-sign` / `fn-dsa-kgen` / `fn-dsa-comm`. The cleanest pure-Rust no_std PQ verifier we could find.
- **[`fips204` crate by integritychain](https://crates.io/crates/fips204)** — pure Rust ML-DSA implementation tracking FIPS 204 final.
- **[`mldsa-native` (pq-code-package)](https://github.com/pq-code-package/mldsa-native)** — portable C ML-DSA used by the deprecated v1 lock.
- **[`ckb-c-stdlib`](https://github.com/nervosnetwork/ckb-c-stdlib)** — CKB-VM syscall headers.
- **[`xxuejie/ckb-tx-message-all-test-vector-utils`](https://github.com/xxuejie/ckb-tx-message-all-test-vector-utils)** — original CighashAll algorithm.
- **[QuantumPurse / key-vault-wasm](https://github.com/QuantumPurse/key-vault-wasm)** — upstream wallet that this project's `ckb-fips204-utils` extension targets. The SPHINCS+ structure (`ckb-fips205-utils`) was the structural model for the ML-DSA crate.

---

## License

MIT
