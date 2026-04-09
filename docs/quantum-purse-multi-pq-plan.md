# Quantum Purse — Multi-PQ Wallet Integration Plan

**Target**: land all 5 post-quantum lock variants (mldsa44/65/87 × fips204+ml-dsa backends, falcon512/1024) inside the Quantum Purse wallet, following the scheme-threading pattern already established on the `feat/mldsa65` branch.

**Authored**: 2026-04-10, after session 9 of ckb-mldsa-lock (all 5 locks deployed + smoke-spent on testnet under tx `0x39b1c11e...a45cf1f1`).

**Audience**: future-Phill, starting cold tomorrow.

---

## tl;dr — where things stand

- **`toastmanAu/quantum-purse` fork, branch `feat/mldsa65`** is 20 commits ahead of main and has the **entire scheme-awareness scaffold already done** — it threads a `sigScheme: "sphincs+" | "mldsa65"` tagged union through `wallet.ts`, `qp_signer.ts`, `quantum_purse.ts`, the redux store, the routing, AND has parallel `CreateWalletMlDsa.tsx` / `ImportWalletMlDsa.tsx` pages. **Do not start from scratch.** This is the foundation; build on it.

- **BUT that branch is wired to the DEPRECATED v1 C lock** (`MLDSA_LOCK.codeHash = 0x8984f4230d...`, deploy tx `0xba4a6560...`). It has the HIGH-1 sighash coverage gap the README warned about — it signs `tx_hash` instead of the full CighashAll stream. **This is why nothing will work end-to-end against our session-9 v2 locks until the signing path is rewired.**

- **`feat/mldsa65-cighash` branch of key-vault-wasm** has all the crate-level plumbing for ML-DSA {44,65,87} + Falcon {512,1024} already done (see session-9 audit in this same `docs/` folder if preserved, or re-derive from that branch's commit history). What it **doesn't** have: (a) the RustCrypto `ml-dsa` backend path for `mldsa-lock-v2-rust`, (b) variant-parameterised WASM exports for the new locks, (c) any Falcon WASM exports at all.

- **Key architectural insight from the `feat/mldsa65` branch**: the wallet uses **parallel flows**, not a unified variant-picker form. Each PQ scheme family gets its own `CreateWallet<Family>.tsx` + `ImportWallet<Family>.tsx` + its own route. This means adding a new family is mostly file-copying, not refactoring.

---

## Tomorrow's work, in dependency order

**Critical insight**: you have two workstreams that gate each other. Workstream A is a migration (fix what exists); B is additive (add the rest). **A must complete before B is worth starting.**

---

## Workstream A — Migrate `feat/mldsa65` from v1 C lock to v2 locks

**Goal**: the existing mldsa65 UX on the branch produces a valid on-chain spend against `mldsa65-lock-v2` (fips204) OR `mldsa65-lock-v2-rust` (ml-dsa crate). No visible wallet UX change; just rewire the plumbing beneath the scheme-aware scaffold that's already in place.

**Start by branching:** `feat/mldsa65` → `feat/mldsa65-v2-migration` on the quantum-purse fork, and `feat/mldsa65-cighash` → `feat/multi-pq-family` on key-vault-wasm.

### A1. key-vault-wasm: expose a CighashAll-capable `sign_ml_dsa`

**Files**: `/home/phill/code/key-vault-wasm/src/lib.rs` + `Cargo.toml`.

The current WASM `sign_ml_dsa` (on `feat/mldsa65-cighash`) takes a raw `tx_hash` and the on-chain v1 C lock's verify logic covers only `tx_hash`. The v2 locks require the full CighashAll byte stream fed through a personalised blake2b. Reference implementation: `tests/integration/src/bin/mldsa65_spend_test.rs:447-570` in the ckb-mldsa-lock repo — specifically the `generate_ckb_tx_message_all_host` call followed by `Hasher::message_hasher()` digest. You can also see the TS wallet-side equivalent pattern in `wallet/src/core/utils.ts` (`get_ckb_tx_message_all_hash`, used for SPHINCS+ already) — we want the MLDSA hasher'd variant.

**Changes**:
1. Add `hkdf = "0.12"`, `sha2 = "0.10"`, and `ml-dsa = { git = "https://github.com/RustCrypto/signatures", rev = "66473ec" }` to `Cargo.toml` `[dependencies]`. Same pins as the lock contract (`contracts/mldsa-lock-v2-rust/Cargo.toml`).
2. In `src/lib.rs`, parameterise `sign_ml_dsa` to take `(password, lock_args, cighash_all_bytes, variant: MldsaVariant, backend: MldsaBackend)`.
3. Add two variant / backend enums exposed to wasm-bindgen:
   ```rust
   #[wasm_bindgen]
   pub enum MldsaVariant { Mldsa44 = 0, Mldsa65 = 1, Mldsa87 = 2 }

   #[wasm_bindgen]
   pub enum MldsaBackend { Fips204 = 0, MlDsa = 1 }
   ```
4. Internal dispatch:
   - `Backend::Fips204` → existing `ckb_fips204_utils::signing::sign` (already variant-generic per session-9 audit)
   - `Backend::MlDsa` → **copy `sign_mldsa_rust` verbatim from `ckb-mldsa-lock/tests/integration/src/bin/mldsa65_spend_test.rs` lines ~820-1000**. It's already tested end-to-end on all 3 variants via tonight's on-chain smoke spends.
5. The old `sign_ml_dsa` signature (takes `tx_hash`) can be removed entirely — no back-compat needed since there are no v1 cells held by users on this key (the wallet is testnet-only and the fork branch hasn't shipped to real users).
6. Add variant-parameterised `get_all_ml_dsa_lock_args(variant)`, `gen_ml_dsa_account(password, variant, backend)`, etc. following the same pattern.

**Test checkpoint**: before touching quantum-purse, write a Rust unit test inside key-vault-wasm that feeds a deterministic seed + a canned CighashAll stream through the new `sign_ml_dsa` and asserts the witness bytes match what `mldsa65_spend_test` produces in the lock repo for the same inputs. If they diverge, you have a bug in the port.

### A2. quantum-purse: update `config.ts` to session-9 code_hashes

**File**: `src/core/config.ts`

Replace the `MLDSA_LOCK` constant. The existing value is the v1 C lock (deprecated).

```ts
// Pick ONE of these as the default mldsa65 lock during migration.
// Recommendation: start with mldsa65-lock-v2-rust since it's ~45% faster
// and tonight's on-chain spend proved the signing path works end-to-end.

// Session-9 deploy tx holds all 8 cells. Output index map:
//   0 mldsa44-lock-v2         (fips204)
//   1 mldsa65-lock-v2         (fips204)
//   2 mldsa87-lock-v2         (fips204)
//   3 falcon512-lock-v2       (upgraded binary)
//   4 falcon1024-lock-v2      (upgraded binary)
//   5 mldsa44-lock-v2-rust    (NEW, RustCrypto ml-dsa)
//   6 mldsa65-lock-v2-rust    (NEW, RustCrypto ml-dsa)
//   7 mldsa87-lock-v2-rust    (NEW, RustCrypto ml-dsa)
const SESSION9_DEPLOY_TX =
  "0x39b1c11ed7ca2e4a0491c69d105ee07e5659e88109661d4b48f2ff39a45cf1f1";

// The single mldsa65 constant used by the existing branch code —
// point it at the RustCrypto backend by default.
export const MLDSA_LOCK = IS_MAIN_NET
  ? { /* TODO mainnet */ }
  : {
      codeHash: "0xd70653f7fd51e173ec506b76081f37bf4acebb8a15dc79e6d4ad43ca4d3b78a4",
      hashType: "type" as const,
      outPoint: { txHash: SESSION9_DEPLOY_TX, index: "0x6" },
      depType: "code" as const,
    };
```

In the same file, land the full 8-lock constants table up front even though only `MLDSA_LOCK` is referenced today — it's the lookup table Workstream B needs:

```ts
export const MLDSA_LOCKS_TESTNET = {
  mldsa44_fips204:  { codeHash: "0x1e9798b5545214d7c6bf9a23564847b671c40f3f91536608e7c2eadf782ba237", txHash: SESSION9_DEPLOY_TX, index: "0x0" },
  mldsa65_fips204:  { codeHash: "0xda3e5dc140c25b62ba0697fa83dc866e6c8e29eba4d9d91df5735bf4f06960a7", txHash: SESSION9_DEPLOY_TX, index: "0x1" },
  mldsa87_fips204:  { codeHash: "0x37dc2a33c484de9b2378a07f926e78083e53a0322bc05e78681bb47510607e15", txHash: SESSION9_DEPLOY_TX, index: "0x2" },
  mldsa44_rust:     { codeHash: "0x52acc41edd9218617e164555d99d2830292754c79370b61bee4e5f0e89d34756", txHash: SESSION9_DEPLOY_TX, index: "0x5" },
  mldsa65_rust:     { codeHash: "0xd70653f7fd51e173ec506b76081f37bf4acebb8a15dc79e6d4ad43ca4d3b78a4", txHash: SESSION9_DEPLOY_TX, index: "0x6" },
  mldsa87_rust:     { codeHash: "0x70021f94a11de672edd16bdb2f577cb2178cd8581080c951513e8650cfca033c", txHash: SESSION9_DEPLOY_TX, index: "0x7" },
} as const;

export const FALCON_LOCKS_TESTNET = {
  falcon512:   { codeHash: "0xbf949c7980454296ca2d537471fd86b746f5fa86df50533644d10c9b06a2fbd4", txHash: SESSION9_DEPLOY_TX, index: "0x3" },
  falcon1024:  { codeHash: "0xbf26aaceee7237aad36e984c04917dc0d94ee46d6a84965063509729716cfd10", txHash: SESSION9_DEPLOY_TX, index: "0x4" },
} as const;
```

### A3. quantum-purse: rewire `qp_signer.ts` to feed CighashAll, not tx_hash

**File**: `src/core/ccc-adapter/qp_signer.ts`

The current mldsa65 signing branch (lines ~205-220 on `feat/mldsa65`) looks like:

```ts
// CURRENT (broken against v2 locks):
const txHashBytes = new Uint8Array(bytesFrom(tx.hash()));
const mldsaWitness = await this.keyVault.sign_ml_dsa(
  password,
  this.accountPointer as string,
  txHashBytes
);
```

**Replace with**:

```ts
// TARGET:
const cighashAllBytes = get_ckb_tx_message_all_bytes(tx); // NOT the hashed output — the raw stream
const mldsaWitness = await this.keyVault.sign_ml_dsa(
  password,
  this.accountPointer as string,
  cighashAllBytes,
  MldsaVariant.Mldsa65,  // from the WASM enum in A1
  MldsaBackend.MlDsa,    // default to the fast RustCrypto backend
);
```

Note the function name change: the existing `get_ckb_tx_message_all_hash` helper (used by the SPHINCS+ branch) returns the **hashed** 32-byte output. The ML-DSA path needs the **raw bytes** fed into our personalised blake2b inside the WASM. Either:
- Add a new helper `get_ckb_tx_message_all_bytes(tx): Uint8Array` in `src/core/utils.ts`, OR
- Change the WASM `sign_ml_dsa` to also accept the already-hashed 32 bytes and hash internally with the right personalisation (less robust — easier to miss the personalisation step).

Recommendation: the former. Split the existing helper into a `build` step (produces bytes) and a `hash` step (wraps in blake2b). SPHINCS+ continues to use `build → hash`; ML-DSA uses `build` only and lets the WASM do its own personalised hashing.

### A4. quantum-purse: fix `MLDSA65_WITNESS_LOCK_SIZE`

**File**: `src/core/ccc-adapter/qp_signer.ts` line ~28.

Current value: `5305` (v1 C lock's Molecule-wrapped witness). v2 witness is `1 + pk_len + sig_len` raw bytes:

```ts
const V2_WITNESS_LOCK_SIZE: Record<string, number> = {
  mldsa44: 3733,   // 1 + 1312 + 2420
  mldsa65: 5262,   // 1 + 1952 + 3309
  mldsa87: 7220,   // 1 + 2592 + 4627
};
```

Update `prepareTransaction` to pick from this table based on the account's variant.

### A5. quantum-purse: `quantum_purse.ts` `fetchMlDsaCellDeps` → session-9 tx

**File**: `src/core/quantum_purse.ts`

There's almost certainly a method on the `QuantumPurse` singleton that hits RPC at startup to pre-fetch the ML-DSA cell_dep (graph node `fetchMlDsaCellDeps` or similar, brought in by commit `5e939722`). Update the hardcoded tx_hash + output index to the session-9 values from `MLDSA_LOCKS_TESTNET.mldsa65_rust` in `config.ts`.

### A6. Test against testnet

1. Build the new key-vault-wasm dist (`wasm-pack build --target web --out-dir pkg`). Vendor it into the wallet via the `18ccd329` workaround if CI needs it.
2. Run the wallet locally, import an existing mldsa65 SRP, try `Send` with any amount. Watch the RPC log — the spend should commit under `mldsa65-lock-v2-rust` code_hash `0xd70653f7...`.
3. If it fails, compare the CighashAll bytes emitted by the wallet against the bytes `mldsa65_spend_test` produces for the same tx shape. They should be byte-identical. If not, look at input cell resolution — the wallet has to fetch the input cells the same way the helper does.

**A is done when**: you can create a new mldsa65 account in the wallet, fund it from the session-9 deploy wallet, send CKB from it, and see the spend tx on the testnet explorer. No new UX, just working v2 plumbing.

---

## Workstream B — Add the rest of the variants

Now that the signing path is modernised and the code_hash table is in place, **adding each additional variant is mostly mechanical file-copying**, following the pattern the existing branch established.

### B1. Extend the `SigScheme` union

**Files**: `src/ui/store/models/interface.ts`, `src/ui/store/models/wallet.ts`, `src/core/ccc-adapter/qp_signer.ts`, `src/core/quantum_purse.ts`.

```ts
// interface.ts — BEFORE:
export type SigScheme = "sphincs+" | "mldsa65";

// AFTER:
export type SigScheme =
  | "sphincs+"
  | "mldsa44" | "mldsa65" | "mldsa87"        // fips204 backend
  | "mldsa44-rust" | "mldsa65-rust" | "mldsa87-rust"  // RustCrypto ml-dsa backend
  | "falcon512" | "falcon1024";
```

Every `if (sigScheme === "mldsa65")` branch in `qp_signer.ts` / `wallet.ts` / `quantum_purse.ts` becomes a `switch` over a helper:

```ts
function schemeFamily(s: SigScheme): "sphincs" | "mldsa" | "falcon" {
  if (s === "sphincs+") return "sphincs";
  if (s.startsWith("mldsa")) return "mldsa";
  return "falcon";
}
```

Then per-site: `switch (schemeFamily(scheme)) { case "mldsa": ... }`. All existing code paths for `"mldsa65"` stay correct (they fall into the `mldsa` family).

### B2. Add mldsa44 / mldsa87 variants to the mldsa flow (TRIVIAL)

Smallest change of all: `CreateWalletMlDsa.tsx` already exists. Commit `96652a08` on the branch explicitly *removed* the variant picker from this page with the rationale "use fixed internal default". Revert that: add a small dropdown (44 / 65 / 87) and thread the variant through `genMlDsa65Account()` (rename to `genMlDsaAccount(variant)`).

Same for `ImportWalletMlDsa.tsx`.

Update `QuantumPurse.genMlDsaAccount()` to accept a variant parameter and pass it into the WASM `gen_ml_dsa_account(password, variant, backend)` from A1.

### B3. Add the ml-dsa-rust backend toggle

In `CreateWalletMlDsa.tsx`: add a checkbox or segmented control alongside the variant dropdown:
- **Standardised (fips204)** — old reference-impl backend
- **Fast (ml-dsa/RustCrypto)** ← default — ~45% fewer cycles, proven on testnet

The backend choice is stored on the account record alongside the variant. At sign time, `qp_signer.ts` passes `backend` through to the WASM. The lock_args are identical across backends (we proved this in session 9), so switching backend on an existing account is actually legal — it just moves to a new address under a new code_hash.

Add a `backend: "fips204" | "ml-dsa"` field to `IAccount` (optional, default `"ml-dsa"` for new accounts).

### B4. Add Falcon as a third parallel flow

**Biggest change of the B group** because it creates a new scheme family.

1. Copy `src/ui/pages/CreateWalletMlDsa/CreateWalletMlDsa.tsx` → `src/ui/pages/CreateWalletFalcon/CreateWalletFalcon.tsx`. Swap the variant enum (falcon512 / falcon1024) and the WASM method (`gen_falcon_account`).
2. Same for `ImportWallet`.
3. Add routes in `src/ui/utils/constants.ts`:
   ```ts
   CREATE_WALLET_FALCON: "/create-wallet-falcon",
   IMPORT_WALLET_FALCON: "/import-wallet-falcon",
   ```
4. Add the falcon lock constants (see `FALCON_LOCKS_TESTNET` in A2) and a `fetchFalconCellDeps()` method on `QuantumPurse`.
5. `qp_signer.ts` gets a third signing branch (`case "falcon"`) that calls the new `keyVault.sign_falcon()` WASM method. That method needs to exist — its Rust impl is pre-baked in `ckb_fips204_utils::falcon_signing::sign` on the `feat/mldsa65-cighash` branch, you just need a WASM wrapper.
6. Witness size table (`V2_WITNESS_LOCK_SIZE`) gets two more entries:
   ```ts
   falcon512: 1564,   // 1 + 897 + 666
   falcon1024: 3074,  // 1 + 1793 + 1280
   ```
7. **UX warning**: Falcon signing requires hardware FP. It works in the browser via wasm32 but NOT on embedded targets. Add a subtle badge on the Falcon create page: "browser/desktop only — not supported on embedded wallets". Also add a "draft standard" note since FIPS 206 wasn't final at `fn-dsa` 0.3.0.
8. `Welcome.tsx` — add a third "Create Falcon wallet" button alongside the SPHINCS+ and ML-DSA options.

### B5. UI polish: scheme cascader on main wallet type picker

Commit `465cc992` introduced a **cascader** ("scheme first, then variant"). That's the right pattern for the full 3-family / ~17-option menu. Extend it with:
- SPHINCS+ → 12 variants (existing)
- ML-DSA → 3 variants × 2 backends = 6 options (or 3 variants + a backend toggle)
- Falcon → 2 variants

Put this cascader on the `Welcome.tsx` landing page AND on the `Accounts.tsx` "add account" flow.

### B6. Docs

Clone `docs/mldsa65-testing.md` (already on the branch) → per-scheme testing guides, OR merge into one `docs/multi-pq-testing.md` that covers all 5 variants × 2 backends. Include funding instructions (testnet faucet + the session-9 deploy wallet address `ckt1qyq2wa4lqtgeetarwjweqmxzex43eu0gplms445qx4`) and expected spend outputs.

---

## Suggested PR / branch structure

Off the base branch (`feat/mldsa65` on quantum-purse, `feat/mldsa65-cighash` on key-vault-wasm), land these as sequential PRs:

| # | Branch | Scope | Workstream |
|---|---|---|---|
| 1 | `feat/v2-migration` | A1 (key-vault-wasm crate changes) + A2-A6 (wallet rewire) | A |
| 2 | `feat/mldsa-all-variants` | B1 (scheme union) + B2 (44/87 variants) | B |
| 3 | `feat/mldsa-rustcrypto-backend` | B3 (backend toggle) | B |
| 4 | `feat/falcon` | B4 (new parallel flow) | B |
| 5 | `feat/ui-cascader` | B5 (polish) | B |

PR 1 is the only non-negotiable one — everything else builds on it. PRs 2-5 can land in any order or as a single consolidated PR if you prefer one review pass over the full feature.

---

## Things to verify before starting

- [ ] Confirm `/home/phill/code/key-vault-wasm` branch `feat/mldsa65-cighash` still has the commits listed in the session-9 memory file (in particular `154892b` for ML-DSA 44/65/87 support and `5cc0c1e` for Falcon support). If someone rebased or squashed them, adjust A1.
- [ ] Confirm `toastmanAu/quantum-purse` branch `feat/mldsa65` is still at `5e939722` (tip as of session 9). `gh api repos/toastmanAu/quantum-purse/branches/feat/mldsa65 --jq .commit.sha`.
- [ ] Confirm the session-9 deploy tx `0x39b1c11ed7ca2e4a0491c69d105ee07e5659e88109661d4b48f2ff39a45cf1f1` is still reachable on testnet and the 8 cells are unspent. Simple: `ckb-cli rpc get_transaction --hash 0x39b1c11e...` — status should be `committed`.
- [ ] Confirm you have the deploy wallet password for the session-9 owner (`0xa776bf02d19cafa3749d906cc2c9ab1cf1e80ff7`) — needed for any further deploys or funding operations.

## Reference — session-9 smoke spend chain (proves the on-chain contracts work)

These 5 txs are the reference implementation of "the wallet should produce output that looks like this". If the migrated wallet's sign output ever diverges from what these produced, diff the bytes.

| Variant | Spend tx | Block |
|---|---|---|
| mldsa44-lock-v2-rust | `0x46fd79bca33ea1760ac2ec2a42648c3ed606eb13eec9b3100b423869827d38f4` | 20711308 |
| mldsa65-lock-v2-rust | `0x12170078a25a20fb816b94512d6f3527aa4d9e0579bd2cef7dea2b6aef6ed3e6` | 20711313 |
| mldsa87-lock-v2-rust | `0xa8df06e16b6802210f8d07a0f4a23da771037931b55c1ded616671ecd97a638d` | 20711318 |
| falcon512-lock-v2 | `0x94c2c05b8b5034f0dd79f2fbe81f5b01499411a6890d678f8b962375d034c2c5` | 20711322 |
| falcon1024-lock-v2 | `0x7b88abf9a3185435967132af1fb4d4cf269be660a20a86b168da365520a569c1` | 20711327 |

The source helper that produced them lives at `tests/integration/src/bin/mldsa65_spend_test.rs` on `main` of this repo. Its `sign_mldsa_rust` function (lines ~820-1000) is the canonical reference for A1.

## If you get stuck

Query the quantum-purse graph at `/home/phill/graphs/quantum-purse-corpus/graphify-out/graph.json` (also registered in `~/.claude/graphs.json` as `quantum-purse`, so a future Claude session will auto-route to it). The `Signing Flow`, `Key Management`, and `Falcon Plug-In Seam` hyperedges in the graph list the exact node names (and therefore file paths) that matter for each sub-task.

Good luck, tomorrow-you. 🎯
