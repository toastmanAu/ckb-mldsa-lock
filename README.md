# ckb-mldsa-lock

A post-quantum lock script for [CKB (Nervos Network)](https://nervos.org) based on **ML-DSA-65** (NIST FIPS 204, formerly CRYSTALS-Dilithium). Protects cells with a quantum-resistant digital signature.

> **Testnet only** — not audited for mainnet use. See [security notes](#security-notes).

## Overview

`mldsa-lock` is a CKB lock script that replaces ECDSA (secp256k1) with ML-DSA-65, a lattice-based signature scheme standardised by NIST in FIPS 204. It is believed to be secure against both classical and quantum adversaries.

### How it works

1. **Cell creation**: derive a 36-byte lock args from your public key and use them as the script args
2. **Cell spending**: sign the transaction hash and attach the signature + public key as a witness
3. **On-chain verification**: the lock script verifies the ML-DSA-65 signature against the stored pubkey hash

```
Lock args (36 bytes):
  [0]    version   = 0x01
  [1]    algo_id   = 0x02  (ML-DSA)
  [2]    param_id  = 0x02  (ML-DSA-65)
  [3]    reserved  = 0x00
  [4-35] blake2b_256(public_key)

Signing digest:
  msg = blake2b_256("CKB-MLDSA-LOCK" || tx_hash)
  ctx = "CKB-MLDSA-LOCK"
```

## Testnet Deployment

| Field | Value |
|---|---|
| **type_id** (stable) | `0x8984f4230ded4ac1f5efee2b67fef45fcda08bd6344c133a2f378e2f469d310d` |
| **data_hash** | `0x7dcb281583da642016be3a0a4a4d7d4c4d573df2ae10cd4fb4d1616d74007725` |
| **deploy tx** | `0xba4a6560ef719b24d170bf678611b25b799c56e6a80f18ce9c79e9561085cba7` |
| **index** | `0` |
| **hash_type** | `type` (recommended — survives upgrades) |
| **cycles** | ~4.76M |

## Repository Structure

```
ckb-mldsa-lock/
├── contracts/mldsa-lock/   Lock script (C, RISC-V rv64imc)
│   ├── src/                entry.c, mldsa_adapter.c, startup.S, sys.c
│   ├── tests/              gen_test_vector.c, ckb-debugger test harness
│   └── vendor/             mldsa-native (portable C, FIPS 204)
├── crates/
│   ├── sdk-rust/           Rust SDK (ckb-mldsa-sdk)
│   └── molecule-types/     Shared Molecule serialization
├── sdk/js/                 TypeScript/JS SDK (@ckb-mldsa/sdk)
└── deploy/                 Deployment config and migration records
```

## SDKs

### Rust

```toml
[dependencies]
ckb-mldsa-sdk = { git = "https://github.com/toastmanAu/ckb-mldsa-lock" }
```

```rust
use ckb_mldsa_sdk::{MldsaKeyPair, testnet};

// Generate key pair
let kp = MldsaKeyPair::generate();

// Lock args to use when creating a cell
let lock_args = kp.lock_args(); // [u8; 36]

// Build the lock script
// Script {
//   code_hash: testnet::CODE_HASH_TYPE_ID,
//   hash_type: "type",
//   args: hex::encode(lock_args),
// }

// When spending — sign and build witness
let tx_hash: [u8; 32] = /* from CKB RPC */;
let witness = kp.sign_witness(&tx_hash); // Vec<u8> — set as witnesses[0]
```

### JavaScript / TypeScript

```bash
npm install @ckb-mldsa/sdk
```

```typescript
import { MldsaKeyPair, toHex, TESTNET } from '@ckb-mldsa/sdk';

// Generate key pair
const kp = MldsaKeyPair.generate();

// Lock args for cell creation
const lockArgs = toHex(kp.lockArgs()); // "0x01020200..."

// Lock script
const lockScript = {
  codeHash: TESTNET.CODE_HASH_TYPE_ID,
  hashType: 'type',
  args: lockArgs,
};

// When spending — build witness
const txHash = new Uint8Array(32); // from CKB RPC
const witness = toHex(kp.signWitness(txHash));
```

## Building the Contract

**Prerequisites**: `riscv64-unknown-elf-gcc`, `ckb-debugger`

```bash
cd contracts/mldsa-lock

# Fetch dependencies
make deps

# Build
make

# Run tests (generates mock tx and verifies with ckb-debugger)
cd tests
gcc -O2 -I../vendor/mldsa-native/mldsa -I../vendor/mldsa-native/mldsa/src \
    -DMLD_CONFIG_PARAMETER_SET=65 -DMLDSA_RANDOMIZED_SIGNING=0 \
    gen_test_vector.c ../vendor/mldsa-native/mldsa/mldsa_native.c -o gen_test_vector

./gen_test_vector > mock_tx.json
ckb-debugger --mode fast --tx-file mock_tx.json \
    --script-group-type lock --cell-index 0 --cell-type input
# Run result: 0  ✓

./gen_test_vector --fail > mock_tx_fail.json
ckb-debugger --mode fast --tx-file mock_tx_fail.json \
    --script-group-type lock --cell-index 0 --cell-type input
# Run result: 7  ✓ (ERROR_INVALID_SIGNATURE)
```

## Running the SDKs

```bash
# Rust
cargo test

# TypeScript
cd sdk/js
npm install
npm test
```

## Contract Architecture

The lock script is a single C compilation unit targeting RISC-V rv64imc (CKB-VM).

**Verification flow:**

```
1. Load script args (36 bytes) → validate version/algo/param, extract pubkey_hash
2. Load witness[0] as WitnessArgs → extract lock field
3. Parse MldsaWitness → pubkey (1952B) + signature (3309B)
4. Verify pubkey hash: blake2b(pubkey) == pubkey_hash  [constant-time]
5. Build signing digest: blake2b("CKB-MLDSA-LOCK" || tx_hash)
6. Verify ML-DSA-65 signature
```

**Error codes:**

| Code | Meaning |
|------|---------|
| 5 | `ERROR_ARGS_LEN` — wrong script args length |
| 6 | `ERROR_INVALID_VERSION` |
| 7 | `ERROR_INVALID_SIGNATURE` |
| 8 | `ERROR_WITNESS_MALFORMED` |
| 9 | `ERROR_PUBKEY_HASH_MISMATCH` |
| 10 | `ERROR_MESSAGE_BUILD` |
| 11 | `ERROR_INVALID_ALGO` |
| 12 | `ERROR_INVALID_PARAM` |

**Key sizes (ML-DSA-65):**

| | Bytes |
|---|---|
| Public key | 1952 |
| Secret key | 4032 |
| Signature | 3309 |
| WitnessArgs total | 5337 |

## Security Notes

- **Testnet only** — not audited. Use at your own risk.
- **Sighash coverage**: the signing digest covers `tx_hash` only, not all witnesses. Safe for testnet (tx_hash is unique per transaction) but does not implement full RFC-0024 sighash-all. Will be fixed before any mainnet deployment.
- **Key storage**: ML-DSA secret keys are 4032 bytes. Store them securely (HSM, encrypted keystore, etc.).
- The contract uses constant-time comparison for the pubkey hash check (no timing oracle).

## Acknowledgements

- [mldsa-native](https://github.com/pq-crystals/dilithium) — portable C ML-DSA implementation
- [ckb-c-stdlib](https://github.com/nervosnetwork/ckb-c-stdlib) — CKB system call headers
- [fips204](https://crates.io/crates/fips204) — pure Rust FIPS 204 ML-DSA
- [@noble/post-quantum](https://github.com/paulmillr/noble-post-quantum) — audited TypeScript ML-DSA

## License

MIT
