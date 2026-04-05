# CKB ML-DSA-65 Lock Script — Benchmark Report

**Generated:** 2026-04-05 16:43 UTC
**Host:** Intel(R) Core(TM) i7-14700KF
**OS:** Linux 6.8.0-106-generic x86_64

---

## Summary

| | |
|---|---|
| **Contract cycles (pass)** | 4,761,611 (~4.8 M) |
| **Contract cycles (fail)** | 4,761,603 |
| **Binary size** | 24.4 KB (25016 bytes) |
| **Tests** | 8 Rust + 15 TypeScript |

---

## Contract Performance (CKB-VM)

Measured using `ckb-debugger --mode fast` on the deployed testnet binary.

| Scenario | Cycles | Notes |
|---|---|---|
| **Valid signature** | 4,761,611 | Full keygen→sign→verify path |
| **Invalid signature** | 4,761,603 | Fails at ML-DSA verify |

### CKB-VM Cycle Budget Context

| Limit | Cycles | Headroom |
|---|---|---|
| Single-script limit | 70,000,000 | ~14× budget remaining |
| Block limit | 3,500,000,000 | — |
| **mldsa-lock usage** | 4,761,611 | 6.8% of script limit |

---

## Contract Binary

Built for RISC-V rv64imc (CKB-VM), no stdlib, no OS.

| Section | Bytes |
|---|---|
| .text (code) | 19248 |
| .data | 16 |
| .bss | 11693 |
| **Total stripped** | 25016 (24.4 KB) |

**Comparison with secp256k1 lock script** (reference):

| Script | Binary Size | Cycles |
|---|---|---|
| secp256k1-blake160 | ~65 KB | ~1.7M |
| **mldsa-lock** | **24.4 KB** | **4.7M** |

*secp256k1 figures are approximate from public CKB toolchain benchmarks.*

---

## Rust SDK Performance

**Runtime:** rustc 1.92.0 (ded5c06cf 2025-12-08)

| Operation | Time | Notes |
|---|---|---|
| `keygen` | 147.08 µs | Generate ML-DSA-65 key pair |
| `sign_witness` | 388.13 µs | Sign tx + serialize WitnessArgs |
| `verify` | 97.951 µs | Verify signature |
| `signing_message` | 127.45 ns | blake2b("CKB-MLDSA-LOCK" ‖ tx_hash) |
| `pubkey_hash` | 1.3279 µs | blake2b(pubkey) — 1952 bytes |
| `lock_args` | 1.3333 µs | Full lock args derivation |

### Rust Tests

```
running 2 tests
test tests::witness_args_length ... ok
test tests::witness_args_header_valid ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
running 5 tests
test tests::signing_message_deterministic ... ok
test tests::lock_args_format ... ok
test tests::wrong_sig_fails ... ok
test tests::roundtrip_sign_verify ... ok
test tests::wrong_key_fails ... ok
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.03s
running 0 tests
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
running 1 test
test crates/sdk-rust/src/lib.rs - (line 8) - compile ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
```

---

## TypeScript SDK Performance

**Runtime:** Node.js v22.22.0

| Operation | Time | Notes |
|---|---|---|
| `keygen` | 1.2 ms | Generate ML-DSA-65 key pair |
| `signWitness` | 9.5 ms | Sign tx + serialize WitnessArgs |
| `verify` | 1.1 ms | Verify signature |
| `signingMessage` | 4.7 µs | blake2b("CKB-MLDSA-LOCK" ‖ tx_hash) |
| `ckbBlake2b (1952B)` | 28.9 µs | Pubkey hash |
| `lockArgs` | 29.5 µs | Full lock args derivation |

---

## Key and Witness Sizes

| Field | Bytes | Notes |
|---|---|---|
| **Public key** | 1,952 | ML-DSA-65 parameter |
| **Secret key** | 4,032 | ML-DSA-65 parameter |
| **Signature** | 3,309 | ML-DSA-65 parameter |
| **Lock args** | 36 | version(1) + algo(1) + param(1) + reserved(1) + hash(32) |
| **MldsaWitness** | 5,305 | Molecule-encoded witness |
| **WitnessArgs total** | 5,337 | WitnessArgs wrapper (32 bytes overhead) |

**Comparison with secp256k1:**

| | secp256k1-blake160 | ML-DSA-65 |
|---|---|---|
| Public key | 33 B | 1,952 B (59×) |
| Signature | 65 B | 3,309 B (51×) |
| Witness | ~100 B | 5,337 B (53×) |
| Lock args | 20 B | 36 B (1.8×) |
| Quantum-safe | ✗ | ✓ |

*The larger sizes are the fundamental cost of lattice-based post-quantum security.*

---

## Testnet Deployment

| Field | Value |
|---|---|
| **type_id** | `0x8984f4230ded4ac1f5efee2b67fef45fcda08bd6344c133a2f378e2f469d310d` |
| **data_hash** | `0x7dcb281583da642016be3a0a4a4d7d4c4d573df2ae10cd4fb4d1616d74007725` |
| **deploy tx** | `0xba4a6560ef719b24d170bf678611b25b799c56e6a80f18ce9c79e9561085cba7` |
| **Network** | CKB Testnet |
| **Block at deploy** | 20,668,507 |

---

## Security Parameters

| Parameter | Value |
|---|---|
| **Standard** | NIST FIPS 204 (ML-DSA) |
| **Instance** | ML-DSA-65 |
| **Security level** | NIST Level 3 (≈128-bit classical, ≈128-bit quantum) |
| **Hardness assumption** | Module Learning With Errors (MLWE) + Module Short Integer Solution (MSIS) |
| **Signing algorithm** | Fiat-Shamir with aborts (deterministic mode) |
| **Hash function** | SHAKE-256 (internal), Blake2b-256 (CKB digest) |

---

## Notes

- Contract compiled with `-Os` optimisation, no stdlib, no OS.
- Cycle counts are deterministic for a given input — no variance.
- Rust benchmarks use Criterion.rs (statistical, outlier-filtered).
- TypeScript benchmarks are wall-clock timing loops (20–2000 iterations).
- **Sighash coverage**: signing digest covers `tx_hash` only (safe for testnet). Full RFC-0024 sighash-all planned before mainnet.
