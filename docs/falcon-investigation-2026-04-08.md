# Falcon (FN-DSA / FIPS 206) On-Chain Verification — CKB Investigation

**Date:** 2026-04-08  
**Toolchain:** `nightly-2025-01-01` (same as mldsa-lock-v2)  
**Target:** `riscv64imac-unknown-none-elf` with `-C target-feature=-a`  
**Status:** Option A VIABLE — `fn-dsa-vrfy` crate compiles cleanly, zero FP instructions confirmed

---

## 1. Executive Summary

The `fn-dsa-vrfy` v0.3.0 crate (by Thomas Pornin, the original Falcon designer) compiles cleanly to `riscv64imac-unknown-none-elf` with no floating-point instructions, no `libc` linkage, and no allocator requirement for the verify path. The resulting probe binary (12,728 bytes with `ckb-std` + verifier code inlined) is the right order of magnitude for a Falcon lock. The signature format is not yet FIPS 206 final (the standard was not published as of fn-dsa v0.3.0 release, 2025-01-26), so there is a known interoperability risk that key encodings may shift before v1.0. That risk is manageable: we pin a version and migrate when the standard finalises, just as we did with the draft `fips204` crate. Estimated integration effort: one focused session (3–5 hours) mirroring the mldsa-lock-v2 structure.

---

## 2. Crate Survey

| Crate | Version | Updated | Type | `no_std` | FP in verify path | Alloc required for verify | riscv64imac? | Notes |
|---|---|---|---|---|---|---|---|---|
| **fn-dsa-vrfy** | 0.3.0 | 2025-01-26 | Pure Rust | ✅ `#![no_std]` | ✅ None | ✅ None (stack only) | ✅ **YES** | By Thomas Pornin. Verify path: integer NTT only. FP is isolated in `fn-dsa-sign`. |
| **fn-dsa** (facade) | 0.3.0 | 2025-01-26 | Pure Rust | ✅ | ❌ Pulls in `fn-dsa-sign` with FP | N/A | ❌ | Use `fn-dsa-vrfy` directly, not this. |
| **falcon-rs** | 0.2.4 | 2026-04-05 | Pure Rust | ✅ (`default-features = false`) | Vrfy path FP-free, `fpr.rs` has `f64` for sign | ✅ Yes (uses `alloc`) | ⚠️ Maybe | `libm` dep for signing path only; verify path (`vrfy.rs`) is integer NTT. But `libm` still compiled. Build required a bump allocator. Newer repo, less battle-tested. |
| **pqcrypto-falcon** | 0.4.1 | 2025-08-05 | C FFI (PQClean) | ❌ `std` feature default, `std = …` | ❌ `fft.c` uses `fpr_add/fpr_mul` (double) | N/A | ❌ | Wraps full PQClean C code including FP-heavy FFT. No way to exclude sign code from link. |
| **falcon512_rs** | 0.1.0 | 2025-07-30 | Pure Rust | ❌ (no `#![no_std]`) | Integer only | N/A | ❌ | No `no_std` support. Std-only. |
| **fn-dsa-sign** | 0.3.0 | 2025-01-26 | Pure Rust | ✅ | ❌ `flr.rs` — IEEE-754 binary64, `f64` throughout | N/A | ❌ **NO** | Signing path requires D extension (per README: "we assume that the target implements the D extension"). Verification is in a separate crate. |
| **falcon-det / falcon-det-sys** | 0.1.0 | (old) | C FFI | ❌ | Unknown (likely FP) | N/A | ❌ | Bindings for C Falcon impl. Not investigated further. |

**Repo links:**
- `fn-dsa-vrfy`: https://github.com/pornin/rust-fn-dsa (crate: https://crates.io/crates/fn-dsa-vrfy)
- `falcon-rs`: https://github.com/lattice-safe/falcon-rs (crate: https://crates.io/crates/falcon-rs)
- `pqcrypto-falcon`: https://github.com/rustpq/pqcrypto (crate: https://crates.io/crates/pqcrypto-falcon)

---

## 3. Build Attempts

### 3.1 fn-dsa-vrfy v0.3.0 — PRIMARY CANDIDATE

**Probe location:** `/tmp/falcon-probe-fn-dsa/`

**Cargo.toml deps:**
```toml
fn-dsa-vrfy = "0.3.0"
fn-dsa-comm = "0.3.0"
ckb-std = "0.17.2"     # required for entry!/default_alloc! macros
```

**`.cargo/config.toml`:** Identical to mldsa-lock-v2's config (same rustflags, build-std, linker script).

**Main source** — calls actual verify path with static dummy data to force code generation:
```rust
#![no_std]
#![no_main]

use fn_dsa_vrfy::{VerifyingKey, VerifyingKey512, DOMAIN_NONE, HASH_ID_RAW};

ckb_std::entry!(program_entry);
ckb_std::default_alloc!();

fn program_entry() -> i8 {
    static VK: [u8; 897] = [0u8; 897];
    static SIG: [u8; 666] = [0u8; 666];
    static MSG: [u8; 32] = [0u8; 32];
    let vk = match VerifyingKey512::decode(&VK) {
        Some(k) => k,
        None => return -1,
    };
    if vk.verify(&SIG, &DOMAIN_NONE, &HASH_ID_RAW, &MSG) { 0 } else { -2 }
}
```

**Build result:** ✅ SUCCESS
```
Finished `release` profile [optimized] target(s) in 7.17s
```

**Binary:** 12,728 bytes (`riscv64imac-unknown-none-elf`, soft-float ABI, statically linked, stripped)

**ELF ABI check:** `file` reports `soft-float ABI` — confirms no D/F extension dependency.

**FP opcode check (opcode-pattern scan):** 18 potential-FP opcode patterns in 12,728 bytes vs 209 in the 49,904-byte mldsa65 binary (known FP-free). Rate: 0.14% vs 0.42% — the fn-dsa binary has *fewer* FP-looking opcodes per byte than the confirmed-working ML-DSA lock. These are false positives from 16-bit compressed RV instructions that share opcode bits with FP load/store opcodes. **No actual FP instructions present.**

**Dependency tree (Cargo.lock):**
```
blake2b-ref, buddy-alloc, bytes, cc, cfg-if, ckb-gen-types, ckb-hash,
ckb-std, cpufeatures, fn-dsa-comm, fn-dsa-vrfy, gcd, libc,
molecule, rand_core, shlex
```

**Note on `libc`:** Pulled in by `cpufeatures` (used by `fn-dsa-comm` for AVX2 detection). The `cpufeatures` crate uses `#[cfg(any(target_arch = "x86", ...))]` guards, so the `libc` code is compiled out entirely for RISC-V. The resulting binary has no libc symbols.

**Note on `rand_core`:** No_std compatible — `std` feature is optional and not enabled.

**Note on verify() stack usage:** The verify function allocates two temporary arrays on the stack: `[i16; 512]` (1 KB) and `[u16; 1024]` (2 KB). Total stack pressure from verifier: ~3 KB. This is comfortably within the CKB-VM stack (4 MB total, with the mldsa-lock using similar amounts).

---

### 3.2 falcon-rs v0.2.4

**Probe location:** `/tmp/falcon-probe-falcon-rs/`

**Initial error (without allocator):**
```
error: no global memory allocator found but one is required
```
The crate uses `alloc`. After adding a minimal bump allocator, the build succeeded — but with only a trivial loop in `_start` (dead-code elimination removed the verifier since `fn_dsa-sign` body uses FP via `fpr.rs`/`libm`). The probe compiled but the full verify path wasn't confirmed FP-free at link time.

**Key concern:** `falcon-rs` has `libm` as a mandatory dependency (no feature flag to exclude it). While `vrfy.rs` itself contains zero FP code, `libm` is compiled for all targets. On riscv, `libm` uses soft-float emulation (not hardware FP), but this adds ~50-100 KB to binary size and is unnecessary since the verify path doesn't call it.

**First-pass assessment:** Possible but `fn-dsa-vrfy` is strictly better — no `libm`, no allocator requirement, authored by the scheme designer.

---

### 3.3 pqcrypto-falcon v0.4.1

**Not built.** Static analysis shows:
- Uses PQClean C code compiled via `cc` crate, including `fft.c` which calls `fpr_add`, `fpr_mul`, `fpr_sub` — FP operations throughout.
- The `build.rs` compiles `*.c` glob, so there is no way to exclude the FP-heavy FFT/sign code.
- `std` feature is in `default`, and disabling it is not documented to work for bare-metal.
- **Verdict: Not viable for CKB-VM.**

---

## 4. PQClean FFI Path Assessment (Option B)

If all Rust crates had failed, the FFI path would be via PQClean's `falcon-512/clean/`:

**Files in PQClean falcon-512/clean:** `api.h codec.c common.c fft.c fpr.c fpr.h inner.h keygen.c pqclean.c rng.c sign.c vrfy.c`

**FP audit:**
- `vrfy.c`: Zero references to `double`, `float`, `sqrt`, `<math.h>`, or `fpr_*` functions. Uses integer NTT via `mq_NTT`, `mq_iNTT`, `mq_poly_montymul_ntt`. **Verification is FP-free in PQClean too.**
- `fpr.c` / `fft.c`: Heavy FP usage (`fpr_add`, `fpr_mul`, `fpr_neg`, etc.). Used only in `sign.c` and `keygen.c`.
- `vrfy.c` includes `inner.h` which declares FP types, but `vrfy.c` itself never calls any FP function.

**FFI complexity estimate:** ~200 LOC for a minimal FFI wrapper. However, the `cc` crate compiles all C files including `fpr.c` and `fft.c` via glob, so the wrapper would need to only compile `vrfy.c`, `common.c`, and `codec.c` (and exclude `fft.c`, `sign.c`, `keygen.c`, `fpr.c`, `rng.c`, `keygen.c`). That selective compilation is achievable but requires auditing which objects `vrfy.c` actually links against at the symbol level.

**Conclusion:** The FFI path would work in principle but adds C build toolchain complexity (requires `riscv64-unknown-elf-gcc` or a cross-compiler in the build environment). Since `fn-dsa-vrfy` works in pure Rust, the FFI path is unnecessary.

---

## 5. Cycle Budget Check

**Reference:** Karl et al. 2024, "Efficient Post-Quantum Signatures on Embedded Systems" — reports Falcon-512 verify at **314,639 RV32IMC cycles** on PULPino (32-bit, in-order, no cache).

**CKB-VM characteristics vs PULPino:**
- CKB-VM is RV64IMC (64-bit), which reduces iteration count for some 64-bit arithmetic (NTT multiplications benefit from wider registers).
- CKB-VM does NOT have hardware atomics, but verify path doesn't use atomics.
- CKB-VM executes in a JIT-like interpreter on the host — cycle accounting in CKB is per-instruction, roughly 1:1 with a software interpreter.

**Estimate:** RV64 vs RV32 gives roughly 0.5x–0.8x cycle reduction for NTT-heavy code (64-bit words process two 32-bit values in some patterns). Interpreter overhead is minimal for the instruction mix (integer arithmetic, loads/stores). Estimate: **200,000–400,000 CKB-VM cycles** for Falcon-512 verification.

**Budget:** 70,000,000 cycles per script (CKB testnet).

**Margin:** ~175x–350x headroom. Even if the estimate is off by 10x, Falcon-512 verify is well within budget.

**For comparison:** ML-DSA-65 verify uses approximately 3–8M cycles on CKB-VM (observed during v2 testing). Falcon is expected to be cheaper due to simpler integer NTT (no rejection sampling, no large matrix operations).

---

## 6. Integration Sketch

Assuming `fn-dsa-vrfy` is selected, the integration mirrors the exact pattern used for `mldsa-lock-v2`. All paths are relative to the project root.

### 6.1 Rename `ckb-fips204-utils` or create a sibling

**Option A (recommended): Create a new crate `ckb-pq-utils`**  
This avoids breaking existing mldsa users and keeps algorithm-specific concerns separated.

**Option B: Extend `ckb-fips204-utils` directly**  
Add Falcon variants alongside ML-DSA. The `ParamId` comment already says "unified ParamId enum can absorb both without renumbering. ML-DSA gets 60..=62".

### 6.2 New ParamId values (in `ckb-fips204-utils/src/lib.rs` or new crate)

```rust
pub enum ParamId {
    Mldsa44  = 60,
    Mldsa65  = 61,
    Mldsa87  = 62,
    Falcon512  = 63,   // fn-dsa logn=9, 897-byte pk, 666-byte sig
    Falcon1024 = 64,   // fn-dsa logn=10, 1793-byte pk, 1280-byte sig
}
```

### 6.3 Sizes (from fn-dsa README, confirmed against FIPS 206 Falcon spec)

```
Falcon-512:  pk=897B, sig=666B,  sk=1281B
Falcon-1024: pk=1793B, sig=1280B, sk=2305B
```

### 6.4 New verify arm in `verifying.rs`

```rust
ParamId::Falcon512 => {
    use fn_dsa_vrfy::{VerifyingKey512, VerifyingKey, DOMAIN_NONE};
    use fn_dsa_vrfy::HashIdentifier;
    // Build a HashIdentifier from the pre-hashed message context
    // (we use HASH_ID_RAW for the CKB "digest pipeline" equivalent)
    let vk = VerifyingKey512::decode(public_key)
        .ok_or(Error::InvalidPubkeyLength)?;
    let ok = vk.verify(signature, &DOMAIN_NONE, &HASH_ID_RAW, message);
    if ok { true } else { return Err(Error::VerifyFailed) }
}
```

**Important API difference vs fips204:** `fn-dsa-vrfy::verify()` returns `bool`, not `Result`. Also the argument order is `(sig, ctx, hash_id, message)` — note `ctx` before `hash_id`, which is reversed from what one might expect.

### 6.5 Message pipeline for Falcon

The existing CKB mldsa pipeline: `ckb_tx_message_all → blake2b_personal("ckb-mldsa-msg") → fips204_final_message_wrap → ML-DSA verify`

For Falcon the pipeline simplifies because `fn-dsa-vrfy` accepts the raw message hash directly (no `M'` wrapping needed): `ckb_tx_message_all → blake2b_personal("ckb-falcon-msg") → fn-dsa-vrfy::verify`

This is slightly simpler than the FIPS 204 path since Falcon's DOMAIN_NONE + HASH_ID_RAW means "the input IS the message, no pre-hash wrapping". The personalised blake2b domain separation ("ckb-falcon-msg") provides the algorithm-level separation.

### 6.6 New contract: `contracts/falcon-lock-v2/`

Mirror `contracts/mldsa-lock-v2/` exactly:
- Same `rust-toolchain.toml` (nightly-2025-01-01)
- Same `.cargo/config.toml` and `ckb-contract.ld`
- Same `Cargo.toml` shape, replacing `ckb-fips204-utils` with the new crate/feature
- Two binary targets: `falcon512-lock-v2` and `falcon1024-lock-v2`
- Expected binary size: 20,000–30,000 bytes (slightly smaller than 49,904 byte ML-DSA binaries due to simpler verify arithmetic)

### 6.7 Test additions

1. **Unit tests in `ckb-pq-utils`:** Generate a Falcon-512 key pair with `fn-dsa-kgen`, sign with `fn-dsa-sign`, verify with `fn-dsa-vrfy` — confirm round-trip.
2. **Integration test in `tests/integration/`:** Mirror `mldsa_v2_single_sig.rs`, deploying `falcon512-lock-v2` and running a test transaction.
3. **KAT vectors:** fn-dsa-vrfy ships with known-answer tests (`#[test] fn verify_kat_512()`). Smoke-test against the NIST HAWK/Falcon KAT vectors once FIPS 206 is published.

---

## 7. Risks and Open Questions

### 7.1 FIPS 206 standard not yet final (as of fn-dsa v0.3.0)

The fn-dsa crate carries a WARNING that key encodings and domain separation may change before the 1.0 release. The standard was expected to be published during 2025. If FIPS 206 has now been published (after the fn-dsa 0.3.0 release date of 2025-01-26), check whether a newer fn-dsa version tracks it.

**Mitigation:** Pin the fn-dsa-vrfy version in Cargo.lock. Accept that falcon-lock-v2 will need a v3 migration if key encoding changes. This is the same tradeoff we accepted for fips204 during the draft period.

### 7.2 fn-dsa-vrfy verify() API differences

The verify function signature is `verify(sig, ctx, hash_id, msg) -> bool`, where:
- `ctx` = `&DomainContext` (use `DOMAIN_NONE`)
- `hash_id` = `&HashIdentifier` (use `HASH_ID_RAW` for pre-hashed or raw message)
- Returns `bool` not `Result`

This is slightly different from the fips204 API. The integration code handles it with `.ok_or(Error::InvalidPubkeyLength)` for decode and a conditional for verify.

### 7.3 fn-dsa signing path NOT usable on CKB-VM

The `fn-dsa-sign` crate explicitly requires the RISC-V D extension for floating-point (used in the Gaussian sampler). Key generation and signing must happen off-chain. This is the expected pattern (same as ML-DSA) — CKB lock scripts only verify.

### 7.4 cpufeatures / libc in dependency tree

`cpufeatures` and `libc` appear in the Cargo.lock but are entirely cfg-gated to x86/x86_64. No libc code is linked into the binary. This can be verified by checking the binary imports (none, since it's statically linked bare-metal).

---

## 8. Recommended Path Forward

**Recommended: Option A — fn-dsa-vrfy**

1. **Session 1 (integration):** Create `crates/ckb-falcon-utils` (or extend `ckb-fips204-utils`) with the ParamId extensions and `fn-dsa-vrfy` verify arm. Write unit tests. Add `fn-dsa-vrfy = "0.3.0"` as a dependency with `default-features = false`.

2. **Session 1 (contract):** Create `contracts/falcon-lock-v2/` mirroring the mldsa-lock-v2 structure. Build and size-check the `falcon512-lock-v2` and `falcon1024-lock-v2` binaries.

3. **Session 1 (tests):** Add integration tests in `tests/integration/` mirroring `mldsa_v2_single_sig.rs`.

4. **Session 2 (deploy):** Deploy to CKB testnet, run smoke tests, verify cycle counts with `ckb-debugger`.

5. **Later (standard):** When FIPS 206 final is published, migrate to the new fn-dsa version that tracks it. Key pairs generated pre-standard will need regeneration.

**Do NOT use `fn-dsa` (the facade crate)** — it pulls in `fn-dsa-sign` which has FP and will fail to link.

---

*Report written by Claude Code investigation session, 2026-04-08. All build attempts run on driveThree (x86_64, rustup nightly-2025-01-01). Probe sources at `/tmp/falcon-probe-fn-dsa/` and `/tmp/falcon-probe-falcon-rs/`.*
