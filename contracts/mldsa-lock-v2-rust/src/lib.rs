//! ckb-mldsa-lock v2-rust — RustCrypto ml-dsa lock script (shared library).
//!
//! Pure-Rust sibling of `mldsa-lock-v2` using the RustCrypto `ml-dsa` crate
//! instead of `fips204`. Separate deployment with distinct `code_hash` per
//! variant — NOT a replacement. Signatures from this lock are NOT cross-
//! compatible with `mldsa-lock-v2` because the two crates apply FIPS-204 §5.4
//! M' framing differently:
//!
//!   mldsa-lock-v2       → explicit `build_fips204_final_message` wrapper on
//!                         host, passes result to fips204::verify with empty
//!                         ctx (which wraps AGAIN, double-framing)
//!   mldsa-lock-v2-rust  → passes raw digest + ctx to
//!                         ml-dsa's `verify_with_context`, which applies the
//!                         M' framing once per strict FIPS 204 §5.4
//!
//! Motivation: XuJiandong's benchmark #9 showed the RustCrypto `ml-dsa` crate
//! at ~25% fewer cycles than `fips204` on CKB-VM for verify (mldsa-65:
//! ~7.4M vs ~9.8M cycles). This crate measures that delta on the real lock-
//! plumbing, not on a bare verify call in a benchmark harness.
//!
//! ## Lock args layout (37 bytes, identical to mldsa-lock-v2)
//!
//! ```text
//! [0]     0x80                       multisig header
//! [1]     0x01                       require_first_n
//! [2]     0x01                       threshold
//! [3]     0x01                       pubkey count
//! [4]     flag = (param_id << 1)     no sig bit (0)
//! [5..37] blake2b_256(pk)            32-byte pubkey hash (personalised "ckb-mldsa-sct")
//! ```
//!
//! ## Witness lock layout (identical to mldsa-lock-v2)
//!
//! `WitnessArgs.lock` = `[flag | pubkey | signature]`
//! - `flag` packs `(param_id, has_sig=1)`
//! - `pubkey` length depends on param_id (1312 / 1952 / 2592)
//! - `signature` length depends on param_id (2420 / 3309 / 4627)
//!
//! ## Verification pipeline (differs from mldsa-lock-v2)
//!
//! 1. Load script args, validate 37-byte prefix + flag.
//! 2. Load witness lock, split into `(flag, pk, sig)`.
//! 3. Hash pk into `Hasher::script_args_hasher`, compare against args[5..37].
//! 4. Build signing digest: stream `generate_ckb_tx_message_all` into
//!    `Hasher::message_hasher`, finalise to 32 bytes.
//! 5. Call `ml_dsa::VerifyingKey::verify_with_context(digest, DOMAIN, sig)`.
//!    (No explicit M' wrapping — the crate does it internally.)

#![no_std]

extern crate alloc;

pub mod entry;
pub mod helpers;
pub mod streamer;

pub use helpers::{construct_flag, destruct_flag, lengths, Error, Hasher, ParamId, DOMAIN};
