//! ckb-mldsa-lock v2 — SPHINCS+-style ML-DSA lock script (shared library).
//!
//! This library is consumed by three bin targets (`mldsa{44,65,87}-lock-v2`).
//! Each bin is a ~6-line stub that wires the `ckb_std::entry!` macro to
//! `entry::run(ParamId::Mldsa{N})`.
//!
//! ## Lock args layout (37 bytes, v2)
//!
//! ```text
//! [0]     0x80                       multisig header
//! [1]     0x01                       require_first_n
//! [2]     0x01                       threshold
//! [3]     0x01                       pubkey count
//! [4]     flag = (param_id << 1)     no sig bit (0)
//! [5..37] blake2b_256(pk)            32-byte pubkey hash
//! ```
//!
//! ## Witness lock layout
//!
//! `WitnessArgs.lock` = `[flag | pubkey | signature]`
//! - `flag` packs `(param_id, has_sig=1)`
//! - `pubkey` length depends on param_id (1312 / 1952 / 2592)
//! - `signature` length depends on param_id (2420 / 3309 / 4627)
//!
//! ## Verification pipeline
//!
//! 1. Load script args, validate prefix `[0x80, 0x01, 0x01, 0x01, flag]`.
//! 2. Load witness at index 0 of `GroupInput`, parse `WitnessArgs`, extract lock.
//! 3. Split lock into `(flag, pk, sig)`. Reject if any length wrong.
//! 4. Hash pk into `Hasher::script_args_hasher()`, compare against args[5..37].
//! 5. Build signing digest: feed `generate_ckb_tx_message_all` into
//!    `Hasher::message_hasher()`, finalise to 32 bytes.
//! 6. Wrap digest via `build_fips204_final_message(None, digest, Some(DOMAIN))`.
//! 7. Call `verifying::verify(param_id, pk, sig, final_msg)`.

#![no_std]

extern crate alloc;

pub mod entry;
