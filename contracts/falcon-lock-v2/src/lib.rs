//! falcon-lock-v2 — Falcon / FN-DSA (FIPS 206 draft) CKB lock script.
//!
//! Sibling to `mldsa-lock-v2`. This library is consumed by two bin targets
//! (`falcon512-lock-v2`, `falcon1024-lock-v2`); each bin is a 6-line stub
//! that wires `ckb_std::entry!` to `entry::run(ParamId::FalconN)`.
//!
//! ## Lock args layout (37 bytes, identical to mldsa-lock-v2)
//!
//! ```text
//! [0]     0x80                       multisig header
//! [1]     0x01                       require_first_n
//! [2]     0x01                       threshold
//! [3]     0x01                       pubkey count
//! [4]     flag = (param_id << 1)     no sig bit (0)
//! [5..37] blake2b_256(pk)            32-byte pubkey hash, personalised
//!                                    `b"ckb-falcon-sct"`
//! ```
//!
//! ## Witness lock layout
//!
//! `WitnessArgs.lock` = `[flag | pubkey | signature]`
//! - `flag` packs `(param_id, has_sig=1)`
//! - `pubkey` length: 897 (Falcon-512) or 1793 (Falcon-1024)
//! - `signature` length: 666 (Falcon-512) or 1280 (Falcon-1024)
//!
//! ## Verification pipeline
//!
//! Differs from `mldsa-lock-v2` in step 6 — Falcon does NOT use FIPS-204
//! §5.4 `M'` framing. The blake2b digest is fed directly to `fn-dsa-vrfy`
//! with `DOMAIN_NONE + HASH_ID_RAW`. Domain separation is provided entirely
//! by the personalised blake2b (`b"ckb-falcon-msg"`).
//!
//! 1. Load script args, validate prefix `[0x80, 0x01, 0x01, 0x01, flag]`.
//! 2. Load witness at index 0 of `GroupInput`, parse `WitnessArgs`, extract lock.
//! 3. Split lock into `(flag, pk, sig)`. Reject if any length wrong.
//! 4. Hash pk into `Hasher::falcon_script_args_hasher()`, compare against args[5..37].
//! 5. Build signing digest: feed `generate_ckb_tx_message_all` into
//!    `Hasher::falcon_message_hasher()`, finalise to 32 bytes.
//! 6. Call `verifying::verify(param_id, pk, sig, digest)` — fn-dsa-vrfy
//!    accepts the raw digest with `HASH_ID_RAW`.

#![no_std]

extern crate alloc;

pub mod entry;
