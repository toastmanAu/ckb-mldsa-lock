# Mainnet Readiness Checklist

> **This is a gating list, not a deploy strategy.** Mainnet deployment becomes a
> conversation when every item below is checked and nothing has moved for a long
> stretch. Until then, testnet stays on TYPE ID (redeployable) for iteration
> velocity.
>
> **Mainnet deploys will be immutable** (data-hash dep cells, no TYPE ID) to
> close the PQC gap: a TYPE ID upgrade authority protected by a classical
> secp256k1 lock is a quantum-breakable trust root sitting on top of
> quantum-safe verifier code. Immutability eliminates the upgrade authority
> entirely. Trade-off: bugs are unfixable post-deploy; consumers migrate to a
> new `data_hash` cell at their own pace.

## Build safety

- [x] `overflow-checks = true` across all Rust locks (session 10, 2026-04-10)
- [ ] Witness-parse fuzzing corpus — run `cargo-fuzz` against each variant's
      `entry::main()` with crafted witnesses for N hours, zero crashes
- [ ] Deserialization bounds-check audit — every `from_be_bytes`/`from_le_bytes`
      → `as usize` path reviewed for silent wrap (the ckb-fiber onion-packet
      pattern: integer overflow in length parsing → OOB slice access)
- [ ] `cargo-careful` / `miri` clean on host-target builds of the verifier logic
      (riscv target limits miri, but host-target exercises the same Rust code)

## Cryptographic correctness

- [ ] NIST ACVP test vector coverage for ML-DSA-{44,65,87} — all KAT vectors
      pass against the deployed binary via ckb-debugger
- [ ] NIST ACVP test vector coverage for FN-DSA-{512,1024} (when FIPS 206 KATs
      are published; fn-dsa 0.3 predates final spec)
- [ ] Differential testing: RustCrypto ml-dsa vs fips204 vs reference C on a
      large random signature corpus (10k+ keypairs), zero divergence on
      accept/reject decisions
- [ ] Signature malleability audit — confirm the deployed locks reject all
      non-canonical signature encodings (important for consensus: two valid
      encodings of the same sig would produce two valid witness variants)

## External review

- [ ] Independent review by >= 1 external cryptographer or CKB core dev
- [ ] External review of the lock *glue code* (witness parsing, CighashAll
      streaming, lock_args validation) — historically where bugs hide, not in
      the crypto verify call itself
- [ ] Core-dev sign-off on deployment parameters (cell capacity, fee structure,
      type script configuration)

## Reproducibility

- [ ] Reproducible build: same `data_hash` from a clean clone on a second
      machine with pinned toolchain (rust-toolchain.toml already pins nightly)
- [ ] Build instructions documented so any third party can verify the deployed
      binary matches the source at a specific git commit

## Documentation

- [ ] RFC-style spec doc matching deployed behavior byte-for-byte — covers
      witness layout, lock_args format, CighashAll algorithm, domain separation,
      error codes, and the exact `code_hash` computation consumers use
- [ ] Migration guide for existing testnet consumers moving from `hash_type: type`
      (TYPE ID, testnet) to `hash_type: data1` (immutable, mainnet)

## Operational

- [ ] Merge freeze on all lock contract code for >= 2 weeks before deploy —
      no code changes between final audit and mainnet deployment
- [ ] Deploy key ceremony: mainnet deploy cell created from a fresh key that is
      then destroyed (the cell is self-locking via data-hash, so no key is
      needed post-deploy — but the funding tx still needs a classical sighash
      to provide capacity, and that key should not be reusable)
- [ ] Monitoring: block explorer integration or lightweight script that polls
      for new cells using the PQ lock code_hashes and alerts on unexpected
      patterns (large capacity, unusual lock_args lengths, etc.)

---

*Last updated: 2026-04-10, session 10 (overflow-checks re-enabled).*
