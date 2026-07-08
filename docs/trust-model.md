# Trust Model & Deployment Status

> **Status (2026-04-10):** Testnet experimental. **No lock in this repository
> is recommended for mainnet use with real user funds yet.** See the
> [Mainnet Readiness Checklist](#mainnet-readiness-checklist) below.

This document describes the on-chain trust surface of the deployed PQC lock
scripts so that wallet integrators, protocol authors, and auditors can make
informed decisions about which lock to reference and how.

If you integrate one of these locks into a wallet, bridge, or protocol,
**please read this document in full before picking a `code_hash`** — your
choice of reference style directly determines who is part of your security
model.

---

## Deployed locks (CKB testnet)

All 8 v2 locks listed below are currently published in a single deploy
transaction on testnet.

**Deploy tx:** `0x39b1c11ed7ca2e4a0491c69d105ee07e5659e88109661d4b48f2ff39a45cf1f1`

| Lock | Backend | Cycles | `type_id` | `data_hash` |
|---|---|---:|---|---|
| `mldsa44-lock-v2` | fips204 (C) | ~8M† | `0x1e9798b5…2ba237` | `0xc464c88f…165c3d` |
| `mldsa65-lock-v2` | fips204 (C) | 10.2M | `0xda3e5dc1…6960a7` | `0x5d75d288…8e5826` |
| `mldsa87-lock-v2` | fips204 (C) | ~12M† | `0x37dc2a33…607e15` | `0x79ae9a29…064288` |
| `falcon512-lock-v2` | pqclean (C) | **1.09M** | `0xbf949c79…a2fbd4` | `0xbff48a62…9d92a23` |
| `falcon1024-lock-v2` | pqclean (C) | **1.97M** | `0xbf26aace…6cfd10` | `0x2947fe90…d693d9` |
| `mldsa44-lock-v2-rust` | RustCrypto `ml-dsa` | **3.63M** | `0x52acc41e…9d34756` | `0xc23a32a6…f207d7` |
| **`mldsa65-lock-v2-rust`** | RustCrypto `ml-dsa` | **5.56M** | `0xd70653f7…3b78a4` | `0xc0cabe3c…2a8e9d` |
| `mldsa87-lock-v2-rust` | RustCrypto `ml-dsa` | **8.76M** | `0x70021f94…ca033c` | `0x52310463…6b88c9` |

†The fips204-backed `mldsa44-lock-v2` and `mldsa87-lock-v2` cycle numbers are
estimates; only `mldsa65-lock-v2` was re-benchmarked in the session-9
optimisation pass. The `-rust` sibling variants are strictly faster and
should be preferred by new consumers.

A **legacy v1** `mldsa-lock` (C backend, pre-v2) remains deployed on testnet
at tx `0xba4a6560…`. See [Legacy v1 lock](#legacy-v1-lock) below for the
special story behind that cell.

---

## How these cells are referenced

All 8 v2 cells are deployed with `enable_type_id = true`, meaning the
underlying binary is upgradeable in place via CKB's type-id upgrade pattern.
This has two consequences:

1. **Upgrades are possible without changing the `type_id`.** The deploy
   owner (see below) can publish a new transaction that replaces the code
   contents of a cell while the type-id-derived script hash stays the
   same. This is useful for bug fixes, but it also means any consumer
   referencing a lock by its `type_script` implicitly trusts the deploy
   owner to never abuse that capability.
2. **The upgrade path has been exercised.** In session 9 (2026-04-09),
   `falcon512-lock-v2` and `falcon1024-lock-v2` were rebuilt with
   compiler optimizations (44% / 35% cycle reduction respectively) and
   redeployed in place via the existing type_ids. This is not
   hypothetical — it is a live capability demonstrated on testnet.

---

## Deploy owner (trust root)

All 8 v2 cells are owned by a single secp256k1-blake160 address:

```text
code_hash = 0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8
args      = 0xa776bf02d19cafa3749d906cc2c9ab1cf1e80ff7
hash_type = type
```

**This single key currently controls the content of every upgradeable lock
in this repository.** It is held in `ckb-cli`'s default keystore on the
maintainer's workstation. This is acceptable for testnet experimentation.
It is **not** acceptable for mainnet, and hardening the key custody model
is part of the [Mainnet Readiness Checklist](#mainnet-readiness-checklist).

---

## What this means for integrators

If you are a wallet, protocol, or bridge considering one of these locks,
your choice of reference style determines your trust model:

| Reference style | Follows upgrades? | Trust surface |
|---|---|---|
| `type_script` via `type_id` | **Yes** | Script bugs **plus** deploy-owner-key compromise |
| `code_hash` / `data_hash` | No | Script bugs only |

**For experimental integration and rapid iteration**, referencing by
`type_script` is fine — you get automatic bug-fix delivery and you don't
have to chase new hashes when the script is updated.

**For any production integration holding real value**, reference by
`code_hash` (i.e. the `data_hash` column above) so that a compromise of
the deploy owner key cannot alter the script your users are trusting.
If a genuine bug fix ships later, you can update your integration to
pin the new hash explicitly, as a deliberate act reviewed by your team.

This recommendation is not Quantum-Purse-specific; it applies to any
wallet or protocol considering on-chain PQC locks from this repo.

---

## Legacy v1 lock

The original `mldsa-lock` (C backend, pre-v2 cycle optimizations) remains
deployed on testnet at:

```text
tx_hash = 0xba4a6560…   (full hash in deploy/migrations.v1-backup/)
```

The account that deployed this cell lost access to its signing key shortly
after deployment. As a side effect, **this cell is now effectively
immutable on-chain**: nobody — including the maintainers of this
repository — can republish under its type_id. Consumers that explicitly
pin to the v1 cell's `data_hash` therefore enjoy the strongest on-chain
guarantees of any lock in this set, at the cost of using the un-optimised
v1 binary and forgoing future bug fixes.

This was not planned, and we do not recommend reproducing this
operational accident on purpose. It is documented here because it
provides a concrete reference point for what *deliberate* immutability
would look like in this repo's v2 locks if the maintainers chose to
drop `enable_type_id` on a future deploy.

The v1 lock also has a documented witness-coverage gap (see the main
README, issue **HIGH-1**). Integrators should prefer the v2 Rust binaries
regardless of their preferred reference style.

---

## Known limitations

- **`ckb-cli` batch deploys are all-or-nothing on `enable_type_id`.**
  When `deploy/deployment.toml` lists multiple cells, the `enable_type_id`
  flag cannot be set per-cell within a single deploy run. To freeze one
  specific lock as immutable while keeping others upgradeable, that lock
  must be deployed from a separate `deployment.toml` in its own run.
  This is the mechanism the [Mainnet Readiness
  Checklist](#mainnet-readiness-checklist) assumes for the canonical
  `mldsa65-lock-v2-rust` hardening path.
- **Single-key deploy owner.** See [Deploy owner](#deploy-owner-trust-root)
  above. Acceptable on testnet, not acceptable on mainnet.
- **No on-chain upgrade timelock.** The deploy owner can publish an
  upgrade transaction and have it active in the next block. There is
  currently no on-chain mechanism forcing a delay between announcement
  and activation of a lock-script change. A multisig with time-locked
  unlock conditions would impose such a delay off-chain but is not yet
  in place.
- **No formal upgrade policy.** There is no public commitment yet about
  the circumstances under which the deploy owner would upgrade each
  lock (bug-fix-only? no cipher-suite changes? etc.). This will be
  required before mainnet.

---

## Mainnet Readiness Checklist

Before **any** lock in this repository is recommended for mainnet use,
the following must be true. These are blocking items, not aspirations.

### Hardening the canonical PQC lock (`mldsa65-lock-v2-rust`)

`mldsa65-lock-v2-rust` is the NIST-Level-3 ML-DSA variant that the
[Quantum Purse multi-PQ integration plan](./quantum-purse-multi-pq-plan.md)
stakes real user funds behind. It is the single most critical lock in this
repository and gets the strongest treatment:

- [ ] **Re-deploy `mldsa65-lock-v2-rust` without `enable_type_id`** on
      mainnet, yielding a genuinely immutable code cell. The resulting
      `data_hash` becomes the canonical reference for Quantum Purse and
      any other wallet pinning the mldsa65 variant.
      The deploy will use a dedicated
      `deploy/deployment-mldsa65-canonical.toml` containing only this
      one cell, to satisfy the `ckb-cli` all-or-nothing constraint
      (see [Known limitations](#known-limitations)).
- [ ] **Publish the canonical mainnet `data_hash`** in the main README
      and in this document, together with the mainnet deploy tx hash,
      and tag a repository release at the commit matching the deployed
      binary.
- [ ] **Archive the reproducible build artifacts** (the
      `mldsa65-lock-v2-rust` ELF produced by the deploy build) alongside
      the release so third parties can independently verify the on-chain
      binary matches this source tree.
- [ ] **External audit** of `mldsa65-lock-v2-rust` covering:
      signature-verification correctness, script exit-code handling,
      witness parsing, `CighashAll` streaming boundaries, and edge cases
      in the underlying `ml-dsa` crate. The audit report must be
      published (or at least referenceable) before the canonical
      mainnet deploy.

### Hardening the remaining experimental locks

For the 7 locks that remain upgradeable past mainnet launch:

- [ ] **Move the deploy owner key out of `ckb-cli`'s default keystore**
      to one of:
    - hardware wallet with manual confirmation on upgrades, or
    - m-of-n multisig with at least one offline participant, or
    - time-locked multisig with a minimum N-block delay between
      upgrade tx broadcast and activation.
- [ ] **Publish the key custody model** in this document, including the
      threshold, participants (pseudonymously is fine), and any
      timelock duration.
- [ ] **Publish the upgrade policy**: under what circumstances will the
      deploy owner upgrade each lock (bug fixes only, no cipher-suite
      changes post-deployment, no witness-format changes, etc.), and
      how a given upgrade will be communicated to integrators before
      it lands on chain.

### Verification

- [ ] Known-answer tests passing for each PQC scheme against its NIST
      reference vectors, run against the **on-chain** mainnet binary
      (not just a local build). This ensures the binary that lives on
      mainnet is the binary that was tested.
- [ ] Reproducible build documented in this repo: a fresh clone on a
      clean machine must produce byte-identical ELFs for every cell
      deployed to mainnet.
- [ ] This document updated with mainnet deploy tx hashes, `type_id`s
      (where applicable), `data_hash`es, and any changes to the deploy
      owner model.

---

## Reporting security issues

Please do **not** file security issues in public GitHub issues. Email the
maintainer at **\<CONTACT EMAIL — TODO: add dedicated security address
before mainnet\>** with a description and, if possible, a reproducer.
We will acknowledge within 72 hours and coordinate disclosure privately.

---

## Change log

- **2026-04-10** — Initial version. Documents session-9 testnet state
  (8 v2 locks, all upgradeable, single-key deploy owner) and establishes
  the mainnet readiness checklist. Authored alongside the Quantum Purse
  multi-PQ integration plan.
