# ckb-mldsa-lock — Graph-as-Navigation Usage Records

Tracking whether the graphify knowledge graph of this repo measurably reduced
token spend / search effort during deep deployment prep.

## Session 1 — 2026-04-07 (broken / recovered)

**Session ID:** `5163fb76-f630-4d4d-994e-3a4013bc0acf`
**CWD:** `/home/phill/ckb-mldsa-lock/contracts/mldsa-lock`
**Window:** 2026-04-07 02:27:32 → 10:28:52 UTC (~8h wall, intermittent)
**Outcome:** broken mid-trace of `MLD_API_NAMESPACE` macros in vendored ML-DSA C source

### Corpus
- Path: `~/graphs/ckb-mldsa-lock-corpus/`
- Files: 50 (37 C/H, 3 Rust, 3 JS/TS, 2 MD + meta)
- Mode: `--mode deep`
- Outputs: `graphify-out/{graph.json,graph.html,GRAPH_REPORT.md}` (built ~18:31 local)
- Note: graphify symlink detector only picks up file-level symlinks → real copies needed

### Token totals (raw, from session jsonl)
| Metric | Value |
|---|---:|
| Assistant messages | 751 |
| Tool uses | 360 |
| Tool uses touching graph/graphify | 102 (28%) |
| Input tokens (non-cache) | 1,503 |
| Output tokens | 451,200 |
| Cache read | 359,590,850 |
| Cache write | 3,237,046 |
| Billed-equivalent (in + out + cache_w) | **3,689,749** |

### Concrete result delivered in-session
All three ML-DSA variants build from one source tree:

| Variant | Binary | text | bss | total | NIST | pk | sig |
|---|---|---:|---:|---:|---:|---:|---:|
| ML-DSA-44 | `mldsa44-lock` | 18,946 | 8,636 | 27,598 | 2 | 1312 | 2420 |
| ML-DSA-65 | `mldsa-lock` | 19,248 | 11,693 | 30,957 | 3 | 1952 | 3309 |
| ML-DSA-87 | `mldsa87-lock` | 18,784 | 15,611 | 34,411 | 5 | 2592 | 4627 |

Observation: text size is nearly identical (18.7–19.2 KB) — same code path,
only polyveck/polyvecl dimensions change. BSS scales with parameter set.

### Security state (carried in)
- Closed: CRIT-1, CRIT-2, CRIT-3, HIGH-4
- Open: **HIGH-1**

### Where the trace stopped
Grep over `MLD_API_NAMESPACE` macros in vendored mldsa header — enumerated
keypair / signature / sign / verify / open / pre_hash{,_shake256} variants and
the `crypto_sign_*` aliases. Next step was wiring those into the lock entrypoint
audit. No edits made; pure read.

### ROI signal (qualitative, from session text)
Phill's framing: *"token-tracking is the right way to measure the graph's
actual ROI."* 28% of tool calls touched the graph artifacts directly, and the
graph let the build-size table get derived in one query rather than a multi-file
crawl. Hard ROI number requires a no-graph control run for comparison —
**TODO: re-run an equivalent task on a fresh session without the graph
mounted, capture the same totals, diff them.**

## Session 2 — 2026-04-07 (deep deployment prep, resumed)

**Session ID:** `6642d532-793d-42bf-83a3-6c51dc31b162`
**CWD:** `/home/phill` (worked across `~/code/key-vault-wasm` and `~/ckb-mldsa-lock`)
**Window:** 2026-04-07 11:20:52 → 13:01:56 UTC (~1h 40m sustained)
**Outcome:** successful — three deploy-ready Rust lock binaries produced

### Token totals (from session jsonl)
| Metric | Session 1 | Session 2 |
|---|---:|---:|
| Assistant messages | 751 | 275 |
| Tool uses | 360 | 163 |
| Tool uses touching graph | 102 (28%) | 20 (12%) |
| Input tokens (non-cache) | 1,503 | 425 |
| Output tokens | 451,200 | 97,483 |
| Cache read | 359,590,850 | 48,037,860 |
| Cache write | 3,237,046 | 648,823 |
| **Billed-equivalent** | **3,689,749** | **746,731** |

**~5× lower cost for Session 2** despite more code produced. Attributable to:
1. Clearer scoping (1 concrete deliverable: deployable Rust lock binaries)
2. Graph-first navigation was enforced explicitly after Phill's nudge
3. No repeat of the "where is the on-chain SPHINCS+ lock" dead-ends from Session 1

### What the graph surfaced (vs what grep would have needed)
One decisive query early in the session — `message_build_fips205_final_message`
hit in the KB graph — led directly to `ckb-fips205-utils/src/message.rs`,
`verifying.rs`, `ckb_tx_message_all_in_ckb_vm.rs`, and the complete layered
structure, in 3 tool calls. A grep-only approach would have required finding
the right repo (quantum-purse? key-vault-wasm? xxuejie's test-vector repo?),
then globbing for `*.rs`, then reading multiple files. Estimated ~8–12 tool
calls saved on that single query.

The *other* decisive graph query was earlier in the session — finding Phill's
existing `feat/mldsa65` branch on the fork via `gh api compare`. Not a graph
query strictly, but the same "search for what already exists before writing
new code" discipline.

### Concrete deliverables this session
**key-vault-wasm `feat/mldsa65-cighash` branch (2 commits, +1048 LOC):**
- `crates/ckb-fips204-utils/src/lib.rs` — full rewrite on SPHINCS+ pattern
- `crates/ckb-fips204-utils/src/verifying.rs` — new, ML-DSA-44/65/87 match
- `crates/ckb-fips204-utils/src/message.rs` — new, FIPS-204 §5.4 M' framing
- `crates/ckb-fips204-utils/src/ckb_tx_message_all_in_ckb_vm.rs` — verbatim copy
- `crates/ckb-fips204-utils/src/signing.rs` — rewritten against new API, self-verify
- `crates/ckb-fips204-utils/Cargo.toml` — feature flags: std/verifying/signing/ckb-vm
- `src/lib.rs` (outer wasm crate) — 4 WASM binding call sites updated
- **13/13 tests passing** including a full sign→verify round-trip
- Both default and ckb-vm feature sets build clean

**ckb-mldsa-lock repo (1 commit):**
- `contracts/mldsa-lock-v2/` — standalone Rust contract crate
- Three deploy-ready RISC-V binaries at 49,904 bytes each:
  - `mldsa44-lock-v2`  sha256 `e4f94130...`
  - `mldsa65-lock-v2`  sha256 `7f817415...`
  - `mldsa87-lock-v2`  sha256 `3fb08c9b...`
- 2× the hand-tuned C contract size; feature-gating per variant would close the gap.

### Graph-first rule formalised
Mid-session Phill said: *"you using the graph"* → *"lets keep using the graph"*
→ *"can we write rules to always consult the graph for all relative future work"*
→ *"should we create a separate one for active work we're doing"*.
Formalised as `~/.claude/projects/-home-phill/memory/feedback_graph_first_navigation.md`
(auto-loaded via MEMORY.md index) and the companion project-state file
`project_ckb_mldsa_lock_v2.md`.

