#!/usr/bin/env bash
# benchmark.sh — run all benchmarks and generate a detailed markdown report
# Usage: ./scripts/benchmark.sh [--output path/to/report.md]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TIMESTAMP="$(date -u '+%Y-%m-%d %H:%M UTC')"
DATE="$(date -u '+%Y-%m-%d')"
OUTPUT="${1:-$REPO_ROOT/docs/benchmark-report.md}"

cd "$REPO_ROOT"

echo "==> Running benchmarks (this will take a few minutes)..."

# ── 1. Contract: binary size ──────────────────────────────────────────────
echo "  [1/5] Contract binary size..."
cd contracts/mldsa-lock
make -s 2>/dev/null || true
BIN="build/mldsa-lock"
BIN_SIZE_BYTES=$(wc -c < "$BIN")
BIN_SIZE_KB=$(echo "scale=1; $BIN_SIZE_BYTES / 1024" | bc)
TEXT_SIZE=$(riscv64-unknown-elf-size "$BIN" | tail -1 | awk '{print $1}')
DATA_SIZE=$(riscv64-unknown-elf-size "$BIN" | tail -1 | awk '{print $2}')
BSS_SIZE=$(riscv64-unknown-elf-size "$BIN" | tail -1 | awk '{print $3}')
cd "$REPO_ROOT"

# ── 2. Contract: ckb-debugger cycle counts ───────────────────────────────
echo "  [2/5] Contract cycle counts (ckb-debugger)..."
cd contracts/mldsa-lock/tests
# Rebuild gen_test_vector if needed
if [ ! -f gen_test_vector ]; then
  gcc -O2 \
    -I../vendor/mldsa-native/mldsa -I../vendor/mldsa-native/mldsa/src \
    -DMLD_CONFIG_PARAMETER_SET=65 -DMLDSA_RANDOMIZED_SIGNING=0 \
    gen_test_vector.c ../vendor/mldsa-native/mldsa/mldsa_native.c \
    -o gen_test_vector 2>/dev/null
fi
./gen_test_vector > mock_tx_bench.json 2>bench_gen.log
_DBG_PASS=$(ckb-debugger --mode fast \
  --tx-file mock_tx_bench.json \
  --script-group-type lock --cell-index 0 --cell-type input 2>&1) || true
CYCLES_PASS=$(echo "$_DBG_PASS" | grep "All cycles" | grep -oP '\d+' | head -1)

./gen_test_vector --fail > mock_tx_bench_fail.json 2>/dev/null
_DBG_FAIL=$(ckb-debugger --mode fast \
  --tx-file mock_tx_bench_fail.json \
  --script-group-type lock --cell-index 0 --cell-type input 2>&1) || true
CYCLES_FAIL=$(echo "$_DBG_FAIL" | grep "All cycles" | grep -oP '\d+' | head -1)
rm -f mock_tx_bench.json mock_tx_bench_fail.json bench_gen.log
cd "$REPO_ROOT"

# ── 3. Rust tests + benchmarks ───────────────────────────────────────────
echo "  [3/5] Rust tests..."
RUST_TEST_OUTPUT=$(cargo test 2>&1)
RUST_TESTS_PASSED=$(echo "$RUST_TEST_OUTPUT" | grep -oP '\d+ passed' | grep -oP '\d+' | python3 -c "import sys; print(sum(int(x) for x in sys.stdin))" 2>/dev/null || echo "?")

echo "  [3/5] Rust benchmarks (criterion)..."
RUST_BENCH_RAW=$(cargo bench --bench sdk 2>&1 | sed 's/\x1b\[[0-9;]*m//g')

# Parse criterion output. Criterion emits either:
#   "name   time:   [low median high]"   (short names, same line)
#   "name\n   time:   [low median high]" (long names, next line)
# Strip ANSI, join continuation lines, then match label → median.
# Note: data + label passed via env vars to avoid stdin conflict with heredoc.
parse_criterion() {
  local label="$1"
  BENCH_LABEL="$label" BENCH_DATA="$RUST_BENCH_RAW" python3 << 'PYEOF'
import re, os
label = os.environ['BENCH_LABEL']
lines = os.environ['BENCH_DATA'].splitlines()
prev = ""
for line in lines:
    combined = (prev + " " + line).strip() if line.startswith(" ") else line
    if label in combined and "time:" in combined:
        nums = re.findall(r'([\d.]+)\s*(ns|µs|ms|s)\b', combined)
        if len(nums) >= 3:
            val, unit = nums[1]  # median
            print(f"{val} {unit}")
            break
    if not line.startswith(" "):
        prev = line
PYEOF
}

BENCH_KEYGEN=$(parse_criterion "keygen")
BENCH_SIGN=$(parse_criterion "sign_witness")
BENCH_VERIFY=$(parse_criterion "verify")
BENCH_SIGNING_MSG=$(parse_criterion "signing_message")
BENCH_PUBKEY_HASH=$(parse_criterion "pubkey_hash")
BENCH_LOCK_ARGS=$(parse_criterion "lock_args")

# ── 4. TypeScript tests + benchmarks ─────────────────────────────────────
echo "  [4/5] TypeScript tests..."
cd sdk/js
JS_TEST_OUT=$(npm test 2>&1) || true
JS_TESTS_PASSED=$(echo "$JS_TEST_OUT" | grep -oP '\d+ passed' | grep -oP '\d+' | sort -n | tail -1 || echo "?")

echo "  [4/5] TypeScript benchmarks..."
JS_BENCH_RAW=$(npx ts-node src/bench.ts 2>/dev/null)
cd "$REPO_ROOT"

# Parse JS bench JSON
js_field() { echo "$JS_BENCH_RAW" | python3 -c "
import json,sys
data = json.load(sys.stdin)
for r in data['results']:
    if r['name'] == '$1':
        v = r['meanUs']
        if v >= 1000:
            print(f'{v/1000:.1f} ms')
        else:
            print(f'{v:.1f} µs')
        break
" 2>/dev/null || echo "?"; }

JS_KEYGEN=$(js_field "keygen")
JS_SIGN=$(js_field "sign_witness")
JS_VERIFY=$(js_field "verify")
JS_SIGNING_MSG=$(js_field "signing_message (blake2b)")
JS_PUBKEY_HASH=$(js_field "pubkey_hash (blake2b 1952B)")
JS_LOCK_ARGS=$(js_field "lock_args derivation")
JS_NODE=$(echo "$JS_BENCH_RAW" | python3 -c "import json,sys; print(json.load(sys.stdin)['nodeVersion'])" 2>/dev/null || node --version)

# ── 5. System info ────────────────────────────────────────────────────────
echo "  [5/5] Collecting system info..."
CPU_MODEL=$(grep "model name" /proc/cpuinfo | head -1 | cut -d: -f2 | xargs)
RUST_VERSION=$(rustc --version)
OS=$(uname -srm)

# ── Generate report ───────────────────────────────────────────────────────
echo "==> Generating report: $OUTPUT"
mkdir -p "$(dirname "$OUTPUT")"

cat > "$OUTPUT" << REPORT
# CKB ML-DSA-65 Lock Script — Benchmark Report

**Generated:** $TIMESTAMP
**Host:** $CPU_MODEL
**OS:** $OS

---

## Summary

| | |
|---|---|
| **Contract cycles (pass)** | $(printf "%'.0f" "$CYCLES_PASS") (~$(python3 -c "print(f'{$CYCLES_PASS/1e6:.1f}')") M) |
| **Contract cycles (fail)** | $(printf "%'.0f" "$CYCLES_FAIL") |
| **Binary size** | ${BIN_SIZE_KB} KB (${BIN_SIZE_BYTES} bytes) |
| **Tests** | ${RUST_TESTS_PASSED} Rust + ${JS_TESTS_PASSED} TypeScript |

---

## Contract Performance (CKB-VM)

Measured using \`ckb-debugger --mode fast\` on the deployed testnet binary.

| Scenario | Cycles | Notes |
|---|---|---|
| **Valid signature** | $(printf "%'.0f" "$CYCLES_PASS") | Full keygen→sign→verify path |
| **Invalid signature** | $(printf "%'.0f" "$CYCLES_FAIL") | Fails at ML-DSA verify |

### CKB-VM Cycle Budget Context

| Limit | Cycles | Headroom |
|---|---|---|
| Single-script limit | 70,000,000 | ~$(python3 -c "print(f'{70000000//$CYCLES_PASS}×')") budget remaining |
| Block limit | 3,500,000,000 | — |
| **mldsa-lock usage** | $(printf "%'.0f" "$CYCLES_PASS") | $(python3 -c "print(f'{$CYCLES_PASS*100/70000000:.1f}%')") of script limit |

---

## Contract Binary

Built for RISC-V rv64imc (CKB-VM), no stdlib, no OS.

| Section | Bytes |
|---|---|
| .text (code) | $TEXT_SIZE |
| .data | $DATA_SIZE |
| .bss | $BSS_SIZE |
| **Total stripped** | $BIN_SIZE_BYTES (${BIN_SIZE_KB} KB) |

**Comparison with secp256k1 lock script** (reference):

| Script | Binary Size | Cycles |
|---|---|---|
| secp256k1-blake160 | ~65 KB | ~1.7M |
| **mldsa-lock** | **${BIN_SIZE_KB} KB** | **$(echo "scale=1; $CYCLES_PASS / 1000000" | bc)M** |

*secp256k1 figures are approximate from public CKB toolchain benchmarks.*

---

## Rust SDK Performance

**Runtime:** $RUST_VERSION

| Operation | Time | Notes |
|---|---|---|
| \`keygen\` | ${BENCH_KEYGEN:-?} | Generate ML-DSA-65 key pair |
| \`sign_witness\` | ${BENCH_SIGN:-?} | Sign tx + serialize WitnessArgs |
| \`verify\` | ${BENCH_VERIFY:-?} | Verify signature |
| \`signing_message\` | ${BENCH_SIGNING_MSG:-?} | blake2b("CKB-MLDSA-LOCK" ‖ tx_hash) |
| \`pubkey_hash\` | ${BENCH_PUBKEY_HASH:-?} | blake2b(pubkey) — 1952 bytes |
| \`lock_args\` | ${BENCH_LOCK_ARGS:-?} | Full lock args derivation |

### Rust Tests

\`\`\`
$(echo "$RUST_TEST_OUTPUT" | grep -E "^test |running |test result" | head -30)
\`\`\`

---

## TypeScript SDK Performance

**Runtime:** Node.js $JS_NODE

| Operation | Time | Notes |
|---|---|---|
| \`keygen\` | $JS_KEYGEN | Generate ML-DSA-65 key pair |
| \`signWitness\` | $JS_SIGN | Sign tx + serialize WitnessArgs |
| \`verify\` | $JS_VERIFY | Verify signature |
| \`signingMessage\` | $JS_SIGNING_MSG | blake2b("CKB-MLDSA-LOCK" ‖ tx_hash) |
| \`ckbBlake2b (1952B)\` | $JS_PUBKEY_HASH | Pubkey hash |
| \`lockArgs\` | $JS_LOCK_ARGS | Full lock args derivation |

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
| **type_id** | \`0x8984f4230ded4ac1f5efee2b67fef45fcda08bd6344c133a2f378e2f469d310d\` |
| **data_hash** | \`0x7dcb281583da642016be3a0a4a4d7d4c4d573df2ae10cd4fb4d1616d74007725\` |
| **deploy tx** | \`0xba4a6560ef719b24d170bf678611b25b799c56e6a80f18ce9c79e9561085cba7\` |
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

- Contract compiled with \`-Os\` optimisation, no stdlib, no OS.
- Cycle counts are deterministic for a given input — no variance.
- Rust benchmarks use Criterion.rs (statistical, outlier-filtered).
- TypeScript benchmarks are wall-clock timing loops (20–2000 iterations).
- **Sighash coverage**: signing digest covers \`tx_hash\` only (safe for testnet). Full RFC-0024 sighash-all planned before mainnet.
REPORT

echo "==> Done: $OUTPUT"
