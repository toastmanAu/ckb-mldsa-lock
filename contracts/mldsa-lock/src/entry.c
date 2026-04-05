/*
 * CKB ML-DSA-65 Lock Script
 *
 * Verifies an ML-DSA-65 signature (NIST FIPS 204) over the CKB signing digest.
 *
 * Lock args layout (36 bytes):
 *   [0]    version   = 0x01
 *   [1]    algo_id   = 0x02 (ML-DSA)
 *   [2]    param_id  = 0x02 (ML-DSA-65)
 *   [3]    reserved  = 0x00
 *   [4-35] blake2b_256(pubkey)
 *
 * Witness lock field: serialized MldsaWitness (Molecule table)
 *   version | algo_id | param_id | flags | pubkey (1952B) | signature (3309B)
 *
 * Signing message:
 *   msg = blake2b_256("CKB-MLDSA-LOCK" || tx_hash)  [32 bytes]
 *   ctx = "CKB-MLDSA-LOCK"                           [14 bytes]
 *   Passed to ML-DSA verify as (msg, ctx) — library handles SHAKE256 internally.
 *
 * TESTNET NOTICE (HIGH-1):
 *   The signing digest covers tx_hash only, not all witnesses. This is safe for
 *   testnet (tx_hash is unique per transaction, preventing direct replay) but
 *   does not implement the full RFC-0024 sighash-all covering co-signed witnesses.
 *   Fix before mainnet: hash all witnesses in the script group alongside tx_hash.
 */

#include "ckb_syscalls.h"
#include "blake2b.h"
#include "molecule/blockchain.h"
#include "mldsa_params.h"
#include "mldsa_adapter.h"

#ifdef DEBUG_BUILD
/* Print label + hex bytes to ckb-debugger stderr via ckb_debug syscall.
 * Limited to 32 bytes of data (covers tx_hash, signing_msg, pubkey_hash). */
static void dbg_hex(const char *label, const uint8_t *data, size_t len) {
    static const char HEX[] = "0123456789abcdef";
    char buf[128];
    size_t pos = 0;
    for (const char *s = label; *s && pos < 20; s++) buf[pos++] = *s;
    buf[pos++] = ':'; buf[pos++] = ' ';
    if (len > 32) len = 32;
    for (size_t i = 0; i < len && pos + 2 < 127; i++) {
        buf[pos++] = HEX[data[i] >> 4];
        buf[pos++] = HEX[data[i] & 0xf];
    }
    buf[pos] = '\0';
    ckb_debug(buf);
}
#define DBG_HEX(lbl, ptr, n) dbg_hex(lbl, ptr, n)
#else
#define DBG_HEX(lbl, ptr, n) (void)0
#endif

/*
 * Portable little-endian uint32 read from unaligned byte pointer.
 * Avoids UB from casting uint8_t* to uint32_t* (HIGH-4).
 */
static inline uint32_t read_u32_le(const uint8_t *p) {
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

/*
 * Constant-time byte comparison. Returns 0 iff a[0..n-1] == b[0..n-1].
 * All n bytes are always examined regardless of content (CRIT-2).
 */
static int ct_memcmp(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) diff |= a[i] ^ b[i];
    return (int)diff;
}

/*
 * Manual MldsaWitness parsing — Molecule table layout:
 *   full_len(4) | field_offsets(4 * 6) | field_data
 * Fields: version(1), algo_id(1), param_id(1), flags(1), pubkey(Bytes), sig(Bytes)
 *
 * All offset arithmetic uses size_t to prevent uint32_t overflow (CRIT-3).
 * All multi-byte reads use read_u32_le (HIGH-4).
 */
#define MLDSA_WIT_HEADER_SIZE  (4 + 4 * 6)  /* full_size(4) + 6 field offsets */

static int parse_mldsa_witness(
    const uint8_t *buf, size_t len,
    uint8_t *out_version, uint8_t *out_algo,
    uint8_t *out_param, uint8_t *out_flags,
    const uint8_t **out_pubkey, size_t *out_pubkey_len,
    const uint8_t **out_sig,    size_t *out_sig_len
) {
    if (len < MLDSA_WIT_HEADER_SIZE) return ERROR_WITNESS_MALFORMED;

    uint32_t total_len = read_u32_le(buf);
    if ((size_t)total_len != len) return ERROR_WITNESS_MALFORMED;

    /* Field offsets — read as individual u32 LE values (HIGH-4) */
    size_t f0 = (size_t)read_u32_le(buf + 4);
    size_t f1 = (size_t)read_u32_le(buf + 8);
    size_t f2 = (size_t)read_u32_le(buf + 12);
    size_t f3 = (size_t)read_u32_le(buf + 16);
    size_t f4 = (size_t)read_u32_le(buf + 20);
    size_t f5 = (size_t)read_u32_le(buf + 24);

    /* All arithmetic below is in size_t — no uint32 overflow (CRIT-3) */

    if (f0 + 1 > len) return ERROR_WITNESS_MALFORMED;
    *out_version = buf[f0];

    if (f1 + 1 > len) return ERROR_WITNESS_MALFORMED;
    *out_algo = buf[f1];

    if (f2 + 1 > len) return ERROR_WITNESS_MALFORMED;
    *out_param = buf[f2];

    if (f3 + 1 > len) return ERROR_WITNESS_MALFORMED;
    *out_flags = buf[f3];

    /* pubkey: Bytes field = 4-byte LE length prefix + data */
    if (f4 + 4 > len) return ERROR_WITNESS_MALFORMED;
    size_t pubkey_len = (size_t)read_u32_le(buf + f4);
    if (f4 + 4 + pubkey_len > len) return ERROR_WITNESS_MALFORMED;
    *out_pubkey     = buf + f4 + 4;
    *out_pubkey_len = pubkey_len;

    /* signature: Bytes field */
    if (f5 + 4 > len) return ERROR_WITNESS_MALFORMED;
    size_t sig_len = (size_t)read_u32_le(buf + f5);
    if (f5 + 4 + sig_len > len) return ERROR_WITNESS_MALFORMED;
    *out_sig     = buf + f5 + 4;
    *out_sig_len = sig_len;

    return CKB_SUCCESS;
}

/* Maximum witness buffer: pubkey + sig + Molecule overhead (generously sized) */
#define MAX_WITNESS_LEN  (MLDSA65_PUBLICKEY_BYTES + MLDSA65_SIGNATURE_BYTES + 512)
#define BLAKE2B_BLOCK_SIZE 32
#define MAX_TX_HASH_LEN  32

static uint8_t g_witness_buf[MAX_WITNESS_LEN];
static uint8_t g_signing_msg[BLAKE2B_BLOCK_SIZE];

/*
 * Build the CKB-MLDSA signing digest:
 *   blake2b_256("CKB-MLDSA-LOCK" || tx_hash)
 *
 * Uses ckb_checked_load_tx_hash and validates exact 32-byte return (CRIT-1).
 */
static int build_signing_message(uint8_t *out32) {
    uint8_t tx_hash[MAX_TX_HASH_LEN];
    uint64_t hash_len = MAX_TX_HASH_LEN;

    int ret = ckb_checked_load_tx_hash(tx_hash, &hash_len, 0);
    if (ret != CKB_SUCCESS) return ERROR_MESSAGE_BUILD;
    if (hash_len != MAX_TX_HASH_LEN) return ERROR_MESSAGE_BUILD;

    DBG_HEX("tx_hash", tx_hash, 32);

    blake2b_state ctx;
    blake2b_init(&ctx, BLAKE2B_BLOCK_SIZE);
    blake2b_update(&ctx, CKB_MLDSA_DOMAIN, CKB_MLDSA_DOMAIN_LEN);
    blake2b_update(&ctx, tx_hash, hash_len);
    blake2b_final(&ctx, out32, BLAKE2B_BLOCK_SIZE);

    DBG_HEX("signing_msg", out32, 32);

    return CKB_SUCCESS;
}

/* Script buffer: code_hash(32) + hash_type(1) + args_length_prefix(4) + args + slack */
#define MAX_SCRIPT_LEN (32 + 1 + 4 + ARGS_TOTAL_LEN + 32)

static uint8_t g_script_buf[MAX_SCRIPT_LEN];
static uint8_t g_lock_buf[MAX_WITNESS_LEN];

int main() {
    /* 1. Load and validate script args */
    uint64_t script_len = MAX_SCRIPT_LEN;
    int ret = ckb_checked_load_script(g_script_buf, &script_len, 0);
    if (ret != CKB_SUCCESS) return ret;

    mol_seg_t script_seg = {g_script_buf, (mol_num_t)script_len};
    if (MolReader_Script_verify(&script_seg, false) != MOL_OK) return ERROR_ARGS_LEN;

    mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
    /* args_seg is a Bytes field: 4-byte LE length prefix + data */
    if (args_seg.size < 4 + ARGS_TOTAL_LEN) return ERROR_ARGS_LEN;
    if (read_u32_le(args_seg.ptr) != ARGS_TOTAL_LEN) return ERROR_ARGS_LEN;
    const uint8_t *args = args_seg.ptr + 4;

    if (args[ARGS_VERSION_OFFSET] != WITNESS_VERSION)  return ERROR_INVALID_VERSION;
    if (args[ARGS_ALGO_OFFSET]    != ALGO_ID_MLDSA)    return ERROR_INVALID_ALGO;
    if (args[ARGS_PARAM_OFFSET]   != PARAM_ID_MLDSA65) return ERROR_INVALID_PARAM;

    const uint8_t *expected_pubkey_hash = args + ARGS_PUBKEY_HASH_OFFSET;

    /* 2. Load first witness in the script group (ckb_checked to detect truncation) */
    uint64_t wit_len = MAX_WITNESS_LEN;
    ret = ckb_checked_load_witness(g_witness_buf, &wit_len, 0, 0,
                                   CKB_SOURCE_GROUP_INPUT);
    if (ret != CKB_SUCCESS) return ERROR_WITNESS_MALFORMED;

    /* 3. Verify and parse WitnessArgs, then extract lock field */
    mol_seg_t wit_seg = {g_witness_buf, (mol_num_t)wit_len};
    if (MolReader_WitnessArgs_verify(&wit_seg, false) != MOL_OK) {
        return ERROR_WITNESS_MALFORMED;
    }

    mol_seg_t lock_opt = MolReader_WitnessArgs_get_lock(&wit_seg);

    /* lock_opt is BytesOpt: None = size 0; Some(Bytes) = 4-byte LE length + data */
    if (MolReader_BytesOpt_is_none(&lock_opt)) return ERROR_WITNESS_MALFORMED;
    if (lock_opt.size < 4) return ERROR_WITNESS_MALFORMED;

    /* Validate lock_opt.ptr is within the witness buffer (HIGH-3) */
    if (lock_opt.ptr < g_witness_buf ||
        lock_opt.ptr + lock_opt.size > g_witness_buf + (size_t)wit_len) {
        return ERROR_WITNESS_MALFORMED;
    }

    /* Bytes encoding: length at offset 0, data at offset 4 */
    size_t lock_data_len = (size_t)read_u32_le(lock_opt.ptr);
    const uint8_t *lock_data = lock_opt.ptr + 4;

    /* Validate in size_t to prevent overflow (CRIT-3) */
    if (4 + lock_data_len > (size_t)lock_opt.size) {
        return ERROR_WITNESS_MALFORMED;
    }
    if (lock_data_len > MAX_WITNESS_LEN) return ERROR_WITNESS_MALFORMED;

    /* Copy lock bytes to a dedicated buffer for parsing */
    for (size_t i = 0; i < lock_data_len; i++) g_lock_buf[i] = lock_data[i];

    /* 4. Parse MldsaWitness from lock bytes */
    uint8_t wit_version, wit_algo, wit_param, wit_flags;
    const uint8_t *pubkey = NULL, *sig = NULL;
    size_t pubkey_len = 0, sig_len = 0;

    ret = parse_mldsa_witness(g_lock_buf, lock_data_len,
        &wit_version, &wit_algo, &wit_param, &wit_flags,
        &pubkey, &pubkey_len, &sig, &sig_len);
    if (ret != CKB_SUCCESS) return ret;

    if (wit_version != WITNESS_VERSION)  return ERROR_INVALID_VERSION;
    if (wit_algo    != ALGO_ID_MLDSA)    return ERROR_INVALID_ALGO;
    if (wit_param   != PARAM_ID_MLDSA65) return ERROR_INVALID_PARAM;
    if (wit_flags   != 0x00)             return ERROR_WITNESS_MALFORMED;  /* reserved, must be 0 */
    if (pubkey_len  != MLDSA65_PUBLICKEY_BYTES) return ERROR_WITNESS_MALFORMED;
    if (sig_len     != MLDSA65_SIGNATURE_BYTES) return ERROR_WITNESS_MALFORMED;

    /* 5. Verify pubkey hash matches args — constant-time comparison (CRIT-2) */
    uint8_t computed_hash[BLAKE2B_BLOCK_SIZE];
    blake2b_state bctx;
    blake2b_init(&bctx, BLAKE2B_BLOCK_SIZE);
    blake2b_update(&bctx, pubkey, pubkey_len);
    blake2b_final(&bctx, computed_hash, BLAKE2B_BLOCK_SIZE);

    if (ct_memcmp(computed_hash, expected_pubkey_hash, ARGS_PUBKEY_HASH_LEN) != 0) {
        return ERROR_PUBKEY_HASH_MISMATCH;
    }

    /* 6. Build signing message */
    ret = build_signing_message(g_signing_msg);
    if (ret != CKB_SUCCESS) return ret;

    /* 7. Verify ML-DSA-65 signature */
    DBG_HEX("calling_verify", g_signing_msg, 32);

    ret = mldsa65_verify(pubkey,
        g_signing_msg, BLAKE2B_BLOCK_SIZE,
        (const uint8_t *)CKB_MLDSA_DOMAIN, CKB_MLDSA_DOMAIN_LEN,
        sig, sig_len);

    DBG_HEX("verify_ret", (const uint8_t *)&ret, 4);

    if (ret != 0) return ERROR_INVALID_SIGNATURE;

    return CKB_SUCCESS;
}
