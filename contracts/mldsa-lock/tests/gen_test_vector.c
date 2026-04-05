/*
 * gen_test_vector.c
 *
 * Native x86_64 tool: generates a complete ckb-debugger mock transaction JSON
 * for testing the CKB ML-DSA-65 lock script.
 *
 * Build:
 *   gcc -O2 -I../vendor/mldsa-native/mldsa -I../vendor/mldsa-native/mldsa/src \
 *       -DMLD_CONFIG_PARAMETER_SET=65 -DMLDSA_NATIVE_PORTABLE=1 \
 *       -DMLDSA_RANDOMIZED_SIGNING=0 \
 *       gen_test_vector.c ../vendor/mldsa-native/mldsa/mldsa_native.c \
 *       -o gen_test_vector
 *
 * Usage:
 *   ./gen_test_vector > mock_tx.json
 *   ckb-debugger --mode fast --tx-file mock_tx.json --script input.0.lock \
 *                --bin ../build/mldsa-lock
 */

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

/* randombytes for keygen — reads from /dev/urandom */
int randombytes(uint8_t *out, size_t outlen) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return -1;
    size_t r = fread(out, 1, outlen, f);
    fclose(f);
    return (r == outlen) ? 0 : -1;
}

#define MLD_CONFIG_PARAMETER_SET 65
#define MLDSA_NATIVE_PORTABLE    1
#define MLDSA_RANDOMIZED_SIGNING 0

#include "mldsa_native.h"

/* ── sizes ────────────────────────────────────────────────────────── */
#define MLDSA65_PUBLICKEY_BYTES  1952
#define MLDSA65_SIGNATURE_BYTES  3309
#define MLDSA65_SECRETKEY_BYTES  4032

#define CKB_MLDSA_DOMAIN     "CKB-MLDSA-LOCK"
#define CKB_MLDSA_DOMAIN_LEN 14

#define BLAKE2B_OUTLEN 32

/* ── tiny blake2b (header-only from ckb-c-stdlib) ─────────────────── */
/* We copy just what we need inline rather than dragging in the whole   */
/* ckb stdlib. Use the reference blake2b from the BLAKE2 spec.          */

typedef uint64_t  u64;
typedef uint32_t  u32;
typedef uint8_t   u8;

static const u64 blake2b_IV[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};
static const u8 blake2b_sigma[12][16] = {
    {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},
    {14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3},
    {11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4},
    {7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8},
    {9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13},
    {2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9},
    {12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11},
    {13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10},
    {6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5},
    {10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0},
    {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},
    {14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3}
};

typedef struct { u64 h[8]; u64 t[2]; u64 f[2]; u8 buf[128]; size_t buflen; size_t outlen; } blake2b_state;

#define ROTR64(x,n) (((x)>>(n))|((x)<<(64-(n))))
#define G(a,b,c,d,x,y) \
    v[a]+=v[b]+(x); v[d]=ROTR64(v[d]^v[a],32); \
    v[c]+=v[d];     v[b]=ROTR64(v[b]^v[c],24); \
    v[a]+=v[b]+(y); v[d]=ROTR64(v[d]^v[a],16); \
    v[c]+=v[d];     v[b]=ROTR64(v[b]^v[c],63);

static void blake2b_compress(blake2b_state *S, const u8 block[128]) {
    u64 m[16], v[16];
    for (int i=0;i<16;i++) {
        m[i]=0;
        for (int j=0;j<8;j++) m[i]|=((u64)block[i*8+j])<<(j*8);
    }
    for (int i=0;i<8;i++) { v[i]=S->h[i]; v[i+8]=blake2b_IV[i]; }
    v[12]^=S->t[0]; v[13]^=S->t[1]; v[14]^=S->f[0]; v[15]^=S->f[1];
    for (int r=0;r<12;r++) {
        const u8 *s=blake2b_sigma[r];
        G(0,4,8,12, m[s[0]],m[s[1]]); G(1,5,9,13, m[s[2]],m[s[3]]);
        G(2,6,10,14,m[s[4]],m[s[5]]); G(3,7,11,15,m[s[6]],m[s[7]]);
        G(0,5,10,15,m[s[8]],m[s[9]]); G(1,6,11,12,m[s[10]],m[s[11]]);
        G(2,7,8,13, m[s[12]],m[s[13]]); G(3,4,9,14,m[s[14]],m[s[15]]);
    }
    for (int i=0;i<8;i++) S->h[i]^=v[i]^v[i+8];
}
static void blake2b_increment_counter(blake2b_state *S, u64 inc) { S->t[0]+=inc; if(S->t[0]<inc) S->t[1]++; }
/*
 * Init with blake2b parameter block.
 * personalization = "ckb-default-hash" (16 bytes, zero-padded to 16).
 * The blake2b parameter block is 64 bytes; personalization occupies bytes 48-63.
 * Each word in h[] = IV[i] XOR param_block_word[i].
 * Words 6 and 7 XOR with the personalization bytes (little-endian u64).
 */
static void b2b_init(blake2b_state *S, size_t outlen) {
    /* "ckb-default-hash" as two little-endian u64 words */
    static const char PERSONAL[16] = "ckb-default-hash";
    u64 p6 = 0, p7 = 0;
    for (int i=0;i<8;i++) p6 |= ((u64)(u8)PERSONAL[i])   << (i*8);
    for (int i=0;i<8;i++) p7 |= ((u64)(u8)PERSONAL[8+i]) << (i*8);

    memset(S,0,sizeof(*S));
    for (int i=0;i<8;i++) S->h[i]=blake2b_IV[i];
    /* param block: digest_len=outlen, fanout=1, depth=1, personalization at bytes 48-63 */
    S->h[0] ^= 0x01010000ULL ^ ((u64)outlen);
    S->h[6] ^= p6;
    S->h[7] ^= p7;
    S->outlen=outlen;
}
static void b2b_update(blake2b_state *S, const void *in, size_t inlen) {
    const u8 *p=in;
    while (inlen>0) {
        size_t left=S->buflen, fill=128-left;
        if (inlen>fill) {
            S->buflen=0;
            memcpy(S->buf+left,p,fill);
            blake2b_increment_counter(S,(u64)128);
            blake2b_compress(S,S->buf);
            p+=fill; inlen-=fill;
        } else {
            memcpy(S->buf+S->buflen,p,inlen);
            S->buflen+=inlen; inlen=0;
        }
    }
}
static void b2b_final(blake2b_state *S, u8 *out, size_t outlen) {
    u8 tmp[64]; memset(tmp,0,64);
    blake2b_increment_counter(S,(u64)S->buflen);
    S->f[0]=(u64)-1;
    memset(S->buf+S->buflen,0,128-S->buflen);
    blake2b_compress(S,S->buf);
    for (int i=0;i<8;i++) for (int j=0;j<8;j++) tmp[i*8+j]=(u8)(S->h[i]>>(j*8));
    memcpy(out,tmp,outlen);
}

/* ── Molecule serialisation helpers ──────────────────────────────── */

static void write_u32_le(uint8_t *buf, uint32_t v);  /* forward decl */

/*
 * Compute the CKB tx_hash for the mock transaction in this file.
 * tx_hash = ckb_blake2b(molecule_encode(RawTransaction))
 *
 * RawTransaction layout (all fields fixed/constant except prev_out_tx_hash):
 *   version        = 0
 *   cell_deps      = [CellDep{out_point:{0x00..01,0}, dep_type:code}]
 *   header_deps    = []
 *   inputs         = [CellInput{since:0, previous_output:{prev_out_tx_hash,0}}]
 *   outputs        = [CellOutput{cap:0x174876e800, lock:Script{0x00..00,data,0x}, type:None}]
 *   outputs_data   = [Bytes{0x}]
 *
 * Molecule layout (RawTransaction is a table, 6 fields, total = 222 bytes):
 *   header:  total_size(4) + 6 offsets(4) = 28 bytes
 *   off[0]=28  version       : Uint32 LE       = 4 bytes
 *   off[1]=32  cell_deps     : fixvec<CellDep> = 4 + 37 = 41 bytes
 *   off[2]=73  header_deps   : fixvec<Byte32>  = 4 bytes
 *   off[3]=77  inputs        : fixvec<CellInput>= 4 + 44 = 48 bytes
 *   off[4]=125 outputs       : dynvec<CellOutput>= 4+1*4+77 = 85 bytes
 *   off[5]=210 outputs_data  : dynvec<Bytes>   = 4+1*4+4  = 12 bytes
 *   total = 222 bytes
 *
 * Molecule dynvec<T> with N items: total_size(4) + N offsets(4) + items.
 * N=1: total_size(4) + 1 offset(4) + item, where offset[0] = 8.
 */
static void compute_mock_tx_hash(const uint8_t *prev_out_tx_hash, uint8_t *out_hash)
{
    uint8_t buf[256];
    uint8_t *p = buf;

    /* ── RawTransaction table header ───────────────────────────────── */
    write_u32_le(p, 222); p += 4;   /* total_size */
    write_u32_le(p,  28); p += 4;   /* off[0]: version */
    write_u32_le(p,  32); p += 4;   /* off[1]: cell_deps */
    write_u32_le(p,  73); p += 4;   /* off[2]: header_deps */
    write_u32_le(p,  77); p += 4;   /* off[3]: inputs */
    write_u32_le(p, 125); p += 4;   /* off[4]: outputs */
    write_u32_le(p, 210); p += 4;   /* off[5]: outputs_data */

    /* ── version: Uint32 = 0 ─── (p=28) */
    write_u32_le(p, 0); p += 4;

    /* ── cell_deps: fixvec<CellDep>, 1 item ─── (p=32) */
    write_u32_le(p, 1); p += 4;      /* item_count */
    memset(p, 0, 31); p += 31;        /* out_point.tx_hash bytes 0..30 */
    *p++ = 0x01;                       /* out_point.tx_hash byte 31 */
    write_u32_le(p, 0); p += 4;       /* out_point.index = 0 */
    *p++ = 0;                          /* dep_type = code(0) */
    /* p=73 */

    /* ── header_deps: fixvec<Byte32>, 0 items ─── (p=73) */
    write_u32_le(p, 0); p += 4;
    /* p=77 */

    /* ── inputs: fixvec<CellInput>, 1 item ─── (p=77) */
    write_u32_le(p, 1); p += 4;      /* item_count */
    memset(p, 0, 8); p += 8;          /* since = 0 (uint64 LE) */
    memcpy(p, prev_out_tx_hash, 32); p += 32;  /* previous_output.tx_hash */
    write_u32_le(p, 0); p += 4;       /* previous_output.index = 0 */
    /* p=125 */

    /* ── outputs: dynvec<CellOutput>, 1 item ─── (p=125) */
    /* dynvec with 1 item: total_size(4) + 1 offset(4) + item.
     * offset[0] = 8 (item starts immediately after size + offset). */
    write_u32_le(p, 85); p += 4;   /* CellOutputVec total = 8 + 77 = 85 */
    write_u32_le(p,  8); p += 4;   /* offset[0] = 8 */
    /* CellOutput table: total=77, offsets=[16,24,77] */
    write_u32_le(p, 77); p += 4;
    write_u32_le(p, 16); p += 4;   /* off[0]: capacity */
    write_u32_le(p, 24); p += 4;   /* off[1]: lock Script */
    write_u32_le(p, 77); p += 4;   /* off[2]: type (ScriptOpt::None = 0 bytes) */
    /* capacity: uint64 LE = 0x174876e800 */
    { uint64_t cap = 0x174876e800ULL;
      for (int i = 0; i < 8; i++) *p++ = (uint8_t)(cap >> (i * 8)); }
    /* lock Script table: total=53, offsets=[16,48,49] */
    write_u32_le(p, 53); p += 4;
    write_u32_le(p, 16); p += 4;   /* off[0]: code_hash */
    write_u32_le(p, 48); p += 4;   /* off[1]: hash_type */
    write_u32_le(p, 49); p += 4;   /* off[2]: args Bytes */
    memset(p, 0, 32); p += 32;     /* code_hash = 0x00..00 */
    *p++ = 0;                       /* hash_type = data(0) */
    write_u32_le(p, 0); p += 4;    /* args Bytes: length=0 */
    /* p=210 */

    /* ── outputs_data: dynvec<Bytes>, 1 item ─── (p=210) */
    /* dynvec with 1 empty Bytes item: total=12, offset[0]=8, length=0 */
    write_u32_le(p, 12); p += 4;   /* total_size */
    write_u32_le(p,  8); p += 4;   /* offset[0] = 8 */
    write_u32_le(p,  0); p += 4;   /* Bytes item: length=0 */
    /* p=222 */

    blake2b_state ctx;
    b2b_init(&ctx, BLAKE2B_OUTLEN);
    b2b_update(&ctx, buf, (size_t)(p - buf));
    b2b_final(&ctx, out_hash, BLAKE2B_OUTLEN);
}


static void write_u32_le(uint8_t *buf, uint32_t v) {
    buf[0]=(uint8_t)(v);  buf[1]=(uint8_t)(v>>8);
    buf[2]=(uint8_t)(v>>16); buf[3]=(uint8_t)(v>>24);
}

/*
 * Serialize MldsaWitness as a Molecule table:
 *   header:   total_len(4) + 6 offsets × 4 = 28 bytes
 *   field[0]: version  (1 byte)
 *   field[1]: algo_id  (1 byte)
 *   field[2]: param_id (1 byte)
 *   field[3]: flags    (1 byte)
 *   field[4]: pubkey   (4-byte LE len prefix + 1952 bytes)
 *   field[5]: sig      (4-byte LE len prefix + 3309 bytes)
 */
#define MLDSA_WIT_HDR  (4 + 6*4)  /* 28 */
#define MLDSA_WIT_TOTAL (MLDSA_WIT_HDR + 1+1+1+1 + 4+MLDSA65_PUBLICKEY_BYTES + 4+MLDSA65_SIGNATURE_BYTES)

static void serialize_mldsa_witness(
    uint8_t *out,
    uint8_t version, uint8_t algo, uint8_t param, uint8_t flags,
    const uint8_t *pubkey, const uint8_t *sig
) {
    uint32_t total = MLDSA_WIT_TOTAL;
    write_u32_le(out, total);  /* full_size */

    /* field offsets (absolute positions from start of table) */
    uint32_t off = MLDSA_WIT_HDR;
    write_u32_le(out + 4,  off); off += 1; /* version */
    write_u32_le(out + 8,  off); off += 1; /* algo_id */
    write_u32_le(out + 12, off); off += 1; /* param_id */
    write_u32_le(out + 16, off); off += 1; /* flags */
    write_u32_le(out + 20, off); off += 4 + MLDSA65_PUBLICKEY_BYTES; /* pubkey */
    write_u32_le(out + 24, off); /* sig — no need to advance */

    uint8_t *p = out + MLDSA_WIT_HDR;
    *p++ = version;
    *p++ = algo;
    *p++ = param;
    *p++ = flags;
    write_u32_le(p, MLDSA65_PUBLICKEY_BYTES); p += 4;
    memcpy(p, pubkey, MLDSA65_PUBLICKEY_BYTES); p += MLDSA65_PUBLICKEY_BYTES;
    write_u32_le(p, MLDSA65_SIGNATURE_BYTES);  p += 4;
    memcpy(p, sig, MLDSA65_SIGNATURE_BYTES);
}

/*
 * Serialize WitnessArgs as a Molecule table with only the lock field set.
 *   header: total_len(4) + 3 offsets × 4 = 16 bytes
 *   field[0]: lock (BytesOpt = Some(Bytes) = 4-byte presence + 4-byte len + data)
 *   field[1]: input_type  (BytesOpt::None = 0 bytes)
 *   field[2]: output_type (BytesOpt::None = 0 bytes)
 *
 * BytesOpt::Some(x) = the Bytes encoding: 4-byte LE total (including header) + data
 * Actually in Molecule, BytesOpt::Some wraps a Bytes, so the field bytes =
 *   presence_byte(1) + Bytes { len(4) + data }
 * No wait — in ckb Molecule, BytesOpt is just `option Bytes` which is encoded
 * as 0 bytes when None, or the Bytes encoding when Some (no prefix byte).
 * Bytes = 4-byte LE length + raw bytes.
 */
static uint8_t *serialize_witness_args(
    const uint8_t *lock_data, uint32_t lock_data_len,
    uint32_t *out_len
) {
    /* WitnessArgs Molecule table:
     *   total_len(4) + offset[0](4) + offset[1](4) + offset[2](4) = 16 header bytes
     *   field[0] = Bytes { lock_data_len(4) + lock_data }   = 4 + lock_data_len bytes
     *   field[1] = (absent)
     *   field[2] = (absent)
     */
    uint32_t hdr     = 4 + 3*4;  /* 16 */
    uint32_t f0_size = 4 + lock_data_len;
    uint32_t total   = hdr + f0_size;

    uint8_t *buf = (uint8_t *)malloc(total);
    if (!buf) { fprintf(stderr, "OOM\n"); exit(1); }

    write_u32_le(buf, total);
    uint32_t off = hdr;
    write_u32_le(buf + 4, off);  off += f0_size;  /* lock field starts at hdr */
    write_u32_le(buf + 8, off);                    /* input_type (empty) */
    write_u32_le(buf + 12, off);                   /* output_type (empty) */

    write_u32_le(buf + hdr, lock_data_len);
    memcpy(buf + hdr + 4, lock_data, lock_data_len);

    *out_len = total;
    return buf;
}

/* ── hex helpers ──────────────────────────────────────────────────── */
static void print_hex(const uint8_t *data, size_t len) {
    printf("0x");
    for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
}
static void fprint_hex(FILE *f, const uint8_t *data, size_t len) {
    fprintf(f, "0x");
    for (size_t i = 0; i < len; i++) fprintf(f, "%02x", data[i]);
}

/*
 * Load contract binary from path.
 * Returns heap-allocated buffer (caller must free) and sets *out_len.
 * Computes blake2b_256(data) → code_hash (for hash_type "data1").
 */
static uint8_t *load_binary(const char *path, size_t *out_len, uint8_t *code_hash) {
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "cannot open binary: %s\n", path); return NULL; }
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return NULL; }
    uint8_t *buf = (uint8_t *)malloc((size_t)sz);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) { free(buf); fclose(f); return NULL; }
    fclose(f);
    *out_len = (size_t)sz;
    blake2b_state ctx;
    b2b_init(&ctx, BLAKE2B_OUTLEN);
    b2b_update(&ctx, buf, (size_t)sz);
    b2b_final(&ctx, code_hash, BLAKE2B_OUTLEN);
    return buf;
}

/* ── main ─────────────────────────────────────────────────────────── */
int main(int argc, char **argv) {
    int expect_fail = (argc > 1 && strcmp(argv[1], "--fail") == 0);
    /* optional: path to contract binary (default: ../build/mldsa-lock) */
    const char *bin_path = "../build/mldsa-lock";
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--bin") == 0 && i+1 < argc) bin_path = argv[++i];
    }

    /* ── 1. Keygen ─────────────────────────────────────────────── */
    uint8_t pk[MLDSA65_PUBLICKEY_BYTES];
    uint8_t sk[MLDSA65_SECRETKEY_BYTES];
    int rc = PQCP_MLDSA_NATIVE_MLDSA65_keypair(pk, sk);
    if (rc != 0) { fprintf(stderr, "keygen failed: %d\n", rc); return 1; }
    fprintf(stderr, "[gen] keygen OK\n");

    /* ── 2. Load contract binary and compute its code_hash ─────── */
    uint8_t code_hash[32];
    size_t  bin_size = 0;
    uint8_t *bin_data = load_binary(bin_path, &bin_size, code_hash);
    if (!bin_data) {
        fprintf(stderr, "[gen] WARNING: could not load binary %s — using dummy code_hash\n", bin_path);
        memset(code_hash, 0, 32); code_hash[31] = 0x01;
    }
    fprintf(stderr, "[gen] code_hash: ");
    for (int i=0;i<32;i++) fprintf(stderr,"%02x",code_hash[i]);
    fprintf(stderr," (%zu bytes)\n", bin_size);

    /* ── 3. Compute blake2b_256(pubkey) for lock args (loop variable reuse) ─ */
    uint8_t pubkey_hash[32];
    blake2b_state bctx;
    b2b_init(&bctx, 32);
    b2b_update(&bctx, pk, MLDSA65_PUBLICKEY_BYTES);
    b2b_final(&bctx, pubkey_hash, 32);
    fprintf(stderr, "[gen] pubkey_hash: ");
    for (int i=0;i<32;i++) fprintf(stderr,"%02x",pubkey_hash[i]);
    fprintf(stderr,"\n");

    /* ── 4. Fixed previous_output tx_hash (identifies the parent cell) ─── */
    /* This identifies the "parent" transaction that created the input cell.  */
    /* It is NOT the current transaction's hash — just an arbitrary fixed value. */
    uint8_t prev_out_tx_hash[32];
    memset(prev_out_tx_hash, 0xab, 32);

    /* ── 5. Compute the REAL tx_hash of this mock RawTransaction ─────── */
    /* ckb_load_tx_hash() in the VM returns blake2b(molecule_encode(RawTx)) */
    uint8_t tx_hash[32];
    compute_mock_tx_hash(prev_out_tx_hash, tx_hash);
    fprintf(stderr, "[gen] tx_hash (real):    ");
    for (int i=0;i<32;i++) fprintf(stderr,"%02x",tx_hash[i]);
    fprintf(stderr,"\n");

    /* ── 5. Build signing message: blake2b("CKB-MLDSA-LOCK" || tx_hash) ── */
    uint8_t msg[32];
    b2b_init(&bctx, 32);
    b2b_update(&bctx, CKB_MLDSA_DOMAIN, CKB_MLDSA_DOMAIN_LEN);
    b2b_update(&bctx, tx_hash, 32);
    b2b_final(&bctx, msg, 32);
    fprintf(stderr, "[gen] signing_msg: ");
    for (int i=0;i<32;i++) fprintf(stderr,"%02x",msg[i]);
    fprintf(stderr,"\n");

    /* ── 6. Sign (ctx = "CKB-MLDSA-LOCK") ────────────────────── */
    uint8_t ctx[] = CKB_MLDSA_DOMAIN;
    uint8_t sig[MLDSA65_SIGNATURE_BYTES];
    size_t  siglen = 0;
    rc = PQCP_MLDSA_NATIVE_MLDSA65_signature(sig, &siglen, msg, 32, ctx, CKB_MLDSA_DOMAIN_LEN, sk);
    if (rc != 0 || siglen != MLDSA65_SIGNATURE_BYTES) {
        fprintf(stderr, "sign failed: %d siglen=%zu\n", rc, siglen);
        return 1;
    }
    fprintf(stderr, "[gen] sign OK  siglen=%zu\n", siglen);

    /* ── 7. Self-verify signature before embedding ──────────────── */
    if (!expect_fail) {
        uint8_t ctx_v[] = CKB_MLDSA_DOMAIN;
        int vrc = PQCP_MLDSA_NATIVE_MLDSA65_verify(sig, siglen, msg, 32,
                                                     ctx_v, CKB_MLDSA_DOMAIN_LEN, pk);
        fprintf(stderr, "[gen] self-verify: %s (rc=%d)\n", vrc == 0 ? "OK" : "FAIL", vrc);
        if (vrc != 0) { fprintf(stderr, "FATAL: signature does not verify!\n"); return 1; }
    } else {
        /* Corrupt the signature to test the fail path */
        sig[0] ^= 0xFF;
        fprintf(stderr, "[gen] CORRUPTED sig[0] for fail test\n");
    }

    /* ── 8. Serialize MldsaWitness ─────────────────────────────── */
    uint8_t mldsa_wit[MLDSA_WIT_TOTAL];
    serialize_mldsa_witness(mldsa_wit, 0x01, 0x02, 0x02, 0x00, pk, sig);

    /* ── 8. Wrap in WitnessArgs.lock ──────────────────────────── */
    uint32_t wa_len;
    uint8_t *wit_args = serialize_witness_args(mldsa_wit, MLDSA_WIT_TOTAL, &wa_len);
    fprintf(stderr, "[gen] WitnessArgs len=%u\n", wa_len);

    /* ── 9. Build lock args: version|algo|param|reserved|pubkey_hash ── */
    uint8_t lock_args[36];
    lock_args[0] = 0x01;  /* version */
    lock_args[1] = 0x02;  /* algo_id = ML-DSA */
    lock_args[2] = 0x02;  /* param_id = ML-DSA-65 */
    lock_args[3] = 0x00;  /* reserved */
    memcpy(lock_args + 4, pubkey_hash, 32);

    /* ── 10. Emit ckb-debugger mock transaction JSON ─────────────── */
    /*
     * ckb-debugger 1.x mock transaction format:
     *   mock_info.inputs[]  = { "output": <cell>, "data": "0x" }
     *   mock_info.cell_deps[] = { "output": <cell>, "data": "0x<binary_hex>" }
     *   tx = { "outputs": [...], "witnesses": [...], "outputs_data": [...] }
     *
     * --bin overrides the binary for the script under test.
     * The code_hash in the lock must match the cell_dep binary (hash_type "data1").
     * Since --bin overrides, we use a placeholder code_hash.
     */
    printf("{\n");
    printf("  \"mock_info\": {\n");

    /* inputs: each entry needs "input" (outpoint), "output" (cell), and "data" */
    printf("    \"inputs\": [\n");
    printf("      {\n");
    printf("        \"input\": {\n");
    printf("          \"previous_output\": {\n");
    printf("            \"tx_hash\": \"");
    fprint_hex(stdout, prev_out_tx_hash, 32);
    printf("\",\n");
    printf("            \"index\": \"0x0\"\n");
    printf("          },\n");
    printf("          \"since\": \"0x0\"\n");
    printf("        },\n");
    printf("        \"output\": {\n");
    printf("          \"capacity\": \"0x174876e800\",\n");
    printf("          \"lock\": {\n");
    /* real code_hash = blake2b_256(binary) for hash_type "data1" */
    printf("            \"code_hash\": \"");
    fprint_hex(stdout, code_hash, 32);
    printf("\",\n");
    printf("            \"hash_type\": \"data1\",\n");
    printf("            \"args\": \"");
    fprint_hex(stdout, lock_args, 36);
    printf("\"\n");
    printf("          },\n");
    printf("          \"type\": null\n");
    printf("        },\n");
    printf("        \"data\": \"0x\"\n");
    printf("      }\n");
    printf("    ],\n");

    /* cell_deps: embed binary so ckb-debugger can resolve the lock script */
    printf("    \"cell_deps\": [\n");
    printf("      {\n");
    printf("        \"cell_dep\": {\n");
    printf("          \"out_point\": {\n");
    printf("            \"tx_hash\": \"0x0000000000000000000000000000000000000000000000000000000000000001\",\n");
    printf("            \"index\": \"0x0\"\n");
    printf("          },\n");
    printf("          \"dep_type\": \"code\"\n");
    printf("        },\n");
    printf("        \"output\": {\n");
    printf("          \"capacity\": \"0x174876e800\",\n");
    printf("          \"lock\": {\n");
    printf("            \"code_hash\": \"0x0000000000000000000000000000000000000000000000000000000000000000\",\n");
    printf("            \"hash_type\": \"data\",\n");
    printf("            \"args\": \"0x\"\n");
    printf("          },\n");
    printf("          \"type\": null\n");
    printf("        },\n");
    if (bin_data && bin_size > 0) {
        printf("        \"data\": \"");
        fprint_hex(stdout, bin_data, bin_size);
        printf("\"\n");
    } else {
        printf("        \"data\": \"0x\"\n");
    }
    printf("      }\n");
    printf("    ],\n");
    printf("    \"header_deps\": []\n");
    printf("  },\n");

    /* tx: the transaction being evaluated */
    printf("  \"tx\": {\n");
    printf("    \"version\": \"0x0\",\n");
    printf("    \"cell_deps\": [\n");
    printf("      {\n");
    printf("        \"out_point\": {\n");
    printf("          \"tx_hash\": \"0x0000000000000000000000000000000000000000000000000000000000000001\",\n");
    printf("          \"index\": \"0x0\"\n");
    printf("        },\n");
    printf("        \"dep_type\": \"code\"\n");
    printf("      }\n");
    printf("    ],\n");
    printf("    \"header_deps\": [],\n");
    printf("    \"inputs\": [\n");
    printf("      {\n");
    printf("        \"previous_output\": {\n");
    printf("          \"tx_hash\": \"");
    fprint_hex(stdout, prev_out_tx_hash, 32);
    printf("\",\n");
    printf("          \"index\": \"0x0\"\n");
    printf("        },\n");
    printf("        \"since\": \"0x0\"\n");
    printf("      }\n");
    printf("    ],\n");
    printf("    \"outputs\": [\n");
    printf("      {\n");
    printf("        \"capacity\": \"0x174876e800\",\n");
    printf("        \"lock\": {\n");
    printf("          \"code_hash\": \"0x0000000000000000000000000000000000000000000000000000000000000000\",\n");
    printf("          \"hash_type\": \"data\",\n");
    printf("          \"args\": \"0x\"\n");
    printf("        },\n");
    printf("        \"type\": null\n");
    printf("      }\n");
    printf("    ],\n");
    printf("    \"outputs_data\": [\"0x\"],\n");
    printf("    \"witnesses\": [\"");
    fprint_hex(stdout, wit_args, wa_len);
    printf("\"]\n");
    printf("  }\n");
    printf("}\n");

    free(wit_args);
    if (bin_data) free(bin_data);
    return 0;
}
