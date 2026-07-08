#ifndef MLDSA_PARAMS_H
#define MLDSA_PARAMS_H

/*
 * ML-DSA parameters, selected at build time via -DMLD_CONFIG_PARAMETER_SET.
 *
 * Supported values:
 *   44  -> ML-DSA-44 (NIST level 2, pk=1312, sig=2420, param_id=0x01)
 *   65  -> ML-DSA-65 (NIST level 3, pk=1952, sig=3309, param_id=0x02)  [default]
 *   87  -> ML-DSA-87 (NIST level 5, pk=2592, sig=4627, param_id=0x03)
 *
 * The Makefile picks one variant per build. Two binaries are produced from
 * the same source tree: build/mldsa-lock (default -65) and any other variant
 * you build with `make MLDSA_PARAM=44` etc.
 */

#ifndef MLD_CONFIG_PARAMETER_SET
#define MLD_CONFIG_PARAMETER_SET 65
#endif

#if MLD_CONFIG_PARAMETER_SET == 44
#define MLDSA_PUBLICKEY_BYTES  1312
#define MLDSA_SIGNATURE_BYTES  2420
#define MLDSA_SECRETKEY_BYTES  2560
#define MLDSA_PARAM_ID         0x01
#define MLDSA_VARIANT_STR      "ML-DSA-44"
#elif MLD_CONFIG_PARAMETER_SET == 65
#define MLDSA_PUBLICKEY_BYTES  1952
#define MLDSA_SIGNATURE_BYTES  3309
#define MLDSA_SECRETKEY_BYTES  4032
#define MLDSA_PARAM_ID         0x02
#define MLDSA_VARIANT_STR      "ML-DSA-65"
#elif MLD_CONFIG_PARAMETER_SET == 87
#define MLDSA_PUBLICKEY_BYTES  2592
#define MLDSA_SIGNATURE_BYTES  4627
#define MLDSA_SECRETKEY_BYTES  4896
#define MLDSA_PARAM_ID         0x03
#define MLDSA_VARIANT_STR      "ML-DSA-87"
#else
#error "Unsupported MLD_CONFIG_PARAMETER_SET (must be 44, 65, or 87)"
#endif

/* Legacy aliases — do NOT use in new code. Kept so other tooling (Rust SDK,
 * test vectors, deployment scripts) that still references the MLDSA65_*
 * names keeps working until they're updated alongside this refactor. */
#define MLDSA65_PUBLICKEY_BYTES  1952
#define MLDSA65_SIGNATURE_BYTES  3309
#define MLDSA65_SECRETKEY_BYTES  4032
#define PARAM_ID_MLDSA65         0x02

// Args layout: version(1) | algo_id(1) | param_id(1) | reserved(1) | blake2b_256(pubkey)(32)
#define ARGS_VERSION_OFFSET   0
#define ARGS_ALGO_OFFSET      1
#define ARGS_PARAM_OFFSET     2
#define ARGS_RESERVED_OFFSET  3
#define ARGS_PUBKEY_HASH_OFFSET 4
#define ARGS_PUBKEY_HASH_LEN  32
#define ARGS_TOTAL_LEN        36

// Algo ID (same for all ML-DSA variants; param_id distinguishes security level)
#define ALGO_ID_MLDSA    0x02
#define WITNESS_VERSION  0x01

// Domain separator for CKB signing message
#define CKB_MLDSA_DOMAIN "CKB-MLDSA-LOCK"
#define CKB_MLDSA_DOMAIN_LEN 14

// Error codes
#define ERROR_ARGS_LEN           1
#define ERROR_INVALID_VERSION    2
#define ERROR_INVALID_ALGO       3
#define ERROR_INVALID_PARAM      4
#define ERROR_WITNESS_MALFORMED  5
#define ERROR_PUBKEY_HASH_MISMATCH 6
#define ERROR_INVALID_SIGNATURE  7
#define ERROR_MESSAGE_BUILD      8
#define ERROR_ENCODING           9

#endif // MLDSA_PARAMS_H
