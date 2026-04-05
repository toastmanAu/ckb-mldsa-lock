#ifndef MLDSA_PARAMS_H
#define MLDSA_PARAMS_H

// ML-DSA-65 (FIPS 204) fixed sizes
#define MLDSA65_PUBLICKEY_BYTES  1952
#define MLDSA65_SIGNATURE_BYTES  3309
#define MLDSA65_SECRETKEY_BYTES  4032  // not used on-chain

// Args layout: version(1) | algo_id(1) | param_id(1) | reserved(1) | blake2b_256(pubkey)(32)
#define ARGS_VERSION_OFFSET   0
#define ARGS_ALGO_OFFSET      1
#define ARGS_PARAM_OFFSET     2
#define ARGS_RESERVED_OFFSET  3
#define ARGS_PUBKEY_HASH_OFFSET 4
#define ARGS_PUBKEY_HASH_LEN  32
#define ARGS_TOTAL_LEN        36

// Algo/param IDs
#define ALGO_ID_MLDSA    0x02
#define PARAM_ID_MLDSA65 0x02
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
