#ifndef MLDSA_ADAPTER_H
#define MLDSA_ADAPTER_H

#include <stdint.h>
#include <stddef.h>

/*
 * Thin adapter over mldsa-native standard verify path.
 *
 * Signer computes: sig = mldsa65_sign(sk, msg, msg_len, ctx, ctx_len)
 * Verifier calls:  mldsa65_verify(pk, msg, msg_len, ctx, ctx_len, sig, sig_len)
 *
 * For CKB:
 *   msg = blake2b_256("CKB-MLDSA-LOCK" || tx_hash)  [32 bytes]
 *   ctx = "CKB-MLDSA-LOCK"                           [14 bytes]
 *
 * Returns 0 on valid signature, non-zero on failure.
 */
int mldsa65_verify(
    const uint8_t *pubkey,        // MLDSA65_PUBLICKEY_BYTES
    const uint8_t *msg,           // message bytes (32-byte blake2b digest)
    size_t         msg_len,
    const uint8_t *ctx,           // context string
    size_t         ctx_len,
    const uint8_t *sig,           // MLDSA65_SIGNATURE_BYTES
    size_t         sig_len
);

#endif // MLDSA_ADAPTER_H
