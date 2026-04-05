/*
 * Adapter from mldsa-native API to the CKB lock script interface.
 *
 * We configure mldsa-native for:
 *   - ML-DSA-65 only (MLD_CONFIG_PARAMETER_SET=65)
 *   - portable C backend only (no ASM/native backends)
 *   - verify only (no keygen, no signing)
 *   - no file I/O, no stdio, no benchmarks
 *
 * The standard verify path is used: caller provides the message bytes and
 * an optional context string. The library computes tr = SHAKE256(pk, 64)
 * and mu = SHAKE256(tr || OID || ctx_len || ctx || msg, 64) internally.
 * This avoids exposing the 64-byte mu interface on the lock script side.
 */

#define MLD_CONFIG_PARAMETER_SET 65
#define MLDSA_NATIVE_PORTABLE 1
#define MLDSA_NO_SIGN 1
#define MLDSA_NO_KEYGEN 1

#include "../vendor/mldsa-native/mldsa/mldsa_native.h"
#include "mldsa_adapter.h"
#include "mldsa_params.h"

int mldsa65_verify(
    const uint8_t *pubkey,
    const uint8_t *msg,
    size_t         msg_len,
    const uint8_t *ctx,
    size_t         ctx_len,
    const uint8_t *sig,
    size_t         sig_len
) {
    if (sig_len != MLDSA65_SIGNATURE_BYTES) return -1;

    return MLD_API_NAMESPACE(verify)(sig, sig_len, msg, msg_len, ctx, ctx_len, pubkey);
}
