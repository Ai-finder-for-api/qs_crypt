/**
 * @file qs_crypt_mldsa.h
 * @brief ML-DSA-65 (FIPS 204): lattice-based signatures, parameter set (k, l) = (6, 5).
 *
 * Sizes: public key 1952 bytes, secret key 4032 bytes, signature 3309 bytes.
 * Signing is the pure (non-prehashed) variant with a context string of up to 255 bytes.
 * qsc_mldsa65_sign() is hedged (uses fresh randomness); qsc_mldsa65_sign_deterministic() uses
 * rnd = 0 for reproducible known-answer testing.
 *
 * Not independently reviewed. Signing is not constant-time (rejection sampling depends on the
 * secret); the timing of rejected attempts is observable.
 */
#ifndef QS_CRYPT_MLDSA_H
#define QS_CRYPT_MLDSA_H
#include "qs_crypt_types.h"
#ifdef __cplusplus
extern "C" {
#endif

#define QSC_MLDSA65_PK_BYTES  1952
#define QSC_MLDSA65_SK_BYTES  4032
#define QSC_MLDSA65_SIG_BYTES 3309
#define QSC_MLDSA65_CTX_MAX   255

qsc_error_t qsc_mldsa65_keygen(qs_u8 pk[1952], qs_u8 sk[4032]);
qsc_error_t qsc_mldsa65_keygen_seed(const qs_u8 xi[32], qs_u8 pk[1952], qs_u8 sk[4032]);
qsc_error_t qsc_mldsa65_sign(const qs_u8 sk[4032], qsc_slice_t msg, qsc_slice_t ctx, qs_u8 sig[3309]);
qsc_error_t qsc_mldsa65_sign_deterministic(const qs_u8 sk[4032], qsc_slice_t msg, qsc_slice_t ctx, qs_u8 sig[3309]);
qsc_error_t qsc_mldsa65_verify(const qs_u8 pk[1952], qsc_slice_t msg, qsc_slice_t ctx, qsc_slice_t sig);

#ifdef __cplusplus
}
#endif
#endif
