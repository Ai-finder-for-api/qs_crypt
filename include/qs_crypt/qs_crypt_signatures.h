/**
 * @file qs_crypt_signatures.h
 * @brief Digital signature interface boundary (Ed25519, ECDSA, RSA-PSS, ML-DSA).
 * STATUS: interface only; no native implementation in this release.
 */
#ifndef QS_CRYPT_SIGNATURES_H
#define QS_CRYPT_SIGNATURES_H
#include "qs_crypt_types.h"
#ifdef __cplusplus
extern "C" {
#endif

qsc_error_t qsc_sign(const qsc_keypair_t* kp, qsc_slice_t message, qsc_buffer_t* sig_out);
qsc_error_t qsc_verify(const qsc_pubkey_t* pk, qsc_slice_t message, qsc_slice_t sig);

#ifdef __cplusplus
}
#endif
#endif
