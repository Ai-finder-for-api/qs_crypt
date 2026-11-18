/**
 * @file qs_crypt_kem.h
 * @brief Key encapsulation interface boundary (X25519, ML-KEM).
 * STATUS: interface only; no native implementation in this release.
 */
#ifndef QS_CRYPT_KEM_H
#define QS_CRYPT_KEM_H
#include "qs_crypt_types.h"
#ifdef __cplusplus
extern "C" {
#endif

qsc_error_t qsc_kem_encapsulate(const qsc_pubkey_t* pk,
                                qsc_buffer_t* ciphertext_out,
                                qsc_buffer_t* shared_secret_out);
qsc_error_t qsc_kem_decapsulate(const qsc_keypair_t* kp,
                                qsc_slice_t ciphertext,
                                qsc_buffer_t* shared_secret_out);

#ifdef __cplusplus
}
#endif
#endif
