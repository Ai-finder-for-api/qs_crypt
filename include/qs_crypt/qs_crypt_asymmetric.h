/**
 * @file qs_crypt_asymmetric.h
 * @brief Public-key encryption interface boundary.
 *
 * STATUS: interface only. No native implementation in this release.
 * Backends (e.g. a vetted library adapter) must register via the backend
 * interface. Calls with no registered backend return QSC_ERROR_UNSUPPORTED.
 */
#ifndef QS_CRYPT_ASYMMETRIC_H
#define QS_CRYPT_ASYMMETRIC_H
#include "qs_crypt_types.h"
#ifdef __cplusplus
extern "C" {
#endif

qsc_error_t qsc_keypair_generate(qsc_algorithm_id_t alg, qsc_keypair_t** kp);
qsc_error_t qsc_pubkey_from_keypair(const qsc_keypair_t* kp, qsc_pubkey_t** pk);
qsc_error_t qsc_pke_encrypt(const qsc_pubkey_t* pk, qsc_slice_t plaintext,
                            qsc_buffer_t* ciphertext_out);
qsc_error_t qsc_pke_decrypt(const qsc_keypair_t* kp, qsc_slice_t ciphertext,
                            qsc_buffer_t* plaintext_out);
void        qsc_keypair_destroy(qsc_keypair_t* kp);
void        qsc_pubkey_destroy(qsc_pubkey_t* pk);

#ifdef __cplusplus
}
#endif
#endif
