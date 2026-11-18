/**
 * @file qs_crypt_kdf.h
 * @brief Key derivation: HKDF-SHA2-256 (RFC 5869) with mandatory domain separation.
 *
 * BUFFER RULE: variable-length outputs (qsc_buffer_t) are allocated by the callee.
 * On entry out->data must be NULL and out->length is the requested size.
 * On success out->data points to out->length bytes; release with qsc_buffer_free().
 */
#ifndef QS_CRYPT_KDF_H
#define QS_CRYPT_KDF_H
#include "qs_crypt_types.h"
#ifdef __cplusplus
extern "C" {
#endif

/* RFC 5869: output limit is 255 * HashLen. For SHA-256 that is 8160 bytes. */
#define QSC_HKDF_SHA256_MAX_OUTPUT 8160u

/* Empty salt is permitted and is replaced by HashLen zero bytes (RFC 5869 2.2). */
qsc_error_t qsc_hkdf_extract(qsc_algorithm_id_t alg, qsc_slice_t salt,
                             qsc_slice_t ikm, qsc_digest_t* prk);

qsc_error_t qsc_hkdf_expand(qsc_algorithm_id_t alg, qsc_slice_t prk,
                            qsc_slice_t info, qsc_buffer_t* out);

/* Extract then expand. domain_label is REQUIRED and non-empty. */
qsc_error_t qsc_derive_key(qsc_algorithm_id_t alg, qsc_slice_t salt,
                           qsc_slice_t ikm, qsc_slice_t domain_label,
                           qsc_buffer_t* out);

#ifdef __cplusplus
}
#endif
#endif
