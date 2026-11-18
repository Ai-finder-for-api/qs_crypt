/**
 * @file qs_crypt_keys.h
 * @brief Symmetric key objects with explicit size checks and lifecycle.
 */
#ifndef QS_CRYPT_KEYS_H
#define QS_CRYPT_KEYS_H
#include "qs_crypt_types.h"
#ifdef __cplusplus
extern "C" {
#endif

/* Generate a fresh random key sized for 'alg'. */
qsc_error_t qsc_key_generate(qsc_algorithm_id_t alg, qsc_key_t** key);

/* Import raw key bytes; length must match the algorithm exactly. */
qsc_error_t qsc_key_import(qsc_algorithm_id_t alg, qsc_slice_t raw, qsc_key_t** key);

qsc_error_t qsc_key_export(const qsc_key_t* key, qsc_buffer_t* out);
qsc_algorithm_id_t qsc_key_algorithm(const qsc_key_t* key);
qs_u64      qsc_key_size(const qsc_key_t* key);
void        qsc_key_destroy(qsc_key_t* key); /* zeroizes material */

#ifdef __cplusplus
}
#endif
#endif
