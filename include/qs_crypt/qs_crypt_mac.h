/**
 * @file qs_crypt_mac.h
 * @brief Message authentication codes (HMAC-SHA2, Poly1305).
 * Tag comparison in qsc_mac_verify is constant-time.
 */
#ifndef QS_CRYPT_MAC_H
#define QS_CRYPT_MAC_H
#include "qs_crypt_types.h"
#ifdef __cplusplus
extern "C" {
#endif

qsc_error_t qsc_mac(qsc_algorithm_id_t alg, qsc_slice_t key,
                    qsc_slice_t message, qsc_tag_t* out);

qsc_error_t qsc_mac_verify(qsc_algorithm_id_t alg, qsc_slice_t key,
                           qsc_slice_t message, qsc_slice_t expected_tag);

#ifdef __cplusplus
}
#endif
#endif
