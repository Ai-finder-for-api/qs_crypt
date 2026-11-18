/**
 * @file qs_crypt_pq.h
 * @brief Post-quantum layer: policy and hybrid composition boundary.
 *
 * Standardized PQ primitives (ML-KEM / FIPS 203, ML-DSA / FIPS 204,
 * SLH-DSA / FIPS 205) are compatibility backends, NOT QScrypt-native code.
 * Hybrid mode (classical + PQ) is the recommended deployment posture.
 */
#ifndef QS_CRYPT_PQ_H
#define QS_CRYPT_PQ_H
#include "qs_crypt_types.h"
#ifdef __cplusplus
extern "C" {
#endif

/* Returns QS_TRUE only if the algorithm is standardized PQ and a backend is present. */
qs_bool_t qsc_pq_backend_available(qsc_algorithm_id_t alg);

#ifdef __cplusplus
}
#endif
#endif
