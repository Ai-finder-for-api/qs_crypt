/**
 * @file qs_crypt_random.h
 * @brief OS-entropy-backed CSPRNG. No silent fallback to predictable output.
 */
#ifndef QS_CRYPT_RANDOM_H
#define QS_CRYPT_RANDOM_H
#include "qs_crypt_types.h"
#ifdef __cplusplus
extern "C" {
#endif

qsc_error_t qsc_rng_create(qsc_rng_t** rng);
void        qsc_rng_destroy(qsc_rng_t* rng);
qsc_error_t qsc_rng_fill(qsc_rng_t* rng, qs_u8* out, qs_u64 length);

/* Module-level RNG; requires qsc_init(). */
qsc_error_t qsc_random_bytes(qs_u8* out, qs_u64 length);

#ifdef __cplusplus
}
#endif
#endif
