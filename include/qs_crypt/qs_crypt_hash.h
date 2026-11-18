/**
 * @file qs_crypt_hash.h
 * @brief Hash abstraction: one-shot and incremental digests.
 * Implemented: SHA2-256, SHA2-512, SHA3-256, SHA3-512 (fixed output). SHAKE256 via qsc_shake256().
 *
 * OWNERSHIP: qsc_hash_begin allocates a context. qsc_hash_finish consumes it
 * (the context is freed whether or not finish succeeds). Do not call
 * qsc_hash_destroy after finish.
 */
#ifndef QS_CRYPT_HASH_H
#define QS_CRYPT_HASH_H
#include "qs_crypt_types.h"
#ifdef __cplusplus
extern "C" {
#endif

qsc_error_t qsc_hash(qsc_algorithm_id_t alg, qsc_slice_t input, qsc_digest_t* out);
qsc_error_t qsc_hash_begin(qsc_algorithm_id_t alg, qsc_hash_ctx_t** ctx);
qsc_error_t qsc_hash_update(qsc_hash_ctx_t* ctx, qsc_slice_t input);
qsc_error_t qsc_hash_finish(qsc_hash_ctx_t* ctx, qsc_digest_t* out);
qsc_error_t qsc_hash_clone(const qsc_hash_ctx_t* src, qsc_hash_ctx_t** dst);
void        qsc_hash_destroy(qsc_hash_ctx_t* ctx);

/* SHAKE256 extendable-output function. out->data must be NULL on entry, out->length is
 * the requested number of bytes; on success release with qsc_buffer_free(). */
qsc_error_t qsc_shake256(qsc_slice_t input, qsc_buffer_t* out);

#ifdef __cplusplus
}
#endif
#endif
