/**
 * @file qs_crypt_hash_dispatch.c
 * @brief Public hash API. Dispatches to the unified hash state.
 *
 * OWNERSHIP: qsc_hash_begin allocates a context. qsc_hash_finish consumes it.
 */
#include "qs_crypt/qs_crypt.h"
#include "qs_crypt_hash_internal.h"
#include "../core/qs_crypt_internal.h"
#include <string.h>

struct qsc_hash_ctx {
    qsc_hstate st;
};

static int is_fixed_hash(qsc_algorithm_id_t alg) {
    return qsc_hstate_outlen(alg) != 0;
}

qsc_error_t qsc_hash(qsc_algorithm_id_t alg, qsc_slice_t input, qsc_digest_t* out) {
    qsc_hash_ctx_t* ctx = NULL;
    qsc_error_t e;
    if (!out || (input.length && !input.data)) return QSC_ERROR_INVALID_ARGUMENT;
    if ((e = qsc_hash_begin(alg, &ctx)) != QSC_OK) return e;
    if ((e = qsc_hash_update(ctx, input)) != QSC_OK) { qsc_hash_destroy(ctx); return e; }
    return qsc_hash_finish(ctx, out);
}

qsc_error_t qsc_hash_begin(qsc_algorithm_id_t alg, qsc_hash_ctx_t** ctx) {
    qsc_error_t e;
    if (!ctx) return QSC_ERROR_INVALID_ARGUMENT;
    if (!is_fixed_hash(alg)) return QSC_ERROR_UNSUPPORTED;
    *ctx = (qsc_hash_ctx_t*)qsc_alloc(sizeof(qsc_hash_ctx_t));
    if (!*ctx) return QSC_ERROR_OOM;
    if ((e = qsc_hstate_init(&(*ctx)->st, alg)) != QSC_OK) {
        qsc_free_zero(*ctx, sizeof(qsc_hash_ctx_t));
        *ctx = NULL;
        return e;
    }
    return QSC_OK;
}

qsc_error_t qsc_hash_update(qsc_hash_ctx_t* ctx, qsc_slice_t input) {
    if (!ctx) return QSC_ERROR_INVALID_ARGUMENT;
    if (input.length && !input.data) return QSC_ERROR_INVALID_ARGUMENT;
    qsc_hstate_update(&ctx->st, input.data, (size_t)input.length);
    return QSC_OK;
}

qsc_error_t qsc_hash_finish(qsc_hash_ctx_t* ctx, qsc_digest_t* out) {
    if (!ctx) return QSC_ERROR_INVALID_ARGUMENT;
    if (!out) { qsc_hash_destroy(ctx); return QSC_ERROR_INVALID_ARGUMENT; }
    qsc_hstate_final(&ctx->st, out->data);
    out->length = qsc_hstate_outlen(ctx->st.alg);
    qsc_free_zero(ctx, sizeof *ctx);
    return QSC_OK;
}

qsc_error_t qsc_hash_clone(const qsc_hash_ctx_t* src, qsc_hash_ctx_t** dst) {
    if (!src || !dst) return QSC_ERROR_INVALID_ARGUMENT;
    *dst = (qsc_hash_ctx_t*)qsc_alloc(sizeof(qsc_hash_ctx_t));
    if (!*dst) return QSC_ERROR_OOM;
    memcpy(*dst, src, sizeof *src);
    return QSC_OK;
}

void qsc_hash_destroy(qsc_hash_ctx_t* ctx) {
    if (ctx) qsc_free_zero(ctx, sizeof *ctx);
}

/* ---- SHAKE256 (XOF): one-shot. out->data must be NULL; out->length is the requested size. */
qsc_error_t qsc_shake256(qsc_slice_t input, qsc_buffer_t* out) {
    qsc_keccak_state s;
    if (!out || out->data != NULL) return QSC_ERROR_INVALID_ARGUMENT;
    if (input.length && !input.data) return QSC_ERROR_INVALID_ARGUMENT;
    if (out->length == 0) return QSC_ERROR_INVALID_PARAMETERS;
    out->data = (qs_u8*)qsc_alloc((size_t)out->length);
    if (!out->data) return QSC_ERROR_OOM;
    qsc_keccak_init(&s, 136, 0x1F);
    qsc_keccak_absorb(&s, input.data, (size_t)input.length);
    qsc_keccak_squeeze(&s, out->data, (size_t)out->length);
    qsc_secure_zero(&s, sizeof s);
    return QSC_OK;
}
