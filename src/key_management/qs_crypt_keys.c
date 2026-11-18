/**
 * @file qs_crypt_keys.c
 * @brief Symmetric key objects. Sizes are exact; all-zero keys are rejected.
 */
#include "qs_crypt/qs_crypt.h"
#include "../core/qs_crypt_internal.h"
#include <string.h>

static qs_u64 required_size(qsc_algorithm_id_t alg) {
    switch (alg) {
        case QSC_ALG_CHACHA20:            return 32;
        case QSC_ALG_CHACHA20_POLY1305:   return 32;
        case QSC_ALG_AES_128_GCM:         return 16;
        case QSC_ALG_AES_256_GCM:         return 32;
        case QSC_ALG_HMAC_SHA2_256:       return 32;
        case QSC_ALG_HMAC_SHA2_512:       return 64;
        default:                          return 0;
    }
}

static qs_bool_t is_all_zero(const qs_u8* p, qs_u64 n) {
    qs_u8 acc = 0;
    for (qs_u64 i = 0; i < n; i++) acc |= p[i];
    return acc == 0 ? QS_TRUE : QS_FALSE;
}

qsc_error_t qsc_key_generate(qsc_algorithm_id_t alg, qsc_key_t** key) {
    qs_u64 n = required_size(alg);
    qsc_error_t e = QSC_OK;
    if (!key) return QSC_ERROR_INVALID_ARGUMENT;
    if (n == 0) return QSC_ERROR_UNSUPPORTED;
    *key = (qsc_key_t*)qsc_alloc(sizeof(qsc_key_t));
    if (!*key) return QSC_ERROR_OOM;
    (*key)->alg = alg;
    (*key)->size = n;
    do {
        e = qsc_random_bytes((*key)->material, n);
        if (e != QSC_OK) break;
    } while (is_all_zero((*key)->material, n));   /* practically never loops; keeps the invariant */
    if (e != QSC_OK) { qsc_key_destroy(*key); *key = NULL; }
    return e;
}

qsc_error_t qsc_key_import(qsc_algorithm_id_t alg, qsc_slice_t raw, qsc_key_t** key) {
    qs_u64 n = required_size(alg);
    if (!key || !raw.data) return QSC_ERROR_INVALID_ARGUMENT;
    if (n == 0) return QSC_ERROR_UNSUPPORTED;
    if (raw.length != n) return QSC_ERROR_KEY_SIZE_MISMATCH;
    if (is_all_zero(raw.data, n)) return QSC_ERROR_WEAK_KEY;
    *key = (qsc_key_t*)qsc_alloc(sizeof(qsc_key_t));
    if (!*key) return QSC_ERROR_OOM;
    (*key)->alg = alg;
    (*key)->size = n;
    memcpy((*key)->material, raw.data, (size_t)n);
    return QSC_OK;
}

qsc_error_t qsc_key_export(const qsc_key_t* key, qsc_buffer_t* out) {
    if (!key || !out || out->data != NULL) return QSC_ERROR_INVALID_ARGUMENT;
    out->data = (qs_u8*)qsc_alloc((size_t)key->size);
    if (!out->data) return QSC_ERROR_OOM;
    memcpy(out->data, key->material, (size_t)key->size);
    out->length = key->size;
    return QSC_OK;
}

qsc_algorithm_id_t qsc_key_algorithm(const qsc_key_t* key) {
    return key ? key->alg : QSC_ALG_UNKNOWN;
}

qs_u64 qsc_key_size(const qsc_key_t* key) {
    return key ? key->size : 0;
}

void qsc_key_destroy(qsc_key_t* key) {
    if (key) qsc_free_zero(key, sizeof *key);
}
