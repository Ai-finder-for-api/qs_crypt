/**
 * @file qs_crypt_aead_dispatch.c
 * @brief Public AEAD API. Validates sizes and dispatches by algorithm id.
 *        Implemented: ChaCha20-Poly1305, AES-128-GCM, AES-256-GCM.
 */
#include "qs_crypt/qs_crypt.h"
#include "../core/qs_crypt_internal.h"

#define TAG_LEN 16u
#define NONCE_LEN 12u

static qsc_error_t key_len_for(qsc_algorithm_id_t alg, qs_u64* klen) {
    switch (alg) {
        case QSC_ALG_CHACHA20_POLY1305: *klen = 32; return QSC_OK;
        case QSC_ALG_AES_128_GCM:       *klen = 16; return QSC_OK;
        case QSC_ALG_AES_256_GCM:       *klen = 32; return QSC_OK;
        default: return QSC_ERROR_UNSUPPORTED;
    }
}

static qsc_error_t check_common(qsc_algorithm_id_t alg, qsc_slice_t key, qsc_slice_t nonce) {
    qs_u64 want;
    qsc_error_t e = key_len_for(alg, &want);
    if (e != QSC_OK) return e;
    if (!key.data || key.length != want) return QSC_ERROR_KEY_SIZE_MISMATCH;
    if (!nonce.data || nonce.length != NONCE_LEN) return QSC_ERROR_INVALID_NONCE;
    return QSC_OK;
}

qsc_error_t qsc_aead_encrypt(qsc_algorithm_id_t alg, qsc_slice_t key, qsc_slice_t nonce,
                             qsc_slice_t aad, qsc_slice_t plaintext,
                             qs_u8* ciphertext_out, qsc_tag_t* tag_out) {
    qsc_error_t e = check_common(alg, key, nonce);
    if (e != QSC_OK) return e;
    if (!tag_out) return QSC_ERROR_INVALID_ARGUMENT;
    if (plaintext.length && (!plaintext.data || !ciphertext_out)) return QSC_ERROR_INVALID_ARGUMENT;
    if (aad.length && !aad.data) return QSC_ERROR_INVALID_ARGUMENT;
    if (alg == QSC_ALG_CHACHA20_POLY1305) {
        e = qsc_cp_encrypt(key.data, nonce.data, aad, plaintext, ciphertext_out, tag_out->data);
    } else {
        e = qsc_gcm_encrypt(key.data, key.length, nonce.data, aad, plaintext,
                            ciphertext_out, tag_out->data);
    }
    if (e != QSC_OK) return e;
    tag_out->length = TAG_LEN;
    return QSC_OK;
}

qsc_error_t qsc_aead_decrypt(qsc_algorithm_id_t alg, qsc_slice_t key, qsc_slice_t nonce,
                             qsc_slice_t aad, qsc_slice_t ciphertext, qsc_slice_t tag,
                             qs_u8* plaintext_out) {
    qsc_error_t e = check_common(alg, key, nonce);
    if (e != QSC_OK) return e;
    if (!tag.data || tag.length != TAG_LEN) return QSC_ERROR_INVALID_TAG;
    if (ciphertext.length && (!ciphertext.data || !plaintext_out)) return QSC_ERROR_INVALID_ARGUMENT;
    if (aad.length && !aad.data) return QSC_ERROR_INVALID_ARGUMENT;
    if (alg == QSC_ALG_CHACHA20_POLY1305) {
        return qsc_cp_decrypt(key.data, nonce.data, aad, ciphertext, tag.data, plaintext_out);
    }
    return qsc_gcm_decrypt(key.data, key.length, nonce.data, aad, ciphertext, tag.data,
                           plaintext_out);
}

qs_bool_t qsc_aead_is_supported(qsc_algorithm_id_t alg) {
    qs_u64 k;
    return key_len_for(alg, &k) == QSC_OK ? QS_TRUE : QS_FALSE;
}
