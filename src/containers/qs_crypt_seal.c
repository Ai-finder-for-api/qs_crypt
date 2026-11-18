/**
 * @file qs_crypt_seal.c
 * @brief Sealed container: wire envelope around (nonce || tag || ciphertext).
 *
 * The envelope's algorithm id is the key's AEAD algorithm. It is checked on open,
 * so a container cannot be opened under a different algorithm than the one that
 * produced it. A fresh random 96-bit nonce is drawn per seal.
 */
#include "qs_crypt/qs_crypt.h"
#include "../core/qs_crypt_internal.h"
#include <string.h>

#define SEAL_NONCE    12u
#define SEAL_TAG      16u
#define SEAL_OVERHEAD (SEAL_NONCE + SEAL_TAG)

static int is_aead_alg(qsc_algorithm_id_t alg) {
    return alg == QSC_ALG_CHACHA20_POLY1305 ||
           alg == QSC_ALG_AES_128_GCM ||
           alg == QSC_ALG_AES_256_GCM;
}

qsc_error_t qsc_seal(const qsc_key_t* key, qsc_slice_t aad, qsc_slice_t plaintext,
                     qsc_buffer_t* container_out) {
    qs_u8 nonce[SEAL_NONCE];
    qsc_tag_t tag;
    qs_u8* payload;
    qsc_error_t e;
    qs_u64 total;
    if (!key || !container_out || container_out->data != NULL) return QSC_ERROR_INVALID_ARGUMENT;
    if (!is_aead_alg(key->alg)) return QSC_ERROR_CAPABILITY_MISMATCH;
    if (plaintext.length && !plaintext.data) return QSC_ERROR_INVALID_ARGUMENT;
    if (aad.length && !aad.data) return QSC_ERROR_INVALID_ARGUMENT;

    if ((e = qsc_random_bytes(nonce, sizeof nonce)) != QSC_OK) return e;

    total = SEAL_OVERHEAD + plaintext.length;
    payload = (qs_u8*)qsc_alloc((size_t)total);
    if (!payload) return QSC_ERROR_OOM;
    memcpy(payload, nonce, SEAL_NONCE);

    e = qsc_aead_encrypt(key->alg, (qsc_slice_t){ key->material, key->size },
                         (qsc_slice_t){ nonce, SEAL_NONCE }, aad, plaintext,
                         payload + SEAL_OVERHEAD, &tag);
    if (e == QSC_OK) {
        memcpy(payload + SEAL_NONCE, tag.data, SEAL_TAG);
        e = qsc_serialize_wrap(key->alg, (qsc_slice_t){ payload, total }, container_out);
    }
    qsc_free_zero(payload, (size_t)total);
    return e;
}

qsc_error_t qsc_open(const qsc_key_t* key, qsc_slice_t aad, qsc_slice_t container,
                     qsc_buffer_t* plaintext_out) {
    qsc_algorithm_id_t alg;
    qsc_slice_t payload;
    qsc_error_t e;
    qs_u8* pt;
    qs_u64 ct_len;
    if (!key || !plaintext_out || plaintext_out->data != NULL) return QSC_ERROR_INVALID_ARGUMENT;
    if (!is_aead_alg(key->alg)) return QSC_ERROR_CAPABILITY_MISMATCH;
    if ((e = qsc_serialize_unwrap(container, &alg, &payload)) != QSC_OK) return e;
    if (alg != key->alg) return QSC_ERROR_CAPABILITY_MISMATCH;
    if (payload.length < SEAL_OVERHEAD) return QSC_ERROR_TRUNCATED;

    ct_len = payload.length - SEAL_OVERHEAD;
    pt = (qs_u8*)qsc_alloc((size_t)ct_len);
    if (!pt) return QSC_ERROR_OOM;

    e = qsc_aead_decrypt(key->alg, (qsc_slice_t){ key->material, key->size },
                         (qsc_slice_t){ payload.data, SEAL_NONCE }, aad,
                         (qsc_slice_t){ payload.data + SEAL_OVERHEAD, ct_len },
                         (qsc_slice_t){ payload.data + SEAL_NONCE, SEAL_TAG }, pt);
    if (e != QSC_OK) {
        qsc_free_zero(pt, (size_t)ct_len);
        return e;
    }
    plaintext_out->data = pt;
    plaintext_out->length = ct_len;
    return QSC_OK;
}
