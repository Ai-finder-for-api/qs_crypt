/**
 * @file qs_crypt_hmac.c
 * @brief HMAC-SHA-256 and HMAC-SHA-512 per RFC 2104, plus the public MAC API.
 */
#include "qs_crypt/qs_crypt.h"
#include "qs_crypt_hmac_internal.h"
#include "../core/qs_crypt_internal.h"
#include <string.h>

static qsc_algorithm_id_t hash_for(qsc_algorithm_id_t hmac_alg) {
    switch (hmac_alg) {
        case QSC_ALG_HMAC_SHA2_256: return QSC_ALG_SHA2_256;
        case QSC_ALG_HMAC_SHA2_384: return QSC_ALG_SHA2_384;
        case QSC_ALG_HMAC_SHA2_512: return QSC_ALG_SHA2_512;
        default: return QSC_ALG_UNKNOWN;
    }
}

size_t qsc_hmac_outlen(qsc_algorithm_id_t hmac_alg) {
    return qsc_hstate_outlen(hash_for(hmac_alg));
}

qsc_error_t qsc_hmac_begin(qsc_algorithm_id_t hmac_alg, const uint8_t* key, size_t klen,
                           qsc_hmac_ctx* c) {
    qsc_algorithm_id_t ha = hash_for(hmac_alg);
    size_t block;
    uint8_t k0[128], ipad[128];
    qsc_error_t e;
    if (ha == QSC_ALG_UNKNOWN) return QSC_ERROR_UNSUPPORTED;
    block = qsc_hstate_block(ha);
    memset(k0, 0, sizeof k0);
    if (klen > block) {
        qsc_hstate t;
        if ((e = qsc_hstate_init(&t, ha)) != QSC_OK) return e;
        qsc_hstate_update(&t, key, klen);
        qsc_hstate_final(&t, k0);
    } else if (klen) {
        memcpy(k0, key, klen);
    }
    for (size_t i = 0; i < block; i++) {
        ipad[i] = k0[i] ^ 0x36;
        c->opad[i] = k0[i] ^ 0x5c;
    }
    c->hmac_alg = hmac_alg;
    if ((e = qsc_hstate_init(&c->inner, ha)) != QSC_OK) return e;
    qsc_hstate_update(&c->inner, ipad, block);
    qsc_secure_zero(k0, sizeof k0);
    qsc_secure_zero(ipad, sizeof ipad);
    return QSC_OK;
}

void qsc_hmac_update(qsc_hmac_ctx* c, const uint8_t* d, size_t n) {
    qsc_hstate_update(&c->inner, d, n);
}

size_t qsc_hmac_finish(qsc_hmac_ctx* c, uint8_t out[64]) {
    qsc_algorithm_id_t ha = hash_for(c->hmac_alg);
    size_t hl = qsc_hstate_outlen(ha);
    size_t block = qsc_hstate_block(ha);
    uint8_t ih[64];
    qsc_hstate outer;
    qsc_hstate_final(&c->inner, ih);
    qsc_hstate_init(&outer, ha);
    qsc_hstate_update(&outer, c->opad, block);
    qsc_hstate_update(&outer, ih, hl);
    qsc_hstate_final(&outer, out);
    qsc_secure_zero(c, sizeof *c);
    qsc_secure_zero(ih, sizeof ih);
    return hl;
}

/* ---- public API ---------------------------------------------------------- */

qsc_error_t qsc_mac(qsc_algorithm_id_t alg, qsc_slice_t key,
                    qsc_slice_t message, qsc_tag_t* out) {
    qsc_hmac_ctx c;
    qsc_error_t e;
    size_t tl;
    if (hash_for(alg) == QSC_ALG_UNKNOWN) return QSC_ERROR_UNSUPPORTED;
    if (!out || (key.length && !key.data) || (message.length && !message.data))
        return QSC_ERROR_INVALID_ARGUMENT;
    if (key.length == 0) return QSC_ERROR_INVALID_KEY;  /* empty MAC key is almost always a bug */
    if ((e = qsc_hmac_begin(alg, key.data, (size_t)key.length, &c)) != QSC_OK) return e;
    qsc_hmac_update(&c, message.data, (size_t)message.length);
    tl = qsc_hmac_finish(&c, out->data);
    out->length = tl;
    return QSC_OK;
}

qsc_error_t qsc_mac_verify(qsc_algorithm_id_t alg, qsc_slice_t key,
                           qsc_slice_t message, qsc_slice_t expected_tag) {
    qsc_tag_t t;
    qsc_error_t e = qsc_mac(alg, key, message, &t);
    if (e != QSC_OK) return e;
    if (expected_tag.length != t.length || !expected_tag.data) return QSC_ERROR_INVALID_TAG;
    return qsc_constant_time_equal(t.data, expected_tag.data, t.length)
               ? QSC_OK : QSC_ERROR_AUTH_FAILED;
}
