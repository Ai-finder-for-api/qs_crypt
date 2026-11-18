/**
 * @file qs_crypt_hkdf.c
 * @brief HKDF (RFC 5869) over HMAC-SHA-256 and HMAC-SHA-512, with mandatory domain labels.
 */
#include "qs_crypt/qs_crypt.h"
#include "../mac/qs_crypt_hmac_internal.h"
#include "../core/qs_crypt_internal.h"
#include <string.h>

static qsc_algorithm_id_t hmac_for(qsc_algorithm_id_t kdf) {
    switch (kdf) {
        case QSC_ALG_HKDF_SHA2_256: return QSC_ALG_HMAC_SHA2_256;
        case QSC_ALG_HKDF_SHA2_512: return QSC_ALG_HMAC_SHA2_512;
        default: return QSC_ALG_UNKNOWN;
    }
}

qsc_error_t qsc_hkdf_extract(qsc_algorithm_id_t alg, qsc_slice_t salt,
                             qsc_slice_t ikm, qsc_digest_t* prk) {
    qsc_hmac_ctx c;
    qsc_algorithm_id_t h = hmac_for(alg);
    uint8_t zero_salt[64];
    const uint8_t* s = salt.data;
    size_t slen = (size_t)salt.length;
    size_t hl;
    qsc_error_t e;
    if (h == QSC_ALG_UNKNOWN) return QSC_ERROR_UNSUPPORTED;
    if (!prk || (ikm.length && !ikm.data) || (salt.length && !salt.data))
        return QSC_ERROR_INVALID_ARGUMENT;
    hl = qsc_hmac_outlen(h);
    if (slen == 0) { memset(zero_salt, 0, sizeof zero_salt); s = zero_salt; slen = hl; }
    if ((e = qsc_hmac_begin(h, s, slen, &c)) != QSC_OK) return e;
    qsc_hmac_update(&c, ikm.data, (size_t)ikm.length);
    prk->length = qsc_hmac_finish(&c, prk->data);
    return QSC_OK;
}

qsc_error_t qsc_hkdf_expand(qsc_algorithm_id_t alg, qsc_slice_t prk,
                            qsc_slice_t info, qsc_buffer_t* out) {
    qsc_algorithm_id_t h = hmac_for(alg);
    uint8_t t[64];
    size_t tlen = 0, hl;
    uint64_t n, L;
    if (h == QSC_ALG_UNKNOWN) return QSC_ERROR_UNSUPPORTED;
    if (!out || out->data != NULL) return QSC_ERROR_INVALID_ARGUMENT;
    hl = qsc_hmac_outlen(h);
    if (!prk.data || prk.length != hl) return QSC_ERROR_INVALID_KEY;
    if (info.length && !info.data) return QSC_ERROR_INVALID_ARGUMENT;
    L = out->length;
    if (L == 0 || L > 255u * hl) return QSC_ERROR_INVALID_PARAMETERS;
    out->data = (qs_u8*)qsc_alloc((size_t)L);
    if (!out->data) return QSC_ERROR_OOM;
    n = (L + hl - 1) / hl;
    for (uint64_t i = 1; i <= n; i++) {
        qsc_hmac_ctx c;
        uint8_t ctr = (uint8_t)i;
        size_t off = (size_t)((i - 1) * hl);
        size_t take = (L - off) < hl ? (size_t)(L - off) : hl;
        qsc_hmac_begin(h, prk.data, hl, &c);
        qsc_hmac_update(&c, t, tlen);
        qsc_hmac_update(&c, info.data, (size_t)info.length);
        qsc_hmac_update(&c, &ctr, 1);
        qsc_hmac_finish(&c, t);
        tlen = hl;
        memcpy(out->data + off, t, take);
    }
    qsc_secure_zero(t, sizeof t);
    return QSC_OK;
}

qsc_error_t qsc_derive_key(qsc_algorithm_id_t alg, qsc_slice_t salt,
                           qsc_slice_t ikm, qsc_slice_t domain_label,
                           qsc_buffer_t* out) {
    qsc_digest_t prk;
    qsc_error_t e;
    if (!domain_label.data || domain_label.length == 0) return QSC_ERROR_INVALID_PARAMETERS;
    if ((e = qsc_hkdf_extract(alg, salt, ikm, &prk)) != QSC_OK) return e;
    e = qsc_hkdf_expand(alg, (qsc_slice_t){ prk.data, prk.length }, domain_label, out);
    qsc_secure_zero(&prk, sizeof prk);
    return e;
}
