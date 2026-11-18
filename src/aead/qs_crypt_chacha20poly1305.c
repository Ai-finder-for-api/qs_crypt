/**
 * @file qs_crypt_chacha20poly1305.c
 * @brief ChaCha20-Poly1305 AEAD (RFC 8439 section 2.8).
 *
 * Decrypt verifies the tag in constant time BEFORE writing any plaintext.
 */
#include "qs_crypt/qs_crypt.h"
#include "../core/qs_crypt_internal.h"
#include <string.h>

void qsc_poly1305_aead_mac(const uint8_t key[32], const uint8_t* aad, size_t alen,
                           const uint8_t* ct, size_t clen, uint8_t out[16]);

/* Poly1305 one-time key = first 32 bytes of ChaCha20 block 0. */
static qsc_error_t compute_tag(const qs_u8 key[32], const qs_u8 nonce[12],
                               qsc_slice_t aad, const qs_u8* ct, qs_u64 clen,
                               qs_u8 tag[16]) {
    qs_u8 otk[64], zero[64];
    qsc_error_t e;
    memset(zero, 0, sizeof zero);
    e = qsc_chacha20_xor((qsc_slice_t){ key, 32 }, (qsc_slice_t){ nonce, 12 }, 0,
                         (qsc_slice_t){ zero, 64 }, otk);
    if (e != QSC_OK) return e;
    qsc_poly1305_aead_mac(otk, aad.data, (size_t)aad.length, ct, (size_t)clen, tag);
    qsc_secure_zero(otk, sizeof otk);
    return QSC_OK;
}

qsc_error_t qsc_cp_encrypt(const qs_u8 key[32], const qs_u8 nonce[12],
                           qsc_slice_t aad, qsc_slice_t pt, qs_u8* ct_out,
                           qs_u8 tag_out[16]) {
    qsc_error_t e;
    if (pt.length && (!pt.data || !ct_out)) return QSC_ERROR_INVALID_ARGUMENT;
    if (aad.length && !aad.data) return QSC_ERROR_INVALID_ARGUMENT;
    e = qsc_chacha20_xor((qsc_slice_t){ key, 32 }, (qsc_slice_t){ nonce, 12 }, 1, pt, ct_out);
    if (e != QSC_OK) return e;
    return compute_tag(key, nonce, aad, ct_out, pt.length, tag_out);
}

qsc_error_t qsc_cp_decrypt(const qs_u8 key[32], const qs_u8 nonce[12],
                           qsc_slice_t aad, qsc_slice_t ct, const qs_u8 tag[16],
                           qs_u8* pt_out) {
    qs_u8 expect[16];
    qsc_error_t e;
    if (ct.length && (!ct.data || !pt_out)) return QSC_ERROR_INVALID_ARGUMENT;
    if (aad.length && !aad.data) return QSC_ERROR_INVALID_ARGUMENT;
    e = compute_tag(key, nonce, aad, ct.data, ct.length, expect);
    if (e != QSC_OK) return e;
    if (!qsc_constant_time_equal(expect, tag, 16)) {
        qsc_secure_zero(expect, sizeof expect);
        return QSC_ERROR_AUTH_FAILED;
    }
    qsc_secure_zero(expect, sizeof expect);
    return qsc_chacha20_xor((qsc_slice_t){ key, 32 }, (qsc_slice_t){ nonce, 12 }, 1, ct, pt_out);
}
