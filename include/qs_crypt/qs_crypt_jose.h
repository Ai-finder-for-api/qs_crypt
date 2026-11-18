/**
 * @file qs_crypt_jose.h
 * @brief Building blocks needed by JOSE/JWE: AES-CBC, AES Key Wrap, PBKDF2.
 * Table-based AES: see the timing caveat in qs_crypt_aes_gcm.c.
 */
#ifndef QS_CRYPT_JOSE_H
#define QS_CRYPT_JOSE_H
#include "qs_crypt_types.h"
#ifdef __cplusplus
extern "C" {
#endif

/* AES-CBC with PKCS#7 padding. Key 16/24/32 bytes, IV 16 bytes.
 * ct_out must hold (pt.length / 16 + 1) * 16 bytes. Authenticate BEFORE decrypting. */
qsc_error_t qsc_aes_cbc_encrypt(qsc_slice_t key, const qs_u8 iv[16], qsc_slice_t pt,
                                qs_u8* ct_out, qs_u64* ct_len);
qsc_error_t qsc_aes_cbc_decrypt(qsc_slice_t key, const qs_u8 iv[16], qsc_slice_t ct,
                                qs_u8* pt_out, qs_u64* pt_len);

/* AES Key Wrap, RFC 3394. KEK 16/24/32 bytes. Input key: multiple of 8 bytes, >= 16.
 * wrap output = input + 8 bytes; unwrap output = input - 8 bytes. */
qsc_error_t qsc_aes_kw_wrap(qsc_slice_t kek, qsc_slice_t key_in, qs_u8* out);
qsc_error_t qsc_aes_kw_unwrap(qsc_slice_t kek, qsc_slice_t wrapped, qs_u8* out);

/* PBKDF2, RFC 8018. prf = QSC_ALG_HMAC_SHA2_256 / _384 / _512. out holds dklen bytes. */
qsc_error_t qsc_pbkdf2(qsc_algorithm_id_t prf, qsc_slice_t password, qsc_slice_t salt,
                       qs_u32 iterations, qs_u8* out, qs_u64 dklen);

#ifdef __cplusplus
}
#endif
#endif
