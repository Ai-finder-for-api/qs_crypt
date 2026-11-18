/**
 * @file qs_crypt_rsa.h
 * @brief RSA: OAEP (SHA-256) encryption and PSS (SHA-256, 32-byte salt) signatures.
 *
 * Sizes: 2048, 3072, 4096 bits. Public exponent: 32-bit, odd, >= 3 (65537 at keygen).
 * Keys: opaque handles. Private key serialization is not provided in this release;
 * keep the private handle in memory. Key generation is slow (seconds at 2048 bits).
 *
 * Constant-time: modular exponentiation performs the same operations for every exponent bit.
 * The padding checks are not constant-time, and decryption returns one generic error on any
 * padding failure. Not independently reviewed.
 *
 * Buffers: output parameters take caller storage in qsc_buffer_t.data. length is the capacity
 * on entry and the bytes written on return. BUFFER_TOO_SMALL sets length to the required size.
 */
#ifndef QS_CRYPT_RSA_H
#define QS_CRYPT_RSA_H
#include "qs_crypt_types.h"
#ifdef __cplusplus
extern "C" {
#endif

typedef struct qsc_rsa_public  qsc_rsa_public_t;
typedef struct qsc_rsa_private qsc_rsa_private_t;

qsc_error_t qsc_rsa_keygen(qs_u32 bits, qsc_rsa_public_t** pub, qsc_rsa_private_t** priv);
void        qsc_rsa_public_destroy(qsc_rsa_public_t* pub);
void        qsc_rsa_private_destroy(qsc_rsa_private_t* priv);

/* Import a private key from big-endian modulus n (256/384/512 bytes) and private exponent d. */
qsc_error_t qsc_rsa_private_create(qsc_slice_t n, qsc_slice_t d, qsc_rsa_private_t** priv);

/* Import a public key from big-endian modulus n (256/384/512 bytes) and exponent e (<= 4 bytes). */
qsc_error_t qsc_rsa_public_create(qsc_slice_t n, qsc_slice_t e, qsc_rsa_public_t** pub);
qsc_error_t qsc_rsa_public_get_modulus(const qsc_rsa_public_t* pub, qsc_buffer_t* n_out);
qsc_error_t qsc_rsa_public_get_exponent(const qsc_rsa_public_t* pub, qs_u32* e);
qs_u64      qsc_rsa_public_modulus_bytes(const qsc_rsa_public_t* pub);
qs_u64      qsc_rsa_private_modulus_bytes(const qsc_rsa_private_t* priv);

/* OAEP-SHA256, empty label. Max message length = modulus_bytes - 66. */
qsc_error_t qsc_rsa_oaep_encrypt(const qsc_rsa_public_t* pub, qsc_slice_t msg, qsc_buffer_t* ct);
qsc_error_t qsc_rsa_oaep_decrypt(const qsc_rsa_private_t* priv, qsc_slice_t ct, qsc_buffer_t* msg);

/* RSASSA-PSS, SHA-256, MGF1-SHA256, salt length 32. Signature length = modulus_bytes. */
qsc_error_t qsc_rsa_pss_sign(const qsc_rsa_private_t* priv, qsc_slice_t msg, qsc_buffer_t* sig);
qsc_error_t qsc_rsa_pss_verify(const qsc_rsa_public_t* pub, qsc_slice_t msg, qsc_slice_t sig);

/* ---- Generic-hash variants (hash = QSC_ALG_SHA2_256 / SHA2_384 / SHA2_512) ---- */
/* RSASSA-PKCS1-v1_5 (RFC 8017 8.2). Signature length = modulus_bytes. */
qsc_error_t qsc_rsa_pkcs1_sign(const qsc_rsa_private_t* priv, qsc_algorithm_id_t hash,
                               qsc_slice_t msg, qsc_buffer_t* sig);
qsc_error_t qsc_rsa_pkcs1_verify(const qsc_rsa_public_t* pub, qsc_algorithm_id_t hash,
                                 qsc_slice_t msg, qsc_slice_t sig);
/* RSASSA-PSS: salt length = hash length, MGF1 uses the same hash. */
qsc_error_t qsc_rsa_pss_sign_ex(const qsc_rsa_private_t* priv, qsc_algorithm_id_t hash,
                                qsc_slice_t msg, qsc_buffer_t* sig);
qsc_error_t qsc_rsa_pss_verify_ex(const qsc_rsa_public_t* pub, qsc_algorithm_id_t hash,
                                  qsc_slice_t msg, qsc_slice_t sig);
/* RSAES-OAEP, empty label, MGF1 uses the same hash. */
qsc_error_t qsc_rsa_oaep_encrypt_ex(const qsc_rsa_public_t* pub, qsc_algorithm_id_t hash,
                                    qsc_slice_t msg, qsc_buffer_t* ct);
qsc_error_t qsc_rsa_oaep_decrypt_ex(const qsc_rsa_private_t* priv, qsc_algorithm_id_t hash,
                                    qsc_slice_t ct, qsc_buffer_t* msg);
/* Private key import with CRT parameters: checks p*q == n and a round trip. */
qsc_error_t qsc_rsa_private_create_crt(qsc_slice_t n, qsc_slice_t e, qsc_slice_t d,
                                       qsc_slice_t p, qsc_slice_t q, qsc_rsa_private_t** priv);

#ifdef __cplusplus
}
#endif
#endif
