/**
 * @file qs_crypt_fhe.h
 * @brief Native BFV fully homomorphic encryption with an RNS ciphertext modulus.
 *
 * Parameters (fixed in this release):
 *   ring        Z_Q[x] / (x^N + 1), N = 4096
 *   ciphertext  modulus Q = q0 * q1 * q2 (RNS), q0 = 2013265921, q1 = 1004535809,
 *               q2 = 469762049; each q_i = 1 mod 2N. log2 Q is about 89.6, inside the
 *               HomomorphicEncryption.org 128-bit classical bound for N = 4096 (log2 Q <= 109).
 *   plaintext   modulus t = 257; a plaintext is N coefficients in [0, t)
 *   secret      ternary polynomial; errors centred binomial with eta = 2
 *
 * Supported operations: encrypt, decrypt, add, subtract, multiply by a dense plaintext
 * polynomial. Dense plaintext products are supported: the noise budget is far larger than
 * the worst-case growth from one such product.
 * NOT supported yet: ciphertext x ciphertext multiplication and relinearization.
 * Not wire- or parameter-compatible with Microsoft SEAL.
 *
 * Serialization format changed with the RNS modulus: the payload is 2 * 3 * N residues of
 * 4 bytes each, little-endian (98304 bytes). Older single-modulus ciphertexts are rejected.
 *
 * Noise: each operation grows noise. qsc_fhe_noise_budget() reports the remaining budget
 * (needs the secret key; a diagnostic, not part of an untrusted decryption path).
 *
 * Not independently reviewed. Decryption is not constant-time.
 */
#ifndef QS_CRYPT_FHE_H
#define QS_CRYPT_FHE_H
#include "qs_crypt_types.h"
#ifdef __cplusplus
extern "C" {
#endif

#define QSC_FHE_N          4096u
#define QSC_FHE_T          257u
#define QSC_FHE_NUM_PRIMES 3u

typedef struct qsc_fhe_ctx qsc_fhe_ctx_t;
typedef struct qsc_fhe_sk  qsc_fhe_sk_t;
typedef struct qsc_fhe_pk  qsc_fhe_pk_t;
typedef struct qsc_fhe_ct  qsc_fhe_ct_t;

qsc_error_t qsc_fhe_ctx_create(qsc_fhe_ctx_t** ctx);
void        qsc_fhe_ctx_destroy(qsc_fhe_ctx_t* ctx);

qsc_error_t qsc_fhe_keygen(const qsc_fhe_ctx_t* ctx, qsc_fhe_sk_t** sk, qsc_fhe_pk_t** pk);
void        qsc_fhe_sk_destroy(qsc_fhe_sk_t* sk);
void        qsc_fhe_pk_destroy(qsc_fhe_pk_t* pk);
void        qsc_fhe_ct_destroy(qsc_fhe_ct_t* ct);

/* m: N coefficients, each < QSC_FHE_T. */
qsc_error_t qsc_fhe_encrypt(const qsc_fhe_ctx_t* ctx, const qsc_fhe_pk_t* pk,
                            const qs_u32 m[QSC_FHE_N], qsc_fhe_ct_t** out);
/* m_out: N coefficients in [0, QSC_FHE_T). */
qsc_error_t qsc_fhe_decrypt(const qsc_fhe_ctx_t* ctx, const qsc_fhe_sk_t* sk,
                            const qsc_fhe_ct_t* ct, qs_u32 m_out[QSC_FHE_N]);

qsc_error_t qsc_fhe_add(const qsc_fhe_ctx_t* ctx, const qsc_fhe_ct_t* a,
                        const qsc_fhe_ct_t* b, qsc_fhe_ct_t** out);
qsc_error_t qsc_fhe_sub(const qsc_fhe_ctx_t* ctx, const qsc_fhe_ct_t* a,
                        const qsc_fhe_ct_t* b, qsc_fhe_ct_t** out);
/* p: N coefficients, each < QSC_FHE_T. Product is taken in the ring x^N + 1. */
qsc_error_t qsc_fhe_mul_plain(const qsc_fhe_ctx_t* ctx, const qsc_fhe_ct_t* a,
                              const qs_u32 p[QSC_FHE_N], qsc_fhe_ct_t** out);

/* Remaining noise budget in bits, approximately floor(log2(bound / max noise)) (+-1). 0 = exhausted. */
qsc_error_t qsc_fhe_noise_budget(const qsc_fhe_ctx_t* ctx, const qsc_fhe_sk_t* sk,
                                 const qsc_fhe_ct_t* ct, int* bits);

/* Serialization uses the QScrypt wire envelope with algorithm QSC_ALG_BFV_N4096. */
qsc_error_t qsc_fhe_ct_serialize(const qsc_fhe_ct_t* ct, qsc_buffer_t* out);
qsc_error_t qsc_fhe_ct_deserialize(const qsc_fhe_ctx_t* ctx, qsc_slice_t in, qsc_fhe_ct_t** out);

#ifdef __cplusplus
}
#endif
#endif
