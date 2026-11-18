/**
 * @file qs_crypt_aead.h
 * @brief Authenticated encryption with associated data.
 *
 * Implemented: ChaCha20-Poly1305, AES-128-GCM, AES-256-GCM (96-bit nonces).
 * Only AEAD is exposed for data encryption. Ciphertext and tag are kept
 * separate so callers cannot accidentally drop the tag. Decryption writes
 * plaintext only after the tag verifies; on failure the output is zeroized.
 *
 * Nonce rule: nonces MUST be unique per key. Use qsc_random_nonce for random
 * 96-bit nonces only while the message count per key stays far below 2^32.
 */
#ifndef QS_CRYPT_AEAD_H
#define QS_CRYPT_AEAD_H
#include "qs_crypt_types.h"
#ifdef __cplusplus
extern "C" {
#endif

qsc_error_t qsc_aead_encrypt(qsc_algorithm_id_t alg,
                             qsc_slice_t key, qsc_slice_t nonce,
                             qsc_slice_t aad, qsc_slice_t plaintext,
                             qs_u8* ciphertext_out, qsc_tag_t* tag_out);

qsc_error_t qsc_aead_decrypt(qsc_algorithm_id_t alg,
                             qsc_slice_t key, qsc_slice_t nonce,
                             qsc_slice_t aad, qsc_slice_t ciphertext,
                             qsc_slice_t tag,
                             qs_u8* plaintext_out);

#ifdef __cplusplus
}
#endif
#endif
