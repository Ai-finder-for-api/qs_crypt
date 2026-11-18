/**
 * @file qs_crypt_symmetric.h
 * @brief Unauthenticated stream primitives (ChaCha20). Prefer AEAD for data.
 */
#ifndef QS_CRYPT_SYMMETRIC_H
#define QS_CRYPT_SYMMETRIC_H
#include "qs_crypt_types.h"
#ifdef __cplusplus
extern "C" {
#endif

/* ChaCha20 (RFC 8439). Key 32 bytes, nonce 12 bytes, counter starts at 'counter'.
 * Encrypts/decrypts in place or to a separate buffer of equal length.
 * Does NOT authenticate; use qsc_aead_* for untrusted ciphertext. */
qsc_error_t qsc_chacha20_xor(qsc_slice_t key, qsc_slice_t nonce, qs_u32 counter,
                             qsc_slice_t input, qs_u8* output);

#ifdef __cplusplus
}
#endif
#endif
