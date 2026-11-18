/**
 * @file qs_crypt_x25519.h
 * @brief X25519 key agreement (RFC 7748).
 * Keys are raw 32-byte arrays. Callers must hash the shared secret (e.g. HKDF with a
 * domain label) before using it as a key. Raw shared secrets must not be used directly.
 */
#ifndef QS_CRYPT_X25519_H
#define QS_CRYPT_X25519_H
#include "qs_crypt_types.h"
#ifdef __cplusplus
extern "C" {
#endif

qsc_error_t qsc_x25519_keygen(qs_u8 priv[32], qs_u8 pub[32]);
qsc_error_t qsc_x25519_public(const qs_u8 priv[32], qs_u8 pub[32]);
/* Returns QSC_ERROR_INVALID_KEY if the result is all-zero (low-order peer point). */
qsc_error_t qsc_x25519_shared(const qs_u8 priv[32], const qs_u8 peer_pub[32], qs_u8 shared[32]);

#ifdef __cplusplus
}
#endif
#endif
