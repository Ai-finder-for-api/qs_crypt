/**
 * @file qs_crypt_ed25519.h
 * @brief Ed25519 signatures (RFC 8032, PureEd25519).
 *
 * Keys: 32-byte seed (private) and 32-byte public key. Signatures: 64 bytes.
 * Verification is variable-time over public data only; never pass secrets to it.
 */
#ifndef QS_CRYPT_ED25519_H
#define QS_CRYPT_ED25519_H
#include "qs_crypt_types.h"
#ifdef __cplusplus
extern "C" {
#endif

qsc_error_t qsc_ed25519_keygen(qs_u8 seed[32], qs_u8 pub[32]);
qsc_error_t qsc_ed25519_public(const qs_u8 seed[32], qs_u8 pub[32]);
qsc_error_t qsc_ed25519_sign(const qs_u8 seed[32], const qs_u8* msg, qs_u64 mlen, qs_u8 sig[64]);
/* Returns QSC_OK, QSC_ERROR_INVALID_SIGNATURE, or QSC_ERROR_INVALID_ARGUMENT. */
qsc_error_t qsc_ed25519_verify(const qs_u8 pub[32], const qs_u8* msg, qs_u64 mlen, const qs_u8 sig[64]);

#ifdef __cplusplus
}
#endif
#endif
