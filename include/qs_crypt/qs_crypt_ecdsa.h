/**
 * @file qs_crypt_ecdsa.h
 * @brief ECDSA over NIST P-256 with SHA-256 (FIPS 186-5). Signatures are raw r || s (64 bytes).
 *
 * Public keys are uncompressed SEC1 points (0x04 || X || Y, 65 bytes). Private keys are
 * 32-byte big-endian scalars in [1, n-1].
 *
 * Nonces are random (not RFC 6979). Scalar multiplication always performs a doubling and an
 * addition per bit, with masked selection. It is not a fully constant-time implementation:
 * the point-addition code branches on the point-at-infinity case, which happens only while
 * leading zero bits are processed. Not independently reviewed.
 */
#ifndef QS_CRYPT_ECDSA_H
#define QS_CRYPT_ECDSA_H
#include "qs_crypt_types.h"
#ifdef __cplusplus
extern "C" {
#endif

#define QSC_ECDSA_P256_PRIV_BYTES 32
#define QSC_ECDSA_P256_PUB_BYTES  65
#define QSC_ECDSA_P256_SIG_BYTES  64

qsc_error_t qsc_ecdsa_p256_keygen(qs_u8 priv[32], qs_u8 pub[65]);
qsc_error_t qsc_ecdsa_p256_public_from_private(const qs_u8 priv[32], qs_u8 pub[65]);
qsc_error_t qsc_ecdsa_p256_sign(const qs_u8 priv[32], qsc_slice_t msg, qs_u8 sig[64]);
qsc_error_t qsc_ecdsa_p256_verify(const qs_u8 pub[65], qsc_slice_t msg, const qs_u8 sig[64]);

#ifdef __cplusplus
}
#endif
#endif
