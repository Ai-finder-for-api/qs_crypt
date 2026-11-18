/**
 * @file qs_crypt_mlkem.h
 * @brief ML-KEM-768 (FIPS 203): IND-CCA2 key encapsulation, parameter set k = 3.
 *
 * Sizes: encapsulation key 1184 bytes, decapsulation key 2400 bytes, ciphertext 1088 bytes,
 * shared secret 32 bytes. Keygen and encapsulation take 32-byte or 64-byte seeds from
 * qsc_random_bytes(); the *_seed variants are deterministic (for known-answer testing).
 *
 * Not independently reviewed. Constant-time behaviour is intended for the decapsulation
 * re-encryption comparison and the implicit-rejection select, not verified by measurement.
 */
#ifndef QS_CRYPT_MLKEM_H
#define QS_CRYPT_MLKEM_H
#include "qs_crypt_types.h"
#ifdef __cplusplus
extern "C" {
#endif

#define QSC_MLKEM768_EK_BYTES 1184
#define QSC_MLKEM768_DK_BYTES 2400
#define QSC_MLKEM768_CT_BYTES 1088
#define QSC_MLKEM768_SS_BYTES 32

qsc_error_t qsc_mlkem768_keygen(qs_u8 ek[1184], qs_u8 dk[2400]);
qsc_error_t qsc_mlkem768_keygen_seed(const qs_u8 seed[64], qs_u8 ek[1184], qs_u8 dk[2400]);
qsc_error_t qsc_mlkem768_encaps(const qs_u8 ek[1184], qs_u8 ct[1088], qs_u8 ss[32]);
qsc_error_t qsc_mlkem768_encaps_seed(const qs_u8 ek[1184], const qs_u8 m[32], qs_u8 ct[1088], qs_u8 ss[32]);
qsc_error_t qsc_mlkem768_decaps(const qs_u8 dk[2400], const qs_u8 ct[1088], qs_u8 ss[32]);

#ifdef __cplusplus
}
#endif
#endif
