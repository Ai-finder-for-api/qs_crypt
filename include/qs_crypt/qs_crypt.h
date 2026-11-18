/**
 * @file qs_crypt.h
 * @brief QScrypt umbrella header. Include this to access stable QScrypt APIs.
 *
 * SECURITY: QScrypt is not claimed to be unbreakable or quantum-proof by nature.
 * Standardized primitives should be used for production. Anything marked
 * EXPERIMENTAL has not received independent cryptanalysis.
 */
#ifndef QS_CRYPT_H
#define QS_CRYPT_H

#include "qs_crypt_types.h"
#include "qs_crypt_capabilities.h"
#include "qs_crypt_random.h"
#include "qs_crypt_hash.h"
#include "qs_crypt_mac.h"
#include "qs_crypt_kdf.h"
#include "qs_crypt_symmetric.h"
#include "qs_crypt_aead.h"
#include "qs_crypt_keys.h"
#include "qs_crypt_asymmetric.h"
#include "qs_crypt_signatures.h"
#include "qs_crypt_kem.h"
#include "qs_crypt_pq.h"
#include "qs_crypt_x25519.h"
#include "qs_crypt_ed25519.h"
#include "qs_crypt_fhe.h"
#include "qs_crypt_rsa.h"
#include "qs_crypt_jose.h"
#include "qs_crypt_ecdsa.h"
#include "qs_crypt_mlkem.h"
#include "qs_crypt_mldsa.h"
#include "qs_crypt_serialize.h"
#include "qs_crypt_containers.h"

#ifdef __cplusplus
extern "C" {
#endif

qsc_error_t qsc_init(void);
void        qsc_shutdown(void);
void        qsc_version(qs_u32* major, qs_u32* minor, qs_u32* patch);
const char* qsc_build_info(void);

/* Constant-time comparison. Use for tags and MACs. */
qs_bool_t   qsc_constant_time_equal(const qs_u8* a, const qs_u8* b, qs_u64 length);

/* Compiler-barrier zeroization. Not elided by optimizers. */
void        qsc_secure_zero(void* ptr, qs_u64 size);

#ifdef __cplusplus
}
#endif
#endif
