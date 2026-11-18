/**
 * @file qs_crypt_hmac_internal.h
 * @brief Streaming HMAC over SHA-2 (RFC 2104). Internal.
 */
#ifndef QS_CRYPT_HMAC_INTERNAL_H
#define QS_CRYPT_HMAC_INTERNAL_H
#include "../hash/qs_crypt_hash_internal.h"

typedef struct {
    qsc_algorithm_id_t hmac_alg;
    qsc_hstate         inner;
    uint8_t            opad[128];
} qsc_hmac_ctx;

/* hmac_alg: QSC_ALG_HMAC_SHA2_256 or QSC_ALG_HMAC_SHA2_512. */
qsc_error_t qsc_hmac_begin(qsc_algorithm_id_t hmac_alg, const uint8_t* key, size_t klen,
                           qsc_hmac_ctx* c);
void        qsc_hmac_update(qsc_hmac_ctx* c, const uint8_t* d, size_t n);
size_t      qsc_hmac_finish(qsc_hmac_ctx* c, uint8_t out[64]);  /* returns tag length */
size_t      qsc_hmac_outlen(qsc_algorithm_id_t hmac_alg);

#endif
