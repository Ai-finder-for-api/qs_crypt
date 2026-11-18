/**
 * @file qs_crypt_sha256_internal.h
 * @brief Internal SHA-256 streaming state, shared by hash dispatch and HMAC.
 */
#ifndef QS_CRYPT_SHA256_INTERNAL_H
#define QS_CRYPT_SHA256_INTERNAL_H
#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t h[8];
    uint8_t  buf[64];
    uint64_t total;   /* bytes absorbed */
    uint32_t buflen;
} qsc_sha256_state;

void qsc_sha256_init(qsc_sha256_state* s);
void qsc_sha256_update(qsc_sha256_state* s, const uint8_t* data, size_t len);
void qsc_sha256_final(qsc_sha256_state* s, uint8_t out[32]);

#endif
