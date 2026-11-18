/**
 * @file qs_crypt_hash_internal.h
 * @brief Internal streaming states for SHA-2, SHA-3/SHAKE, and the unified hash state.
 */
#ifndef QS_CRYPT_HASH_INTERNAL_H
#define QS_CRYPT_HASH_INTERNAL_H
#include "qs_crypt/qs_crypt_types.h"
#include "qs_crypt_sha256_internal.h"
#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint64_t h[8];
    uint8_t  buf[128];
    uint64_t total;     /* bytes absorbed */
    uint32_t buflen;
} qsc_sha512_state;

void qsc_sha512_init(qsc_sha512_state* s);
void qsc_sha512_update(qsc_sha512_state* s, const uint8_t* d, size_t n);
void qsc_sha512_final(qsc_sha512_state* s, uint8_t out[64]);
void qsc_sha384_init(qsc_sha512_state* s);
void qsc_sha384_final(qsc_sha512_state* s, uint8_t out[48]);

/* Keccak-f[1600] sponge. Absorption XORs directly into the lane state. */
typedef struct {
    uint64_t A[25];
    uint32_t rate;       /* bytes per block */
    uint32_t pos;        /* absorb or squeeze position within the rate */
    uint8_t  dom;        /* domain separation byte (0x06 SHA-3, 0x1F SHAKE) */
    uint8_t  squeezing;  /* 0 while absorbing, 1 after padding */
} qsc_keccak_state;

void qsc_keccak_init(qsc_keccak_state* s, uint32_t rate, uint8_t dom);
void qsc_keccak_absorb(qsc_keccak_state* s, const uint8_t* d, size_t n);
void qsc_keccak_squeeze(qsc_keccak_state* s, uint8_t* out, size_t n);

typedef struct {
    qsc_algorithm_id_t alg;
    union {
        qsc_sha256_state s256;
        qsc_sha512_state s512;
        qsc_keccak_state kk;
    } u;
} qsc_hstate;

qsc_error_t qsc_hstate_init(qsc_hstate* h, qsc_algorithm_id_t alg);
void        qsc_hstate_update(qsc_hstate* h, const uint8_t* d, size_t n);
void        qsc_hstate_final(qsc_hstate* h, uint8_t* out);   /* writes outlen bytes */
size_t      qsc_hstate_outlen(qsc_algorithm_id_t alg);       /* 0 if unsupported */
size_t      qsc_hstate_block(qsc_algorithm_id_t alg);        /* HMAC block size */

#endif
