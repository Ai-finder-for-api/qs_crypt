/**
 * @file qs_crypt_internal.h
 * @brief Module-private definitions. NOT part of the public API.
 */
#ifndef QS_CRYPT_INTERNAL_H
#define QS_CRYPT_INTERNAL_H

#include "qs_crypt/qs_crypt_types.h"
#include <stdint.h>
#include <stddef.h>

struct qsc_key {
    qsc_algorithm_id_t alg;
    qs_u64             size;
    qs_u8              material[64];
};

struct qsc_rng {
    qs_u32 magic;
};

/* ---- QScrypt-local memory pool (src/core/qs_crypt_alloc.c) ----------------- */
void* qsc_alloc(size_t n);
void  qsc_free_zero(void* p, size_t n);
void  qsc_alloc_stats(size_t* live_blocks, size_t* live_bytes, size_t* invalid_frees);

/* ---- lifecycle / entropy --------------------------------------------------- */
int         qsc_is_initialized(void);
qsc_error_t qsc_os_entropy(qs_u8* out, qs_u64 length);
void        qsc_aes_init_tables(void);

/* ---- AEAD internals --------------------------------------------------------- */
qsc_error_t qsc_cp_encrypt(const qs_u8 key[32], const qs_u8 nonce[12],
                           qsc_slice_t aad, qsc_slice_t pt, qs_u8* ct_out,
                           qs_u8 tag_out[16]);
qsc_error_t qsc_cp_decrypt(const qs_u8 key[32], const qs_u8 nonce[12],
                           qsc_slice_t aad, qsc_slice_t ct, const qs_u8 tag[16],
                           qs_u8* pt_out);
qsc_error_t qsc_gcm_encrypt(const qs_u8* key, qs_u64 keylen, const qs_u8 nonce[12],
                            qsc_slice_t aad, qsc_slice_t pt, qs_u8* ct_out,
                            qs_u8 tag_out[16]);
qsc_error_t qsc_gcm_decrypt(const qs_u8* key, qs_u64 keylen, const qs_u8 nonce[12],
                            qsc_slice_t aad, qsc_slice_t ct, const qs_u8 tag[16],
                            qs_u8* pt_out);

/* ---- byte helpers ---------------------------------------------------------- */
static inline uint32_t qsc_ld32le(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static inline uint32_t qsc_ld32be(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}
static inline uint64_t qsc_ld64be(const uint8_t* p) {
    return ((uint64_t)qsc_ld32be(p) << 32) | qsc_ld32be(p + 4);
}
static inline uint64_t qsc_ld64le(const uint8_t* p) {
    return (uint64_t)qsc_ld32le(p) | ((uint64_t)qsc_ld32le(p + 4) << 32);
}
static inline void qsc_st32le(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static inline void qsc_st32be(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}
static inline void qsc_st64be(uint8_t* p, uint64_t v) {
    qsc_st32be(p, (uint32_t)(v >> 32)); qsc_st32be(p + 4, (uint32_t)v);
}
static inline void qsc_st64le(uint8_t* p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
}
static inline uint32_t qsc_rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
static inline uint32_t qsc_rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
static inline uint64_t qsc_rotr64(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }
static inline uint64_t qsc_rotl64(uint64_t x, int n) { return (x << n) | (x >> (64 - n)); }

#endif
