/**
 * @file qs_crypt_rsa_internal.h
 * @brief Fixed-limb bignum and Montgomery arithmetic for RSA. Internal; not public API.
 *
 * Limbs are 32-bit, products use 64-bit intermediates (no __int128, MSVC-safe).
 * Operations take an explicit limb count k; words above k are not read.
 */
#ifndef QS_CRYPT_RSA_INTERNAL_H
#define QS_CRYPT_RSA_INTERNAL_H

#include <stdint.h>
#include <stddef.h>

#define QSC_BN_MAX 130            /* 4096-bit modulus = 128 limbs, plus headroom */

typedef struct { uint32_t w[QSC_BN_MAX]; } qsc_bn;

typedef struct {
    qsc_bn   n;                   /* modulus, k limbs, odd */
    qsc_bn   r2;                  /* R^2 mod n, R = 2^(32k) */
    uint32_t n0;                  /* -n^-1 mod 2^32 */
    int      k;
} qsc_mont;

void     qsc_bn_zero(qsc_bn* a);
void     qsc_bn_copy(qsc_bn* r, const qsc_bn* a, int k);
int      qsc_bn_from_be(qsc_bn* r, int k, const uint8_t* b, size_t len);  /* -1 if value needs > k limbs */
void     qsc_bn_to_be(const qsc_bn* a, int k, uint8_t* out, size_t len);
int      qsc_bn_cmp(const qsc_bn* a, const qsc_bn* b, int k);
uint32_t qsc_bn_sub(qsc_bn* r, const qsc_bn* a, const qsc_bn* b, int k);  /* returns borrow */
uint32_t qsc_bn_add(qsc_bn* r, const qsc_bn* a, const qsc_bn* b, int k);  /* returns carry  */
void     qsc_bn_mul(qsc_bn* r, const qsc_bn* a, const qsc_bn* b, int k);  /* r gets 2k limbs */
uint32_t qsc_bn_mul_small(qsc_bn* r, const qsc_bn* a, uint32_t m, int k); /* returns top carry */
uint32_t qsc_bn_divmod_small(qsc_bn* q, const qsc_bn* a, uint32_t d, int k); /* returns remainder */
int      qsc_bn_bit_len(const qsc_bn* a, int k);
void     qsc_bn_shr1(qsc_bn* a, int k);
void     qsc_bn_sel(qsc_bn* r, const qsc_bn* a, const qsc_bn* b, uint32_t mask, int k);
void     qsc_bn_set_u32(qsc_bn* a, uint32_t v);
/* r = a mod m, a has ka limbs, m has km limbs, r gets km limbs. Binary long division. */
void     qsc_bn_mod(qsc_bn* r, const qsc_bn* a, int ka, const qsc_bn* m, int km);

void     qsc_mont_init(qsc_mont* m, const qsc_bn* n, int k);
void     qsc_mont_mul(const qsc_mont* m, qsc_bn* r, const qsc_bn* a, const qsc_bn* b);
void     qsc_mont_to(const qsc_mont* m, qsc_bn* r, const qsc_bn* a);     /* r = a*R mod n */
void     qsc_mont_from(const qsc_mont* m, qsc_bn* r, const qsc_bn* a);   /* r = a*R^-1 mod n */
/* r = base^exp mod n (normal form in and out). exp is big-endian bytes; always 2 mults per bit. */
void     qsc_mont_pow(const qsc_mont* m, qsc_bn* r, const qsc_bn* base,
                      const uint8_t* exp, size_t elen);

#endif
