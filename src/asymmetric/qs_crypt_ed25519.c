/**
 * @file qs_crypt_ed25519.c
 * @brief Ed25519 signatures (RFC 8032, PureEd25519).
 *
 * Points: extended twisted Edwards coordinates (X:Y:Z:T), a = -1.
 * Scalar multiplication: fixed-length Montgomery-style ladder with conditional swaps
 * (no secret-dependent branches or table lookups).
 * Scalar reduction mod L: bitwise shift-and-conditional-subtract over 32-bit words.
 * Constants (d, sqrt(-1), base point) are derived from their definitions at run time,
 * and held in a per-call context so there is no shared mutable state between threads.
 */
#include "qs_crypt/qs_crypt.h"
#include "qs_crypt/qs_crypt_ed25519.h"
#include "../core/qs_crypt_internal.h"
#include "../hash/qs_crypt_hash_internal.h"
#include "qs_crypt_fe25519.h"
#include <string.h>

typedef struct { qsc_fe X, Y, Z, T; } ge;

typedef struct {
    qsc_fe d, d2, sqrtm1;
    ge     base;
} edc;

/* L = 2^252 + 27742317777372353535851937790883648493, little-endian. */
static const uint8_t L_LE[32] = {
    0xed,0xd3,0xf5,0x5c,0x1a,0x63,0x12,0x58,0xd6,0x9c,0xf7,0xa2,0xde,0xf9,0xde,0x14,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x10
};

/* (p-1)/4 and (p-5)/8 as little-endian exponents. */
static const uint8_t E_SQRTM1[32] = {
    0xfb,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x1f
};
static const uint8_t E_58[32] = {
    0xfd,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x0f
};

/* Base point encoding from RFC 8032 (y = 4/5, x positive). */
static const uint8_t BASE_ENC[32] = {
    0x58,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
    0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66
};

/* ---- points ----------------------------------------------------------------- */

static void ge_identity(ge* r) {
    qsc_fe_from_u64(r->X, 0);
    qsc_fe_from_u64(r->Y, 1);
    qsc_fe_from_u64(r->Z, 1);
    qsc_fe_from_u64(r->T, 0);
}

static void ge_add(ge* r, const ge* p, const ge* q, const edc* c) {
    qsc_fe A, B, C, D, E, F, G, H, t1, t2;
    qsc_fe_sub(t1, p->Y, p->X); qsc_fe_sub(t2, q->Y, q->X); qsc_fe_mul(A, t1, t2);
    qsc_fe_add(t1, p->Y, p->X); qsc_fe_add(t2, q->Y, q->X); qsc_fe_mul(B, t1, t2);
    qsc_fe_mul(C, p->T, q->T);  qsc_fe_mul(C, C, c->d2);
    qsc_fe_mul(D, p->Z, q->Z);  qsc_fe_add(D, D, D);
    qsc_fe_sub(E, B, A);
    qsc_fe_sub(F, D, C);
    qsc_fe_add(G, D, C);
    qsc_fe_add(H, B, A);
    qsc_fe_mul(r->X, E, F);
    qsc_fe_mul(r->Y, G, H);
    qsc_fe_mul(r->T, E, H);
    qsc_fe_mul(r->Z, F, G);
}

static void ge_dbl(ge* r, const ge* p) {
    qsc_fe A, B, C, D, E, G, F, H, t;
    qsc_fe_sq(A, p->X);
    qsc_fe_sq(B, p->Y);
    qsc_fe_sq(C, p->Z); qsc_fe_add(C, C, C);
    qsc_fe_neg(D, A);
    qsc_fe_add(t, p->X, p->Y); qsc_fe_sq(E, t); qsc_fe_sub(E, E, A); qsc_fe_sub(E, E, B);
    qsc_fe_add(G, D, B);
    qsc_fe_sub(F, G, C);
    qsc_fe_sub(H, D, B);
    qsc_fe_mul(r->X, E, F);
    qsc_fe_mul(r->Y, G, H);
    qsc_fe_mul(r->T, E, H);
    qsc_fe_mul(r->Z, F, G);
}

static void ge_cswap(ge* a, ge* b, uint64_t bit) {
    qsc_fe_cswap(a->X, b->X, bit);
    qsc_fe_cswap(a->Y, b->Y, bit);
    qsc_fe_cswap(a->Z, b->Z, bit);
    qsc_fe_cswap(a->T, b->T, bit);
}

/* r = k * p, k given as 32 little-endian bytes (top bit must be clear). */
static void ge_scalarmult(ge* r, const uint8_t k[32], const ge* p, const edc* c) {
    ge R0, R1;
    ge_identity(&R0);
    R1 = *p;
    for (int i = 254; i >= 0; i--) {
        uint64_t b = (k[i >> 3] >> (i & 7)) & 1;
        ge_cswap(&R0, &R1, b);
        ge_add(&R1, &R0, &R1, c);
        ge_dbl(&R0, &R0);
        ge_cswap(&R0, &R1, b);
    }
    *r = R0;
}

static void ge_encode(uint8_t out[32], const ge* p) {
    qsc_fe zi, x, y;
    qsc_fe_invert(zi, p->Z);
    qsc_fe_mul(x, p->X, zi);
    qsc_fe_mul(y, p->Y, zi);
    qsc_fe_tobytes(out, y);
    out[31] |= (uint8_t)(qsc_fe_isneg(x) << 7);
}

/* RFC 8032 5.1.3. Returns 1 on success, 0 if the encoding is not a valid point. */
static int ge_decode(ge* p, const uint8_t enc[32], const edc* c) {
    uint8_t bb[32], chk[32];
    int sign = enc[31] >> 7;
    qsc_fe y, y2, u, v, v3, v7, x, t, one, nu;
    memcpy(bb, enc, 32);
    bb[31] &= 0x7F;
    qsc_fe_frombytes(y, bb);
    qsc_fe_tobytes(chk, y);
    if (memcmp(chk, bb, 32) != 0) return 0;               /* non-canonical y >= p */

    qsc_fe_from_u64(one, 1);
    qsc_fe_sq(y2, y);
    qsc_fe_sub(u, y2, one);                               /* u = y^2 - 1 */
    qsc_fe_mul(t, c->d, y2);
    qsc_fe_add(v, t, one);                                /* v = d y^2 + 1 */

    qsc_fe_sq(t, v);  qsc_fe_mul(v3, t, v);               /* v^3 */
    qsc_fe_sq(t, v3); qsc_fe_mul(v7, t, v);               /* v^7 */
    qsc_fe_mul(t, u, v7);
    qsc_fe_pow(t, t, E_58);
    qsc_fe_mul(x, u, v3);
    qsc_fe_mul(x, x, t);                                  /* x = u v^3 (u v^7)^((p-5)/8) */

    qsc_fe_sq(t, x);
    qsc_fe_mul(t, t, v);                                  /* v x^2 */
    if (!qsc_fe_eq(t, u)) {
        qsc_fe_neg(nu, u);
        if (!qsc_fe_eq(t, nu)) return 0;                  /* not a square: no such point */
        qsc_fe_mul(x, x, c->sqrtm1);
    }
    if (qsc_fe_iszero(x) && sign) return 0;
    if (qsc_fe_isneg(x) != sign) qsc_fe_neg(x, x);

    memcpy(p->X, x, sizeof x);
    memcpy(p->Y, y, sizeof y);
    qsc_fe_from_u64(p->Z, 1);
    qsc_fe_mul(p->T, x, y);
    return 1;
}

static void edc_init(edc* c) {
    qsc_fe one, num, den, two;
    qsc_fe_from_u64(one, 1);
    qsc_fe_from_u64(num, 121665);
    qsc_fe_neg(num, num);                                 /* -121665 */
    qsc_fe_from_u64(den, 121666);
    qsc_fe_invert(den, den);
    qsc_fe_mul(c->d, num, den);                           /* d = -121665 / 121666 */
    qsc_fe_add(c->d2, c->d, c->d);
    qsc_fe_from_u64(two, 2);
    qsc_fe_pow(c->sqrtm1, two, E_SQRTM1);                 /* sqrt(-1) = 2^((p-1)/4) */
    if (!ge_decode(&c->base, BASE_ENC, c)) {
        /* Unreachable with correct field code; kept as a guard. */
        ge_identity(&c->base);
    }
    (void)one;
}

/* ---- scalars mod L (32-bit words, little-endian) ---------------------------- */

static void sc_words(uint32_t* w, const uint8_t* b, int n) {
    for (int i = 0; i < n; i++) w[i] = qsc_ld32le(b + 4 * i);
}

static void sc_to_bytes(uint8_t* b, const uint32_t* w, int n) {
    for (int i = 0; i < n; i++) qsc_st32le(b + 4 * i, w[i]);
}

/* a -= L if a >= L. Constant time: the subtraction always runs. */
static void sc_sub_L_masked(uint32_t a[8]) {
    uint32_t Lw[8], t[8];
    uint64_t borrow = 0;
    uint32_t mask;
    sc_words(Lw, L_LE, 8);
    for (int i = 0; i < 8; i++) {
        uint64_t d = (uint64_t)a[i] - Lw[i] - borrow;
        t[i] = (uint32_t)d;
        borrow = (d >> 63) & 1;
    }
    mask = (uint32_t)0 - (uint32_t)(1 - borrow);          /* all ones when a >= L */
    for (int i = 0; i < 8; i++) a[i] = (t[i] & mask) | (a[i] & ~mask);
}

/* Returns 1 if a < L (no secret-dependent branches). */
static int sc_lt_L(const uint32_t a[8]) {
    uint32_t Lw[8];
    uint64_t borrow = 0;
    sc_words(Lw, L_LE, 8);
    for (int i = 0; i < 8; i++) {
        uint64_t d = (uint64_t)a[i] - Lw[i] - borrow;
        borrow = (d >> 63) & 1;
    }
    return (int)borrow;
}

/* Reduce a 512-bit little-endian word array modulo L. */
static void sc_reduce_words(uint32_t out[8], const uint32_t w[16]) {
    uint32_t acc[8];
    memset(acc, 0, sizeof acc);
    for (int i = 511; i >= 0; i--) {
        uint32_t carry = (w[i >> 5] >> (i & 31)) & 1;
        for (int j = 0; j < 8; j++) {
            uint32_t nc = acc[j] >> 31;
            acc[j] = (acc[j] << 1) | carry;
            carry = nc;
        }
        sc_sub_L_masked(acc);
    }
    memcpy(out, acc, sizeof acc);
    qsc_secure_zero(acc, sizeof acc);
}

static void sc_reduce64(uint8_t out[32], const uint8_t in[64]) {
    uint32_t w[16], r[8];
    sc_words(w, in, 16);
    sc_reduce_words(r, w);
    sc_to_bytes(out, r, 8);
}

/* out = (a * b + c) mod L. */
static void sc_muladd(uint8_t out[32], const uint8_t a[32], const uint8_t b[32], const uint8_t c[32]) {
    uint32_t aw[8], bw[8], cw[8], p[16], r[8];
    uint64_t carry;
    sc_words(aw, a, 8);
    sc_words(bw, b, 8);
    sc_words(cw, c, 8);
    memset(p, 0, sizeof p);
    for (int i = 0; i < 8; i++) {
        carry = 0;
        for (int j = 0; j < 8; j++) {
            uint64_t t = (uint64_t)aw[i] * bw[j] + p[i + j] + carry;
            p[i + j] = (uint32_t)t;
            carry = t >> 32;
        }
        p[i + 8] = (uint32_t)carry;
    }
    carry = 0;
    for (int k = 0; k < 16; k++) {
        uint64_t t = (uint64_t)p[k] + (k < 8 ? cw[k] : 0) + carry;
        p[k] = (uint32_t)t;
        carry = t >> 32;
    }
    sc_reduce_words(r, p);
    sc_to_bytes(out, r, 8);
}

/* ---- hashing helper --------------------------------------------------------- */

static void sha512_3(uint8_t out[64], const uint8_t* a, size_t al,
                     const uint8_t* b, size_t bl, const uint8_t* c, size_t cl) {
    qsc_hstate h;
    qsc_hstate_init(&h, QSC_ALG_SHA2_512);
    qsc_hstate_update(&h, a, al);
    qsc_hstate_update(&h, b, bl);
    qsc_hstate_update(&h, c, cl);
    qsc_hstate_final(&h, out);
}

static void clamp(uint8_t a[32]) {
    a[0] &= 248;
    a[31] &= 127;
    a[31] |= 64;
}

/* ---- public API ------------------------------------------------------------- */

qsc_error_t qsc_ed25519_public(const uint8_t seed[32], uint8_t pub[32]) {
    uint8_t h[64], a[32];
    edc c;
    ge A;
    if (!seed || !pub) return QSC_ERROR_INVALID_ARGUMENT;
    sha512_3(h, seed, 32, NULL, 0, NULL, 0);
    memcpy(a, h, 32);
    clamp(a);
    edc_init(&c);
    ge_scalarmult(&A, a, &c.base, &c);
    ge_encode(pub, &A);
    qsc_secure_zero(h, sizeof h);
    qsc_secure_zero(a, sizeof a);
    return QSC_OK;
}

qsc_error_t qsc_ed25519_keygen(uint8_t seed[32], uint8_t pub[32]) {
    qsc_error_t e;
    if (!seed || !pub) return QSC_ERROR_INVALID_ARGUMENT;
    if ((e = qsc_random_bytes(seed, 32)) != QSC_OK) return e;
    return qsc_ed25519_public(seed, pub);
}

qsc_error_t qsc_ed25519_sign(const uint8_t seed[32], const uint8_t* msg, qs_u64 mlen_u,
                             uint8_t sig[64]) {
    size_t mlen = (size_t)mlen_u;
    uint8_t h[64], a[32], A[32], r[32], R[32], k[32], rh[64], kh[64];
    edc c;
    ge P;
    if (!seed || !sig || (mlen && !msg)) return QSC_ERROR_INVALID_ARGUMENT;
    sha512_3(h, seed, 32, NULL, 0, NULL, 0);
    memcpy(a, h, 32);
    clamp(a);
    edc_init(&c);
    ge_scalarmult(&P, a, &c.base, &c);
    ge_encode(A, &P);

    sha512_3(rh, h + 32, 32, msg, mlen, NULL, 0);
    sc_reduce64(r, rh);
    ge_scalarmult(&P, r, &c.base, &c);
    ge_encode(R, &P);

    sha512_3(kh, R, 32, A, 32, msg, mlen);
    sc_reduce64(k, kh);
    memcpy(sig, R, 32);
    sc_muladd(sig + 32, k, a, r);                          /* S = k*a + r mod L */

    qsc_secure_zero(h, sizeof h);
    qsc_secure_zero(a, sizeof a);
    qsc_secure_zero(r, sizeof r);
    qsc_secure_zero(rh, sizeof rh);
    return QSC_OK;
}

qsc_error_t qsc_ed25519_verify(const uint8_t pub[32], const uint8_t* msg, qs_u64 mlen_u,
                               const uint8_t sig[64]) {
    size_t mlen = (size_t)mlen_u;
    uint8_t kh[64], k[32], chk[32];
    uint32_t sw[8];
    edc c;
    ge A, sB, kA, P;
    if (!pub || !sig || (mlen && !msg)) return QSC_ERROR_INVALID_ARGUMENT;

    sc_words(sw, sig + 32, 8);
    if (!sc_lt_L(sw)) return QSC_ERROR_INVALID_SIGNATURE;   /* non-canonical S */

    edc_init(&c);
    if (!ge_decode(&A, pub, &c)) return QSC_ERROR_INVALID_SIGNATURE;

    sha512_3(kh, sig, 32, pub, 32, msg, mlen);
    sc_reduce64(k, kh);

    /* Check [S]B == R + [k]A  via  encode([S]B + [k](-A)) == R. */
    qsc_fe_neg(A.X, A.X);
    qsc_fe_neg(A.T, A.T);
    ge_scalarmult(&sB, sig + 32, &c.base, &c);
    ge_scalarmult(&kA, k, &A, &c);
    ge_add(&P, &sB, &kA, &c);
    ge_encode(chk, &P);
    if (memcmp(chk, sig, 32) != 0) return QSC_ERROR_INVALID_SIGNATURE;
    return QSC_OK;
}
