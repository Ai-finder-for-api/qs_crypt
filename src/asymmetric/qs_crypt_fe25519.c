/**
 * @file qs_crypt_fe25519.c
 * @brief Field arithmetic over GF(2^255 - 19), five 51-bit limbs. Shared by X25519 and Ed25519.
 *
 * The 64x64->128 product uses 32-bit partial products (no __int128), so this builds
 * with MSVC, Clang, and GCC. Operations on secret data avoid data-dependent branches.
 */
#include "qs_crypt_fe25519.h"
#include "../core/qs_crypt_internal.h"
#include <string.h>

#define M51 ((uint64_t)0x7FFFFFFFFFFFFULL)
#define qsc_fe_ld64le(p)    qsc_ld64le(p)
#define qsc_fe_st64le(p, v) qsc_st64le((p), (v))

typedef struct { uint64_t lo, hi; } u128s;

static u128s u128_add(u128s a, u128s b) {
    u128s r;
    r.lo = a.lo + b.lo;
    r.hi = a.hi + b.hi + (r.lo < a.lo ? 1u : 0u);
    return r;
}

static u128s mul64(uint64_t a, uint64_t b) {
    uint64_t a0 = (uint32_t)a, a1 = a >> 32;
    uint64_t b0 = (uint32_t)b, b1 = b >> 32;
    uint64_t p00 = a0 * b0, p01 = a0 * b1, p10 = a1 * b0, p11 = a1 * b1;
    uint64_t mid = (p00 >> 32) + (uint32_t)p01 + (uint32_t)p10;
    u128s r;
    r.lo = (mid << 32) | (uint32_t)p00;
    r.hi = p11 + (p01 >> 32) + (p10 >> 32) + (mid >> 32);
    return r;
}

static u128s u128_shr51(u128s x) {
    u128s r;
    r.lo = (x.lo >> 51) | (x.hi << 13);
    r.hi = x.hi >> 51;
    return r;
}

static void fe_reduce(qsc_fe h, u128s r[5]) {
    uint64_t c;
    r[1] = u128_add(r[1], u128_shr51(r[0])); h[0] = r[0].lo & M51;
    r[2] = u128_add(r[2], u128_shr51(r[1])); h[1] = r[1].lo & M51;
    r[3] = u128_add(r[3], u128_shr51(r[2])); h[2] = r[2].lo & M51;
    r[4] = u128_add(r[4], u128_shr51(r[3])); h[3] = r[3].lo & M51;
    c = u128_shr51(r[4]).lo;                   h[4] = r[4].lo & M51;
    h[0] += 19 * c;
    c = h[0] >> 51; h[0] &= M51; h[1] += c;
}

static void fe_carry(qsc_fe h) {
    uint64_t c;
    c = h[0] >> 51; h[0] &= M51; h[1] += c;
    c = h[1] >> 51; h[1] &= M51; h[2] += c;
    c = h[2] >> 51; h[2] &= M51; h[3] += c;
    c = h[3] >> 51; h[3] &= M51; h[4] += c;
    c = h[4] >> 51; h[4] &= M51; h[0] += 19 * c;
    c = h[0] >> 51; h[0] &= M51; h[1] += c;
}

void qsc_fe_frombytes(qsc_fe h, const uint8_t s[32]) {
    h[0] = qsc_fe_ld64le(s) & M51;
    h[1] = (qsc_fe_ld64le(s + 6) >> 3) & M51;
    h[2] = (qsc_fe_ld64le(s + 12) >> 6) & M51;
    h[3] = (qsc_fe_ld64le(s + 19) >> 1) & M51;
    h[4] = (qsc_fe_ld64le(s + 24) >> 12) & M51;   /* bit 255 is masked off */
}

void qsc_fe_tobytes(uint8_t s[32], const qsc_fe in) {
    qsc_fe h;
    uint64_t g0, g1, g2, g3, g4, c, mask;
    memcpy(h, in, sizeof h);
    fe_carry(h);
    fe_carry(h);
    g0 = h[0] + 19; c = g0 >> 51; g0 &= M51;
    g1 = h[1] + c;  c = g1 >> 51; g1 &= M51;
    g2 = h[2] + c;  c = g2 >> 51; g2 &= M51;
    g3 = h[3] + c;  c = g3 >> 51; g3 &= M51;
    g4 = h[4] + c;  c = g4 >> 51; g4 &= M51;
    mask = (uint64_t)0 - c;
    h[0] = (g0 & mask) | (h[0] & ~mask);
    h[1] = (g1 & mask) | (h[1] & ~mask);
    h[2] = (g2 & mask) | (h[2] & ~mask);
    h[3] = (g3 & mask) | (h[3] & ~mask);
    h[4] = (g4 & mask) | (h[4] & ~mask);
    qsc_fe_st64le(s,      h[0] | (h[1] << 51));
    qsc_fe_st64le(s + 8,  (h[1] >> 13) | (h[2] << 38));
    qsc_fe_st64le(s + 16, (h[2] >> 26) | (h[3] << 25));
    qsc_fe_st64le(s + 24, (h[3] >> 39) | (h[4] << 12));
}

void qsc_fe_add(qsc_fe h, const qsc_fe f, const qsc_fe g) {
    for (int i = 0; i < 5; i++) h[i] = f[i] + g[i];
    fe_carry(h);
}

void qsc_fe_sub(qsc_fe h, const qsc_fe f, const qsc_fe g) {
    h[0] = f[0] + 0xFFFFFFFFFFFDAULL - g[0];
    for (int i = 1; i < 5; i++) h[i] = f[i] + 0xFFFFFFFFFFFFEULL - g[i];
    fe_carry(h);
}

void qsc_fe_neg(qsc_fe h, const qsc_fe f) {
    h[0] = 0xFFFFFFFFFFFDAULL - f[0];
    for (int i = 1; i < 5; i++) h[i] = 0xFFFFFFFFFFFFEULL - f[i];
    fe_carry(h);
}

void qsc_fe_mul(qsc_fe h, const qsc_fe f, const qsc_fe g) {
    uint64_t g1_19 = 19 * g[1], g2_19 = 19 * g[2], g3_19 = 19 * g[3], g4_19 = 19 * g[4];
    u128s r[5];
    r[0] = u128_add(u128_add(mul64(f[0], g[0]), mul64(f[1], g4_19)),
           u128_add(u128_add(mul64(f[2], g3_19), mul64(f[3], g2_19)), mul64(f[4], g1_19)));
    r[1] = u128_add(u128_add(mul64(f[0], g[1]), mul64(f[1], g[0])),
           u128_add(u128_add(mul64(f[2], g4_19), mul64(f[3], g3_19)), mul64(f[4], g2_19)));
    r[2] = u128_add(u128_add(mul64(f[0], g[2]), mul64(f[1], g[1])),
           u128_add(u128_add(mul64(f[2], g[0]), mul64(f[3], g4_19)), mul64(f[4], g3_19)));
    r[3] = u128_add(u128_add(mul64(f[0], g[3]), mul64(f[1], g[2])),
           u128_add(u128_add(mul64(f[2], g[1]), mul64(f[3], g[0])), mul64(f[4], g4_19)));
    r[4] = u128_add(u128_add(mul64(f[0], g[4]), mul64(f[1], g[3])),
           u128_add(u128_add(mul64(f[2], g[2]), mul64(f[3], g[1])), mul64(f[4], g[0])));
    fe_reduce(h, r);
}

void qsc_fe_sq(qsc_fe h, const qsc_fe f) { qsc_fe_mul(h, f, f); }

void qsc_fe_mul_small(qsc_fe h, const qsc_fe f, uint64_t k) {
    u128s r[5];
    for (int i = 0; i < 5; i++) r[i] = mul64(f[i], k);
    fe_reduce(h, r);
}

void qsc_fe_from_u64(qsc_fe h, uint64_t v) {
    memset(h, 0, sizeof(qsc_fe));
    h[0] = v & M51;
    h[1] = v >> 51;
}

void qsc_fe_cswap(qsc_fe a, qsc_fe b, uint64_t swap) {
    uint64_t mask = (uint64_t)0 - swap;
    for (int i = 0; i < 5; i++) {
        uint64_t t = mask & (a[i] ^ b[i]);
        a[i] ^= t;
        b[i] ^= t;
    }
}

/* z^(p-2): p-2 has every bit set from 0..254 except bits 2 and 4. */
void qsc_fe_invert(qsc_fe out, const qsc_fe z) {
    qsc_fe r;
    memcpy(r, z, sizeof r);
    for (int i = 253; i >= 0; i--) {
        qsc_fe_sq(r, r);
        if (i != 2 && i != 4) qsc_fe_mul(r, r, z);
    }
    memcpy(out, r, sizeof r);
}

/* out = base^e with e given as 32 little-endian bytes. Fixed iteration count. */
void qsc_fe_pow(qsc_fe out, const qsc_fe base, const uint8_t e[32]) {
    qsc_fe r;
    qsc_fe_from_u64(r, 1);
    for (int i = 254; i >= 0; i--) {
        qsc_fe_sq(r, r);
        uint64_t bit = (e[i >> 3] >> (i & 7)) & 1;
        qsc_fe t;
        qsc_fe_mul(t, r, base);
        qsc_fe_cswap(r, t, bit);       /* r = bit ? r*base : r */
    }
    memcpy(out, r, sizeof r);
}

int qsc_fe_iszero(const qsc_fe f) {
    uint8_t b[32], acc = 0;
    qsc_fe_tobytes(b, f);
    for (int i = 0; i < 32; i++) acc |= b[i];
    return acc == 0;
}

int qsc_fe_isneg(const qsc_fe f) {
    uint8_t b[32];
    qsc_fe_tobytes(b, f);
    return b[0] & 1;
}

int qsc_fe_eq(const qsc_fe a, const qsc_fe b) {
    uint8_t x[32], y[32], acc = 0;
    qsc_fe_tobytes(x, a);
    qsc_fe_tobytes(y, b);
    for (int i = 0; i < 32; i++) acc |= (uint8_t)(x[i] ^ y[i]);
    return acc == 0;
}
