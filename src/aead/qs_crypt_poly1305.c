/**
 * @file qs_crypt_poly1305.c
 * @brief Poly1305 one-time MAC (RFC 8439 section 2.5). 32-bit limb arithmetic.
 * Internal to the AEAD construction; not exposed as a standalone MAC.
 */
#include "qs_crypt/qs_crypt.h"
#include "../core/qs_crypt_internal.h"
#include <string.h>

typedef struct {
    uint32_t r[5], h[5], pad[4];
    size_t   leftover;
    uint8_t  buffer[16];
} poly1305_st;

static void poly_init(poly1305_st* st, const uint8_t key[32]) {
    st->r[0] = qsc_ld32le(key + 0)  & 0x3ffffff;
    st->r[1] = (qsc_ld32le(key + 3)  >> 2) & 0x3ffff03;
    st->r[2] = (qsc_ld32le(key + 6)  >> 4) & 0x3ffc0ff;
    st->r[3] = (qsc_ld32le(key + 9)  >> 6) & 0x3f03fff;
    st->r[4] = (qsc_ld32le(key + 12) >> 8) & 0x00fffff;
    for (int i = 0; i < 5; i++) st->h[i] = 0;
    for (int i = 0; i < 4; i++) st->pad[i] = qsc_ld32le(key + 16 + 4 * i);
    st->leftover = 0;
}

/* Processes whole 16-byte blocks. hibit = 1<<24 for full blocks, 0 for the final padded block. */
static void poly_blocks(poly1305_st* st, const uint8_t* m, size_t bytes, uint32_t hibit) {
    const uint32_t mask = 0x3ffffff;
    uint32_t r0 = st->r[0], r1 = st->r[1], r2 = st->r[2], r3 = st->r[3], r4 = st->r[4];
    uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    uint32_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2], h3 = st->h[3], h4 = st->h[4];
    while (bytes >= 16) {
        uint64_t d0, d1, d2, d3, d4;
        uint32_t c;
        h0 += qsc_ld32le(m + 0) & mask;
        h1 += (qsc_ld32le(m + 3) >> 2) & mask;
        h2 += (qsc_ld32le(m + 6) >> 4) & mask;
        h3 += (qsc_ld32le(m + 9) >> 6) & mask;
        h4 += (qsc_ld32le(m + 12) >> 8) | hibit;

        d0 = (uint64_t)h0*r0 + (uint64_t)h1*s4 + (uint64_t)h2*s3 + (uint64_t)h3*s2 + (uint64_t)h4*s1;
        d1 = (uint64_t)h0*r1 + (uint64_t)h1*r0 + (uint64_t)h2*s4 + (uint64_t)h3*s3 + (uint64_t)h4*s2;
        d2 = (uint64_t)h0*r2 + (uint64_t)h1*r1 + (uint64_t)h2*r0 + (uint64_t)h3*s4 + (uint64_t)h4*s3;
        d3 = (uint64_t)h0*r3 + (uint64_t)h1*r2 + (uint64_t)h2*r1 + (uint64_t)h3*r0 + (uint64_t)h4*s4;
        d4 = (uint64_t)h0*r4 + (uint64_t)h1*r3 + (uint64_t)h2*r2 + (uint64_t)h3*r1 + (uint64_t)h4*r0;

        c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & mask;
        d1 += c; c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & mask;
        d2 += c; c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & mask;
        d3 += c; c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & mask;
        d4 += c; c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & mask;
        h0 += c * 5; c = h0 >> 26; h0 &= mask; h1 += c;

        m += 16; bytes -= 16;
    }
    st->h[0] = h0; st->h[1] = h1; st->h[2] = h2; st->h[3] = h3; st->h[4] = h4;
}

static void poly_update(poly1305_st* st, const uint8_t* m, size_t bytes) {
    if (st->leftover) {
        size_t want = 16 - st->leftover;
        if (want > bytes) want = bytes;
        memcpy(st->buffer + st->leftover, m, want);
        bytes -= want; m += want; st->leftover += want;
        if (st->leftover < 16) return;
        poly_blocks(st, st->buffer, 16, 1u << 24);
        st->leftover = 0;
    }
    if (bytes >= 16) {
        size_t n = bytes & ~(size_t)15;
        poly_blocks(st, m, n, 1u << 24);
        m += n; bytes -= n;
    }
    if (bytes) {
        memcpy(st->buffer, m, bytes);
        st->leftover = bytes;
    }
}

static void poly_finish(poly1305_st* st, uint8_t mac[16]) {
    const uint32_t mask = 0x3ffffff;
    uint32_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2], h3 = st->h[3], h4 = st->h[4];
    uint32_t c, g0, g1, g2, g3, g4, sel, nsel;
    uint64_t f;

    if (st->leftover) {
        size_t i = st->leftover;
        st->buffer[i++] = 1;
        for (; i < 16; i++) st->buffer[i] = 0;
        poly_blocks(st, st->buffer, 16, 0);
        h0 = st->h[0]; h1 = st->h[1]; h2 = st->h[2]; h3 = st->h[3]; h4 = st->h[4];
    }

    c = h1 >> 26; h1 &= mask; h2 += c;
    c = h2 >> 26; h2 &= mask; h3 += c;
    c = h3 >> 26; h3 &= mask; h4 += c;
    c = h4 >> 26; h4 &= mask; h0 += c * 5;
    c = h0 >> 26; h0 &= mask; h1 += c;

    g0 = h0 + 5;  c = g0 >> 26; g0 &= mask;
    g1 = h1 + c;  c = g1 >> 26; g1 &= mask;
    g2 = h2 + c;  c = g2 >> 26; g2 &= mask;
    g3 = h3 + c;  c = g3 >> 26; g3 &= mask;
    g4 = h4 + c - (1u << 26);

    /* Constant-time select: use g if h >= p (g4 did not underflow), else h. */
    sel = (g4 >> 31) - 1;   /* 0 when underflow (h < p), all-ones otherwise */
    nsel = ~sel;
    h0 = (h0 & nsel) | (g0 & sel);
    h1 = (h1 & nsel) | (g1 & sel);
    h2 = (h2 & nsel) | (g2 & sel);
    h3 = (h3 & nsel) | (g3 & sel);
    h4 = (h4 & nsel) | (g4 & sel);

    h0 = (h0) | (h1 << 26);
    h1 = (h1 >> 6) | (h2 << 20);
    h2 = (h2 >> 12) | (h3 << 14);
    h3 = (h3 >> 18) | (h4 << 8);

    f = (uint64_t)h0 + st->pad[0];            qsc_st32le(mac + 0, (uint32_t)f);
    f = (uint64_t)h1 + st->pad[1] + (f >> 32); qsc_st32le(mac + 4, (uint32_t)f);
    f = (uint64_t)h2 + st->pad[2] + (f >> 32); qsc_st32le(mac + 8, (uint32_t)f);
    f = (uint64_t)h3 + st->pad[3] + (f >> 32); qsc_st32le(mac + 12, (uint32_t)f);

    qsc_secure_zero(st, sizeof *st);
}

/* AEAD MAC input per RFC 8439 2.8: aad||pad16||ct||pad16||le64(len aad)||le64(len ct). */
void qsc_poly1305_aead_mac(const uint8_t key[32],
                           const uint8_t* aad, size_t alen,
                           const uint8_t* ct, size_t clen,
                           uint8_t out[16]) {
    poly1305_st st;
    uint8_t lens[16];
    static const uint8_t zeros[16] = {0};
    poly_init(&st, key);
    poly_update(&st, aad, alen);
    if (alen % 16) poly_update(&st, zeros, 16 - alen % 16);
    poly_update(&st, ct, clen);
    if (clen % 16) poly_update(&st, zeros, 16 - clen % 16);
    qsc_st64le(lens, (uint64_t)alen);
    qsc_st64le(lens + 8, (uint64_t)clen);
    poly_update(&st, lens, 16);
    poly_finish(&st, out);
}
