/**
 * @file qs_crypt_keccak.c
 * @brief Keccak-f[1600] sponge for SHA-3 (FIPS 202) and SHAKE256.
 *
 * Lane indexing is A[x + 5*y]. Rotation offsets are listed in the same order.
 * Absorption XORs bytes straight into the lane state, so no separate block buffer
 * is needed.
 */
#include "qs_crypt/qs_crypt.h"
#include "../core/qs_crypt_internal.h"
#include "qs_crypt_hash_internal.h"
#include <string.h>

static const uint64_t RC[24] = {
    0x0000000000000001ULL,0x0000000000008082ULL,0x800000000000808aULL,0x8000000080008000ULL,
    0x000000000000808bULL,0x0000000080000001ULL,0x8000000080008081ULL,0x8000000000008009ULL,
    0x000000000000008aULL,0x0000000000000088ULL,0x0000000080008009ULL,0x000000008000000aULL,
    0x000000008000808bULL,0x800000000000008bULL,0x8000000000008089ULL,0x8000000000008003ULL,
    0x8000000000008002ULL,0x8000000000000080ULL,0x000000000000800aULL,0x800000008000000aULL,
    0x8000000080008081ULL,0x8000000000008080ULL,0x0000000080000001ULL,0x8000000080008008ULL
};

static const unsigned ROT[25] = {
     0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14
};

static void keccak_f(uint64_t A[25]) {
    for (int round = 0; round < 24; round++) {
        uint64_t C[5], D[5], B[25];
        for (int x = 0; x < 5; x++)                       /* theta */
            C[x] = A[x] ^ A[x+5] ^ A[x+10] ^ A[x+15] ^ A[x+20];
        for (int x = 0; x < 5; x++)
            D[x] = C[(x + 4) % 5] ^ qsc_rotl64(C[(x + 1) % 5], 1);
        for (int i = 0; i < 25; i++)
            A[i] ^= D[i % 5];
        for (int x = 0; x < 5; x++)                       /* rho + pi */
            for (int y = 0; y < 5; y++) {
                int idx = x + 5 * y;
                int nx = y, ny = (2 * x + 3 * y) % 5;
                uint64_t v = A[idx];
                B[nx + 5 * ny] = ROT[idx] ? qsc_rotl64(v, (int)ROT[idx]) : v;
            }
        for (int y = 0; y < 5; y++)                       /* chi */
            for (int x = 0; x < 5; x++)
                A[x + 5*y] = B[x + 5*y] ^ ((~B[(x + 1) % 5 + 5*y]) & B[(x + 2) % 5 + 5*y]);
        A[0] ^= RC[round];                                /* iota */
    }
}

static void xor_byte(qsc_keccak_state* s, uint32_t pos, uint8_t b) {
    s->A[pos >> 3] ^= (uint64_t)b << (8 * (pos & 7));
}

static uint8_t get_byte(const qsc_keccak_state* s, uint32_t pos) {
    return (uint8_t)(s->A[pos >> 3] >> (8 * (pos & 7)));
}

void qsc_keccak_init(qsc_keccak_state* s, uint32_t rate, uint8_t dom) {
    memset(s, 0, sizeof *s);
    s->rate = rate;
    s->dom = dom;
}

void qsc_keccak_absorb(qsc_keccak_state* s, const uint8_t* d, size_t n) {
    for (size_t i = 0; i < n; i++) {
        xor_byte(s, s->pos, d[i]);
        if (++s->pos == s->rate) {
            keccak_f(s->A);
            s->pos = 0;
        }
    }
}

void qsc_keccak_squeeze(qsc_keccak_state* s, uint8_t* out, size_t n) {
    if (!s->squeezing) {
        /* pad10*1 with domain byte */
        xor_byte(s, s->pos, s->dom);
        xor_byte(s, s->rate - 1, 0x80);
        keccak_f(s->A);
        s->pos = 0;
        s->squeezing = 1;
    }
    for (size_t i = 0; i < n; i++) {
        if (s->pos == s->rate) {
            keccak_f(s->A);
            s->pos = 0;
        }
        out[i] = get_byte(s, s->pos++);
    }
}
