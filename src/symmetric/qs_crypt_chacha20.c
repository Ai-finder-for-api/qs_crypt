/**
 * @file qs_crypt_chacha20.c
 * @brief ChaCha20 stream cipher per RFC 8439 section 2.3-2.4.
 * Counter wrap-around within one call is rejected.
 */
#include "qs_crypt/qs_crypt.h"
#include "../core/qs_crypt_internal.h"
#include <string.h>

#define QR(a, b, c, d) do {                              \
    a += b; d ^= a; d = qsc_rotl32(d, 16);               \
    c += d; b ^= c; b = qsc_rotl32(b, 12);               \
    a += b; d ^= a; d = qsc_rotl32(d, 8);                \
    c += d; b ^= c; b = qsc_rotl32(b, 7);                \
} while (0)

static void chacha_block(const uint32_t in[16], uint8_t out[64]) {
    uint32_t x[16];
    memcpy(x, in, sizeof x);
    for (int i = 0; i < 10; i++) {
        QR(x[0], x[4], x[8],  x[12]);  QR(x[1], x[5], x[9],  x[13]);
        QR(x[2], x[6], x[10], x[14]);  QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]);  QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8],  x[13]);  QR(x[3], x[4], x[9],  x[14]);
    }
    for (int i = 0; i < 16; i++) qsc_st32le(out + 4 * i, x[i] + in[i]);
    qsc_secure_zero(x, sizeof x);
}

qsc_error_t qsc_chacha20_xor(qsc_slice_t key, qsc_slice_t nonce, qs_u32 counter,
                             qsc_slice_t input, qs_u8* output) {
    uint32_t st[16];
    uint8_t ks[64];
    uint64_t blocks, off = 0;
    if (key.length != 32 || !key.data) return QSC_ERROR_KEY_SIZE_MISMATCH;
    if (nonce.length != 12 || !nonce.data) return QSC_ERROR_INVALID_NONCE;
    if (input.length && (!input.data || !output)) return QSC_ERROR_INVALID_ARGUMENT;
    blocks = (input.length + 63) / 64;
    if ((uint64_t)counter + blocks > ((uint64_t)1 << 32)) return QSC_ERROR_INVALID_PARAMETERS;

    st[0] = 0x61707865; st[1] = 0x3320646e; st[2] = 0x79622d32; st[3] = 0x6b206574;
    for (int i = 0; i < 8; i++) st[4 + i] = qsc_ld32le(key.data + 4 * i);
    st[12] = counter;
    for (int i = 0; i < 3; i++) st[13 + i] = qsc_ld32le(nonce.data + 4 * i);

    while (off < input.length) {
        uint64_t take = input.length - off;
        if (take > 64) take = 64;
        chacha_block(st, ks);
        for (uint64_t i = 0; i < take; i++)
            output[off + i] = input.data[off + i] ^ ks[i];
        off += take;
        st[12]++;
    }
    qsc_secure_zero(ks, sizeof ks);
    qsc_secure_zero(st, sizeof st);
    return QSC_OK;
}
