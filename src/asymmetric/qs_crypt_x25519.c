/**
 * @file qs_crypt_x25519.c
 * @brief X25519 Diffie-Hellman (RFC 7748) on Curve25519. Uses the shared field module.
 */
#include "qs_crypt/qs_crypt.h"
#include "../core/qs_crypt_internal.h"
#include "qs_crypt_fe25519.h"
#include <string.h>

static void x25519_ladder(uint8_t out[32], const uint8_t scalar[32], const uint8_t u[32]) {
    uint8_t e[32];
    qsc_fe x1, x2, z2, x3, z3, A, AA, B, BB, E, C, D, DA, CB, t0, t1, a24;
    uint64_t swap = 0;
    memcpy(e, scalar, 32);
    e[0] &= 248; e[31] &= 127; e[31] |= 64;

    qsc_fe_frombytes(x1, u);
    qsc_fe_from_u64(x2, 1);
    qsc_fe_from_u64(z2, 0);
    memcpy(x3, x1, sizeof x3);
    qsc_fe_from_u64(z3, 1);
    qsc_fe_from_u64(a24, 121665);

    for (int t = 254; t >= 0; t--) {
        uint64_t k_t = (e[t >> 3] >> (t & 7)) & 1;
        swap ^= k_t;
        qsc_fe_cswap(x2, x3, swap);
        qsc_fe_cswap(z2, z3, swap);
        swap = k_t;

        qsc_fe_add(A, x2, z2);  qsc_fe_sq(AA, A);
        qsc_fe_sub(B, x2, z2);  qsc_fe_sq(BB, B);
        qsc_fe_sub(E, AA, BB);
        qsc_fe_add(C, x3, z3);
        qsc_fe_sub(D, x3, z3);
        qsc_fe_mul(DA, D, A);
        qsc_fe_mul(CB, C, B);
        qsc_fe_add(t0, DA, CB); qsc_fe_sq(x3, t0);
        qsc_fe_sub(t1, DA, CB); qsc_fe_sq(t1, t1); qsc_fe_mul(z3, x1, t1);
        qsc_fe_mul(x2, AA, BB);
        qsc_fe_mul_small(t0, E, 121665);
        qsc_fe_add(t0, AA, t0);
        qsc_fe_mul(z2, E, t0);
    }
    qsc_fe_cswap(x2, x3, swap);
    qsc_fe_cswap(z2, z3, swap);
    qsc_fe_invert(z2, z2);
    qsc_fe_mul(x2, x2, z2);
    qsc_fe_tobytes(out, x2);
    qsc_secure_zero(e, sizeof e);
}

static const uint8_t BASE_U[32] = { 9 };

qsc_error_t qsc_x25519_public(const qs_u8 priv[32], qs_u8 pub[32]) {
    if (!priv || !pub) return QSC_ERROR_INVALID_ARGUMENT;
    x25519_ladder(pub, priv, BASE_U);
    return QSC_OK;
}

qsc_error_t qsc_x25519_shared(const qs_u8 priv[32], const qs_u8 peer_pub[32], qs_u8 shared[32]) {
    uint8_t acc = 0;
    if (!priv || !peer_pub || !shared) return QSC_ERROR_INVALID_ARGUMENT;
    x25519_ladder(shared, priv, peer_pub);
    for (int i = 0; i < 32; i++) acc |= shared[i];
    if (acc == 0) return QSC_ERROR_INVALID_KEY;   /* low-order peer point (RFC 7748 6.1) */
    return QSC_OK;
}

qsc_error_t qsc_x25519_keygen(qs_u8 priv[32], qs_u8 pub[32]) {
    qsc_error_t e;
    if (!priv || !pub) return QSC_ERROR_INVALID_ARGUMENT;
    if ((e = qsc_random_bytes(priv, 32)) != QSC_OK) return e;
    return qsc_x25519_public(priv, pub);
}
