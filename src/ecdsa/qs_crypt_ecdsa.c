/**
 * @file qs_crypt_ecdsa.c
 * @brief ECDSA over P-256: Jacobian point arithmetic on Montgomery field elements, mod-n
 *        arithmetic on a second Montgomery context, SHA-256 digest.
 */
#include "qs_crypt/qs_crypt.h"
#include "qs_crypt/qs_crypt_ecdsa.h"
#include "../rsa/qs_crypt_rsa_internal.h"
#include <string.h>

#define W 8   /* 256-bit = 8 limbs */

static const char P_HEX[]  = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
static const char N_HEX[]  = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
static const char B_HEX[]  = "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b";
static const char GX_HEX[] = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
static const char GY_HEX[] = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";

typedef struct { qsc_bn X, Y, Z; } jpt;

typedef struct {
    qsc_mont fp, fn;          /* field mod p, scalar mod n */
    qsc_bn   p, n;            /* normal-form moduli */
    qsc_bn   b_m, one_m;      /* curve b and 1, in Montgomery form mod p */
    jpt      G;
    qs_u8    pm2[32], nm2[32];
} ec_ctx;

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

static void hex32(const char* h, qs_u8 out[32]) {
    for (int i = 0; i < 32; i++) out[i] = (qs_u8)((hexval(h[2 * i]) << 4) | hexval(h[2 * i + 1]));
}

static void load_hex(qsc_bn* r, const char* h) {
    qs_u8 b[32];
    hex32(h, b);
    qsc_bn_from_be(r, W, b, 32);
}

static int is_zero(const qsc_bn* a) {
    for (int i = 0; i < W; i++) if (a->w[i]) return 0;
    return 1;
}

/* Modular add and subtract for any modulus m; operands are in [0, m). */
static void madd(const qsc_bn* m, qsc_bn* r, const qsc_bn* a, const qsc_bn* b) {
    qsc_bn t, u;
    uint32_t carry = qsc_bn_add(&t, a, b, W);
    uint32_t borrow = qsc_bn_sub(&u, &t, m, W);
    uint32_t use = carry | (borrow == 0);
    qsc_bn_sel(r, &u, &t, 0u - use, W);
}

static void msub(const qsc_bn* m, qsc_bn* r, const qsc_bn* a, const qsc_bn* b) {
    qsc_bn t, u;
    uint32_t borrow = qsc_bn_sub(&t, a, b, W);
    qsc_bn_add(&u, &t, m, W);
    qsc_bn_sel(r, &u, &t, 0u - borrow, W);
}

static void fadd(const ec_ctx* c, qsc_bn* r, const qsc_bn* a, const qsc_bn* b) { madd(&c->p, r, a, b); }
static void fsub(const ec_ctx* c, qsc_bn* r, const qsc_bn* a, const qsc_bn* b) { msub(&c->p, r, a, b); }
static void fmul(const ec_ctx* c, qsc_bn* r, const qsc_bn* a, const qsc_bn* b) { qsc_mont_mul(&c->fp, r, a, b); }
static void ftom(const ec_ctx* c, qsc_bn* r, const qsc_bn* a) { qsc_mont_to(&c->fp, r, a); }

/* Mod-n multiply on normal-form values. */
static void nmul(const ec_ctx* c, qsc_bn* r, const qsc_bn* a, const qsc_bn* b) {
    qsc_bn am, bm, t;
    qsc_mont_to(&c->fn, &am, a);
    qsc_mont_to(&c->fn, &bm, b);
    qsc_mont_mul(&c->fn, &t, &am, &bm);
    qsc_mont_from(&c->fn, r, &t);
}

static void ninv(const ec_ctx* c, qsc_bn* r, const qsc_bn* a) {
    qsc_mont_pow(&c->fn, r, a, c->nm2, 32);
}

static void ec_init(ec_ctx* c) {
    qsc_bn two, t, one, gx, gy, bnorm;
    load_hex(&c->p, P_HEX);
    load_hex(&c->n, N_HEX);
    qsc_mont_init(&c->fp, &c->p, W);
    qsc_mont_init(&c->fn, &c->n, W);

    load_hex(&bnorm, B_HEX);
    ftom(c, &c->b_m, &bnorm);

    qsc_bn_set_u32(&one, 1);
    ftom(c, &c->one_m, &one);

    load_hex(&gx, GX_HEX);
    load_hex(&gy, GY_HEX);
    ftom(c, &c->G.X, &gx);
    ftom(c, &c->G.Y, &gy);
    c->G.Z = c->one_m;

    qsc_bn_set_u32(&two, 2);
    qsc_bn_sub(&t, &c->p, &two, W);
    qsc_bn_to_be(&t, W, c->pm2, 32);
    qsc_bn_sub(&t, &c->n, &two, W);
    qsc_bn_to_be(&t, W, c->nm2, 32);
}

static void set_inf(const ec_ctx* c, jpt* R) {
    R->X = c->one_m;
    R->Y = c->one_m;
    qsc_bn_zero(&R->Z);
}

/* dbl-2001-b, curve a = -3. Reads P fully before writing R. */
static void pt_double(const ec_ctx* c, jpt* R, const jpt* P) {
    qsc_bn delta, gamma, beta, t1, t2, t, alpha, b2, b4, b8, X3, Y3, Z3, g2, g4, g8;
    fmul(c, &delta, &P->Z, &P->Z);
    fmul(c, &gamma, &P->Y, &P->Y);
    fmul(c, &beta, &P->X, &gamma);
    fsub(c, &t1, &P->X, &delta);
    fadd(c, &t2, &P->X, &delta);
    fmul(c, &t, &t1, &t2);
    fadd(c, &alpha, &t, &t);
    fadd(c, &alpha, &alpha, &t);                 /* alpha = 3 (X - Z^2)(X + Z^2) */
    fadd(c, &b2, &beta, &beta);
    fadd(c, &b4, &b2, &b2);
    fadd(c, &b8, &b4, &b4);                      /* 8 beta */
    fmul(c, &X3, &alpha, &alpha);
    fsub(c, &X3, &X3, &b8);
    fadd(c, &t, &P->Y, &P->Z);
    fmul(c, &t, &t, &t);
    fsub(c, &t, &t, &gamma);
    fsub(c, &Z3, &t, &delta);
    fsub(c, &t, &b4, &X3);
    fmul(c, &t, &alpha, &t);
    fmul(c, &g2, &gamma, &gamma);
    fadd(c, &g4, &g2, &g2);
    fadd(c, &g8, &g4, &g4);
    fadd(c, &g8, &g8, &g8);                      /* 8 gamma^2 */
    fsub(c, &Y3, &t, &g8);
    R->X = X3;
    R->Y = Y3;
    R->Z = Z3;
}

/* add-2007-bl with infinity and equal-point handling. */
static void pt_add(const ec_ctx* c, jpt* R, const jpt* P, const jpt* Q) {
    if (is_zero(&P->Z)) { *R = *Q; return; }
    if (is_zero(&Q->Z)) { *R = *P; return; }
    qsc_bn z1z1, z2z2, u1, u2, s1, s2, h, rr, I, J, V, X3, Y3, Z3, t, tt;
    fmul(c, &z1z1, &P->Z, &P->Z);
    fmul(c, &z2z2, &Q->Z, &Q->Z);
    fmul(c, &u1, &P->X, &z2z2);
    fmul(c, &u2, &Q->X, &z1z1);
    fmul(c, &t, &Q->Z, &z2z2);
    fmul(c, &s1, &P->Y, &t);
    fmul(c, &t, &P->Z, &z1z1);
    fmul(c, &s2, &Q->Y, &t);
    fsub(c, &h, &u2, &u1);
    fsub(c, &t, &s2, &s1);
    fadd(c, &rr, &t, &t);                        /* r = 2 (S2 - S1) */
    if (is_zero(&h)) {
        if (is_zero(&rr)) pt_double(c, R, P);
        else set_inf(c, R);
        return;
    }
    fadd(c, &t, &h, &h);
    fmul(c, &I, &t, &t);                         /* I = (2H)^2 */
    fmul(c, &J, &h, &I);
    fmul(c, &V, &u1, &I);
    fmul(c, &X3, &rr, &rr);
    fsub(c, &X3, &X3, &J);
    fsub(c, &X3, &X3, &V);
    fsub(c, &X3, &X3, &V);
    fsub(c, &t, &V, &X3);
    fmul(c, &t, &rr, &t);
    fmul(c, &tt, &s1, &J);
    fadd(c, &tt, &tt, &tt);
    fsub(c, &Y3, &t, &tt);
    fadd(c, &t, &P->Z, &Q->Z);
    fmul(c, &t, &t, &t);
    fsub(c, &t, &t, &z1z1);
    fsub(c, &t, &t, &z2z2);
    fmul(c, &Z3, &t, &h);
    R->X = X3;
    R->Y = Y3;
    R->Z = Z3;
}

/* R = k * P. Double and add every bit; the add result is selected under a mask. */
static void pt_mul(const ec_ctx* c, jpt* R, const qsc_bn* k, const jpt* P) {
    jpt acc, t;
    set_inf(c, &acc);
    for (int i = 255; i >= 0; i--) {
        uint32_t bit = (k->w[i >> 5] >> (i & 31)) & 1u;
        pt_double(c, &acc, &acc);
        pt_add(c, &t, &acc, P);
        uint32_t mask = 0u - bit;
        qsc_bn_sel(&acc.X, &t.X, &acc.X, mask, W);
        qsc_bn_sel(&acc.Y, &t.Y, &acc.Y, mask, W);
        qsc_bn_sel(&acc.Z, &t.Z, &acc.Z, mask, W);
    }
    *R = acc;
}

/* Affine coordinates (normal form). Returns 0 for the point at infinity. */
static int to_affine(const ec_ctx* c, const jpt* P, qsc_bn* x, qsc_bn* y) {
    if (is_zero(&P->Z)) return 0;
    qsc_bn zn, zinv, zinv_m, zi2, zi3, xm, ym;
    qsc_mont_from(&c->fp, &zn, &P->Z);
    qsc_mont_pow(&c->fp, &zinv, &zn, c->pm2, 32);
    ftom(c, &zinv_m, &zinv);
    fmul(c, &zi2, &zinv_m, &zinv_m);
    fmul(c, &zi3, &zi2, &zinv_m);
    fmul(c, &xm, &P->X, &zi2);
    fmul(c, &ym, &P->Y, &zi3);
    qsc_mont_from(&c->fp, x, &xm);
    qsc_mont_from(&c->fp, y, &ym);
    return 1;
}

static void reduce_n(const ec_ctx* c, qsc_bn* a) {
    qsc_bn t;
    uint32_t borrow = qsc_bn_sub(&t, a, &c->n, W);
    qsc_bn_sel(a, &t, a, 0u - (borrow == 0), W);
}

/* Parses an uncompressed point into Montgomery-form Jacobian coordinates. */
static qsc_error_t load_pub(const ec_ctx* c, const qs_u8 pub[65], jpt* Q) {
    qsc_bn x, y, xm, ym, lhs, rhs, x2, x3, t;
    if (pub[0] != 0x04) return QSC_ERROR_INVALID_KEY;
    qsc_bn_from_be(&x, W, pub + 1, 32);
    qsc_bn_from_be(&y, W, pub + 33, 32);
    if (qsc_bn_cmp(&x, &c->p, W) >= 0 || qsc_bn_cmp(&y, &c->p, W) >= 0) return QSC_ERROR_INVALID_KEY;
    ftom(c, &xm, &x);
    ftom(c, &ym, &y);
    fmul(c, &lhs, &ym, &ym);
    fmul(c, &x2, &xm, &xm);
    fmul(c, &x3, &x2, &xm);
    fadd(c, &t, &xm, &xm);
    fadd(c, &t, &t, &xm);                        /* 3x */
    fsub(c, &rhs, &x3, &t);
    fadd(c, &rhs, &rhs, &c->b_m);
    if (qsc_bn_cmp(&lhs, &rhs, W) != 0) return QSC_ERROR_INVALID_KEY;
    Q->X = xm;
    Q->Y = ym;
    Q->Z = c->one_m;
    return QSC_OK;
}

static void encode_point(const qsc_bn* x, const qsc_bn* y, qs_u8 pub[65]) {
    pub[0] = 0x04;
    qsc_bn_to_be(x, W, pub + 1, 32);
    qsc_bn_to_be(y, W, pub + 33, 32);
}

static qsc_error_t load_priv(const ec_ctx* c, const qs_u8 priv[32], qsc_bn* d) {
    qsc_bn_from_be(d, W, priv, 32);
    if (is_zero(d) || qsc_bn_cmp(d, &c->n, W) >= 0) return QSC_ERROR_INVALID_KEY;
    return QSC_OK;
}

/* e = SHA-256(msg) reduced mod n. */
static void digest_mod_n(const ec_ctx* c, qsc_slice_t msg, qsc_bn* e) {
    qsc_digest_t dg;
    qsc_hash(QSC_ALG_SHA2_256, msg, &dg);
    qsc_bn_from_be(e, W, dg.data, 32);
    reduce_n(c, e);
}

qsc_error_t qsc_ecdsa_p256_public_from_private(const qs_u8 priv[32], qs_u8 pub[65]) {
    ec_ctx c;
    qsc_bn d, x, y;
    jpt R;
    if (!priv || !pub) return QSC_ERROR_INVALID_ARGUMENT;
    ec_init(&c);
    if (load_priv(&c, priv, &d) != QSC_OK) return QSC_ERROR_INVALID_KEY;
    pt_mul(&c, &R, &d, &c.G);
    if (!to_affine(&c, &R, &x, &y)) return QSC_ERROR_INVALID_KEY;
    encode_point(&x, &y, pub);
    return QSC_OK;
}

qsc_error_t qsc_ecdsa_p256_keygen(qs_u8 priv[32], qs_u8 pub[65]) {
    if (!priv || !pub) return QSC_ERROR_INVALID_ARGUMENT;
    ec_ctx c;
    ec_init(&c);
    for (int attempt = 0; attempt < 64; attempt++) {
        qsc_bn d;
        if (qsc_random_bytes(priv, 32) != QSC_OK) return QSC_ERROR_ENTROPY_UNAVAILABLE;
        if (load_priv(&c, priv, &d) == QSC_OK) return qsc_ecdsa_p256_public_from_private(priv, pub);
    }
    return QSC_ERROR_ENTROPY_UNAVAILABLE;
}

qsc_error_t qsc_ecdsa_p256_sign(const qs_u8 priv[32], qsc_slice_t msg, qs_u8 sig[64]) {
    if (!priv || !sig || (msg.length && !msg.data)) return QSC_ERROR_INVALID_ARGUMENT;
    ec_ctx c;
    qsc_bn d, e, k, R_x, R_y, r, kinv, t, s, tmp;
    jpt R;
    ec_init(&c);
    if (load_priv(&c, priv, &d) != QSC_OK) return QSC_ERROR_INVALID_KEY;
    digest_mod_n(&c, msg, &e);

    for (int attempt = 0; attempt < 64; attempt++) {
        qs_u8 kb[32];
        if (qsc_random_bytes(kb, 32) != QSC_OK) return QSC_ERROR_ENTROPY_UNAVAILABLE;
        qsc_bn_from_be(&k, W, kb, 32);
        qsc_secure_zero(kb, sizeof kb);
        if (is_zero(&k) || qsc_bn_cmp(&k, &c.n, W) >= 0) continue;

        pt_mul(&c, &R, &k, &c.G);
        if (!to_affine(&c, &R, &R_x, &R_y)) continue;
        r = R_x;
        reduce_n(&c, &r);
        if (is_zero(&r)) continue;

        ninv(&c, &kinv, &k);
        nmul(&c, &tmp, &r, &d);                  /* r d mod n */
        madd(&c.n, &t, &tmp, &e);                /* e + r d mod n */
        nmul(&c, &s, &kinv, &t);
        if (is_zero(&s)) continue;

        qsc_bn_to_be(&r, W, sig, 32);
        qsc_bn_to_be(&s, W, sig + 32, 32);
        qsc_secure_zero(&k, sizeof k);
        qsc_secure_zero(&kinv, sizeof kinv);
        return QSC_OK;
    }
    return QSC_ERROR_INVALID_PARAMETERS;
}

qsc_error_t qsc_ecdsa_p256_verify(const qs_u8 pub[65], qsc_slice_t msg, const qs_u8 sig[64]) {
    if (!pub || !sig || (msg.length && !msg.data)) return QSC_ERROR_INVALID_ARGUMENT;
    ec_ctx c;
    jpt Q, P1, P2, R;
    qsc_bn r, s, e, w, u1, u2, x, y;
    ec_init(&c);
    if (load_pub(&c, pub, &Q) != QSC_OK) return QSC_ERROR_INVALID_KEY;

    qsc_bn_from_be(&r, W, sig, 32);
    qsc_bn_from_be(&s, W, sig + 32, 32);
    if (is_zero(&r) || is_zero(&s) ||
        qsc_bn_cmp(&r, &c.n, W) >= 0 || qsc_bn_cmp(&s, &c.n, W) >= 0)
        return QSC_ERROR_INVALID_SIGNATURE;

    digest_mod_n(&c, msg, &e);
    ninv(&c, &w, &s);
    nmul(&c, &u1, &e, &w);
    nmul(&c, &u2, &r, &w);

    pt_mul(&c, &P1, &u1, &c.G);
    pt_mul(&c, &P2, &u2, &Q);
    pt_add(&c, &R, &P1, &P2);
    if (!to_affine(&c, &R, &x, &y)) return QSC_ERROR_INVALID_SIGNATURE;
    reduce_n(&c, &x);
    return qsc_bn_cmp(&x, &r, W) == 0 ? QSC_OK : QSC_ERROR_INVALID_SIGNATURE;
}
