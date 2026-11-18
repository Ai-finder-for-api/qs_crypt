/**
 * @file qs_crypt_rsa.c
 * @brief RSA with OAEP (SHA-256) encryption and PSS (SHA-256, 32-byte salt) signatures.
 *
 * Key generation: p, q by Miller-Rabin after trial division; e = 65537 (fixed).
 * Private exponent: d = (1 + phi * t) / e, where t = -(phi mod e)^-1 mod e. This needs only
 * big-by-small arithmetic, so no big-number division is required.
 * Decryption is m = c^d mod n directly (no CRT).
 *
 * Supported sizes: 2048, 3072, 4096 bits. Public exponent: fits 32 bits, odd, >= 3.
 */
#include "qs_crypt/qs_crypt.h"
#include "qs_crypt_rsa_internal.h"
#include "../core/qs_crypt_internal.h"
#include <string.h>

#define RSA_PUB_MAGIC   0x52534150u
#define RSA_PRIV_MAGIC  0x52534156u
#define HLEN            32
#define SLEN            32
#define RSA_E_DEFAULT   65537u
#define MR_ROUNDS       8
#define SIEVE_LIMIT     10000u

struct qsc_rsa_public {
    uint32_t  magic;
    int       kn;                 /* modulus limbs */
    uint32_t  bits;
    uint32_t  e;
    qsc_mont  mont;
};

struct qsc_rsa_private {
    uint32_t  magic;
    int       kn;
    uint32_t  bits;
    qsc_mont  mont;               /* mod n, used for the fault check */
    qsc_bn    d;
    /* CRT material, present only for keys produced by keygen (has_crt = 1). */
    int       has_crt;
    int       kp;                 /* limbs of p and q */
    uint32_t  e;                  /* public exponent, for the fault check */
    qsc_bn    p, q, dp, dq;       /* dp = d mod (p-1), dq = d mod (q-1) */
    qsc_mont  mp, mq;             /* Montgomery contexts for p and q */
    qsc_bn    qinv_m;             /* q^-1 mod p, stored as q^-1 * R mod p */
    qsc_bn    phim1;              /* phi(n) - 1, used to compute r^-1 = r^(phi-1) for blinding */
};

static int kn_for_bits(uint32_t bits) {
    switch (bits) {
        case 2048: return 64;
        case 3072: return 96;
        case 4096: return 128;
        default:   return 0;
    }
}

static int pub_ok(const qsc_rsa_public_t* p)   { return p && p->magic == RSA_PUB_MAGIC; }
static int priv_ok(const qsc_rsa_private_t* p) { return p && p->magic == RSA_PRIV_MAGIC; }

/* ---- hashing and MGF1 ------------------------------------------------------- */

static qsc_error_t hp(uint8_t out[HLEN],
                      const uint8_t* a, size_t al,
                      const uint8_t* b, size_t bl,
                      const uint8_t* c, size_t cl) {
    qsc_hash_ctx_t* h = NULL;
    qsc_digest_t d;
    qsc_error_t e = qsc_hash_begin(QSC_ALG_SHA2_256, &h);
    if (e != QSC_OK) return e;
    if (al) { e = qsc_hash_update(h, (qsc_slice_t){ a, al }); if (e != QSC_OK) { qsc_hash_destroy(h); return e; } }
    if (bl) { e = qsc_hash_update(h, (qsc_slice_t){ b, bl }); if (e != QSC_OK) { qsc_hash_destroy(h); return e; } }
    if (cl) { e = qsc_hash_update(h, (qsc_slice_t){ c, cl }); if (e != QSC_OK) { qsc_hash_destroy(h); return e; } }
    e = qsc_hash_finish(h, &d);            /* frees h */
    if (e != QSC_OK) return e;
    memcpy(out, d.data, HLEN);
    return QSC_OK;
}

static qsc_error_t mgf1(const uint8_t* seed, size_t slen, uint8_t* mask, size_t mlen) {
    uint8_t dg[HLEN];
    size_t off = 0;
    for (uint32_t ctr = 0; off < mlen; ctr++) {
        uint8_t c4[4] = { (uint8_t)(ctr >> 24), (uint8_t)(ctr >> 16), (uint8_t)(ctr >> 8), (uint8_t)ctr };
        qsc_error_t e = hp(dg, seed, slen, c4, 4, NULL, 0);
        if (e != QSC_OK) return e;
        size_t take = (mlen - off < HLEN) ? (mlen - off) : HLEN;
        memcpy(mask + off, dg, take);
        off += take;
    }
    return QSC_OK;
}

/* ---- prime generation ------------------------------------------------------- */

static uint32_t modinv_u32(uint32_t a, uint32_t m) {
    int64_t t = 0, nt = 1, r = m, nr = a;
    while (nr) {
        int64_t q = r / nr, tmp;
        tmp = t - q * nt; t = nt; nt = tmp;
        tmp = r - q * nr; r = nr; nr = tmp;
    }
    if (t < 0) t += m;
    return (uint32_t)t;
}

static int is_value(const qsc_bn* a, uint32_t v, int k) {
    qsc_bn t;
    qsc_bn_set_u32(&t, v);
    return qsc_bn_cmp(a, &t, k) == 0;
}

/* Miller-Rabin with small random bases. Returns 1 if probably prime. */
static int mr_test(const qsc_bn* p, int k) {
    qsc_mont m;
    qsc_bn pm1, d, x, ax, t, one;
    uint8_t dbytes[QSC_BN_MAX * 4];
    const size_t nb = (size_t)k * 4;
    int s = 0;

    qsc_mont_init(&m, p, k);
    qsc_bn_set_u32(&one, 1);
    qsc_bn_sub(&pm1, p, &one, k);
    qsc_bn_zero(&d);
    qsc_bn_copy(&d, &pm1, k);
    while (!(d.w[0] & 1u)) { qsc_bn_shr1(&d, k); s++; }
    qsc_bn_to_be(&d, k, dbytes, nb);

    for (int round = 0; round < MR_ROUNDS; round++) {
        uint8_t rb[4];
        if (qsc_random_bytes(rb, 4) != QSC_OK) return 0;
        uint32_t a = (((uint32_t)rb[0] << 24) | ((uint32_t)rb[1] << 16) |
                      ((uint32_t)rb[2] << 8) | rb[3]) & 0x3FFFFFFFu;
        a += 2;
        qsc_bn_set_u32(&ax, a);
        qsc_mont_pow(&m, &x, &ax, dbytes, nb);
        if (is_value(&x, 1, k) || qsc_bn_cmp(&x, &pm1, k) == 0) continue;

        int composite = 1;
        for (int r = 1; r < s; r++) {
            qsc_mont_to(&m, &t, &x);
            qsc_mont_mul(&m, &t, &t, &t);
            qsc_mont_from(&m, &x, &t);
            if (qsc_bn_cmp(&x, &pm1, k) == 0) { composite = 0; break; }
            if (is_value(&x, 1, k)) break;
        }
        if (composite) return 0;
    }
    return 1;
}

static qsc_error_t gen_prime(qsc_bn* p, int kp, uint32_t pbits,
                             const uint32_t* sp, int nsp) {
    uint8_t buf[QSC_BN_MAX * 4];
    const size_t nb = (size_t)kp * 4;
    for (;;) {
        qsc_bn tmp;
        int ok = 1;
        qsc_error_t e = qsc_random_bytes(buf, nb);
        if (e != QSC_OK) return e;
        qsc_bn_from_be(p, kp, buf, nb);
        p->w[kp - 1] |= 0xC0000000u;            /* top two bits set: exact modulus length */
        p->w[0] |= 1u;
        (void)pbits;
        for (int i = 0; i < nsp && ok; i++)
            if (qsc_bn_divmod_small(&tmp, p, sp[i], kp) == 0) ok = 0;
        if (ok && qsc_bn_divmod_small(&tmp, p, RSA_E_DEFAULT, kp) == 1) ok = 0;   /* e | p-1 */
        if (!ok) continue;
        if (mr_test(p, kp)) return QSC_OK;
    }
}

/* ---- keys -------------------------------------------------------------------- */

static void mk_public(qsc_rsa_public_t* pub, const qsc_bn* n, int kn, uint32_t bits, uint32_t e) {
    pub->magic = RSA_PUB_MAGIC;
    pub->kn = kn;
    pub->bits = bits;
    pub->e = e;
    qsc_mont_init(&pub->mont, n, kn);
}

qsc_error_t qsc_rsa_keygen(qs_u32 bits, qsc_rsa_public_t** pubo, qsc_rsa_private_t** privo) {
    const int kn = kn_for_bits(bits);
    const int kp = kn / 2;
    static uint32_t sp[1300];
    static uint8_t comp[SIEVE_LIMIT + 1];
    int nsp = 0;
    qsc_bn p, q, n, pm1, qm1, phi, one, tmp, X, dd;
    qsc_rsa_public_t* pub;
    qsc_rsa_private_t* priv;
    qsc_error_t err;

    if (!kn) return QSC_ERROR_INVALID_PARAMETERS;
    if (!pubo || !privo) return QSC_ERROR_INVALID_ARGUMENT;
    *pubo = NULL; *privo = NULL;

    /* Small primes for trial division (plain sieve; keygen-time only). */
    memset(comp, 0, sizeof comp);
    for (uint32_t i = 2; i <= SIEVE_LIMIT; i++) {
        if (comp[i]) continue;
        if (nsp < (int)(sizeof sp / sizeof sp[0])) sp[nsp++] = i;
        for (uint32_t j = i * i; j <= SIEVE_LIMIT; j += i) comp[j] = 1;
    }

    err = gen_prime(&p, kp, bits / 2, sp, nsp);
    if (err != QSC_OK) return err;
    do {
        err = gen_prime(&q, kp, bits / 2, sp, nsp);
        if (err != QSC_OK) return err;
    } while (qsc_bn_cmp(&p, &q, kp) == 0);

    qsc_bn_mul(&n, &p, &q, kp);                     /* kn limbs */

    qsc_bn_set_u32(&one, 1);
    qsc_bn_sub(&pm1, &p, &one, kp);
    qsc_bn_sub(&qm1, &q, &one, kp);
    qsc_bn_mul(&phi, &pm1, &qm1, kp);               /* kn limbs, phi < n */

    /* d = (1 + phi * t) / e with t = -(phi)^-1 mod e. phi is not divisible by e. */
    uint32_t r = qsc_bn_divmod_small(&tmp, &phi, RSA_E_DEFAULT, kn);
    if (r == 0) return QSC_ERROR_INVALID_PARAMETERS;
    uint32_t t = (RSA_E_DEFAULT - modinv_u32(r, RSA_E_DEFAULT)) % RSA_E_DEFAULT;
    X.w[kn] = qsc_bn_mul_small(&X, &phi, t, kn);
    qsc_bn_add(&X, &X, &one, kn + 1);
    uint32_t rem = qsc_bn_divmod_small(&dd, &X, RSA_E_DEFAULT, kn + 1);
    if (rem != 0 || dd.w[kn] != 0) return QSC_ERROR_INVALID_PARAMETERS;

    pub = (qsc_rsa_public_t*)qsc_alloc(sizeof *pub);
    priv = (qsc_rsa_private_t*)qsc_alloc(sizeof *priv);
    if (!pub || !priv) {
        if (pub) qsc_free_zero(pub, sizeof *pub);
        if (priv) qsc_free_zero(priv, sizeof *priv);
        return QSC_ERROR_OOM;
    }
    mk_public(pub, &n, kn, bits, RSA_E_DEFAULT);
    priv->magic = RSA_PRIV_MAGIC;
    priv->kn = kn;
    priv->bits = bits;
    qsc_mont_init(&priv->mont, &n, kn);
    qsc_bn_zero(&priv->d);
    qsc_bn_copy(&priv->d, &dd, kn);

    /* phi(n) - 1: used for blinding (r^-1 = r^(phi-1) mod n). */
    {
        qsc_bn one1;
        qsc_bn_set_u32(&one1, 1);
        qsc_bn_sub(&priv->phim1, &phi, &one1, kn);
    }

    priv->has_crt = 1;
    priv->kp = kp;
    priv->e = RSA_E_DEFAULT;
    qsc_bn_zero(&priv->p);
    qsc_bn_copy(&priv->p, &p, kp);
    qsc_bn_zero(&priv->q);
    qsc_bn_copy(&priv->q, &q, kp);
    qsc_bn_mod(&priv->dp, &dd, kn, &pm1, kp);
    qsc_bn_mod(&priv->dq, &dd, kn, &qm1, kp);
    qsc_mont_init(&priv->mp, &p, kp);
    qsc_mont_init(&priv->mq, &q, kp);
    {
        qsc_bn qp, two, pm2, qinv;
        uint8_t pm2b[QSC_BN_MAX * 4];
        qsc_bn_mod(&qp, &q, kp, &p, kp);
        qsc_bn_set_u32(&two, 2);
        qsc_bn_sub(&pm2, &p, &two, kp);
        qsc_bn_to_be(&pm2, kp, pm2b, (size_t)kp * 4);
        qsc_mont_pow(&priv->mp, &qinv, &qp, pm2b, (size_t)kp * 4);
        qsc_mont_to(&priv->mp, &priv->qinv_m, &qinv);
        qsc_secure_zero(pm2b, sizeof pm2b);
    }

    *pubo = pub;
    *privo = priv;
    return QSC_OK;
}

void qsc_rsa_public_destroy(qsc_rsa_public_t* pub) {
    if (pub_ok(pub)) qsc_free_zero(pub, sizeof *pub);
}

void qsc_rsa_private_destroy(qsc_rsa_private_t* priv) {
    if (priv_ok(priv)) qsc_free_zero(priv, sizeof *priv);
}

static void strip_zeros(const qs_u8** p, qs_u64* len) {
    while (*len && (*p)[0] == 0) { (*p)++; (*len)--; }
}

qsc_error_t qsc_rsa_public_create(qsc_slice_t n, qsc_slice_t e, qsc_rsa_public_t** out) {
    const qs_u8* np = n.data;
    const qs_u8* ep = e.data;
    qs_u64 nl = n.length, el = e.length;
    qsc_bn nb;
    uint32_t ev = 0;
    qsc_rsa_public_t* pub;

    if (!out || !np || !ep) return QSC_ERROR_INVALID_ARGUMENT;
    *out = NULL;
    strip_zeros(&np, &nl);
    strip_zeros(&ep, &el);
    if (nl != 256 && nl != 384 && nl != 512) return QSC_ERROR_KEY_SIZE_MISMATCH;
    if (el == 0 || el > 4) return QSC_ERROR_INVALID_KEY;
    for (qs_u64 i = 0; i < el; i++) ev = (ev << 8) | ep[i];
    if (ev < 3 || !(ev & 1u)) return QSC_ERROR_INVALID_KEY;

    uint32_t bits = (uint32_t)(nl * 8);
    int kn = kn_for_bits(bits);
    if (!kn) return QSC_ERROR_KEY_SIZE_MISMATCH;
    if (qsc_bn_from_be(&nb, kn, np, (size_t)nl) != 0) return QSC_ERROR_INVALID_KEY;
    if (!(nb.w[0] & 1u)) return QSC_ERROR_INVALID_KEY;

    pub = (qsc_rsa_public_t*)qsc_alloc(sizeof *pub);
    if (!pub) return QSC_ERROR_OOM;
    mk_public(pub, &nb, kn, bits, ev);
    *out = pub;
    return QSC_OK;
}

qs_u64 qsc_rsa_public_modulus_bytes(const qsc_rsa_public_t* pub) {
    return pub_ok(pub) ? (qs_u64)pub->kn * 4 : 0;
}

qs_u64 qsc_rsa_private_modulus_bytes(const qsc_rsa_private_t* priv) {
    return priv_ok(priv) ? (qs_u64)priv->kn * 4 : 0;
}

qsc_error_t qsc_rsa_private_create(qsc_slice_t n, qsc_slice_t d, qsc_rsa_private_t** out) {
    const qs_u8* np = n.data;
    const qs_u8* dp = d.data;
    qs_u64 nl = n.length, dl = d.length;
    qsc_bn nb, db;
    qsc_rsa_private_t* priv;
    if (!out || !np || !dp) return QSC_ERROR_INVALID_ARGUMENT;
    *out = NULL;
    strip_zeros(&np, &nl);
    strip_zeros(&dp, &dl);
    if (nl != 256 && nl != 384 && nl != 512) return QSC_ERROR_KEY_SIZE_MISMATCH;
    uint32_t bits = (uint32_t)(nl * 8);
    int kn = kn_for_bits(bits);
    if (!kn || dl == 0 || dl > (qs_u64)kn * 4) return QSC_ERROR_INVALID_KEY;
    if (qsc_bn_from_be(&nb, kn, np, (size_t)nl) != 0) return QSC_ERROR_INVALID_KEY;
    if (qsc_bn_from_be(&db, kn, dp, (size_t)dl) != 0) return QSC_ERROR_INVALID_KEY;
    if (!(nb.w[0] & 1u)) return QSC_ERROR_INVALID_KEY;
    if (qsc_bn_bit_len(&db, kn) == 0 || qsc_bn_cmp(&db, &nb, kn) >= 0) return QSC_ERROR_INVALID_KEY;

    priv = (qsc_rsa_private_t*)qsc_alloc(sizeof *priv);
    if (!priv) return QSC_ERROR_OOM;
    priv->magic = RSA_PRIV_MAGIC;
    priv->kn = kn;
    priv->bits = bits;
    qsc_mont_init(&priv->mont, &nb, kn);
    qsc_bn_zero(&priv->d);
    qsc_bn_copy(&priv->d, &db, kn);
    priv->has_crt = 0;
    *out = priv;
    return QSC_OK;
}

qsc_error_t qsc_rsa_public_get_modulus(const qsc_rsa_public_t* pub, qsc_buffer_t* n_out) {
    qs_u64 k;
    if (!pub_ok(pub) || !n_out || !n_out->data) return QSC_ERROR_INVALID_ARGUMENT;
    k = qsc_rsa_public_modulus_bytes(pub);
    if (n_out->length < k) { n_out->length = k; return QSC_ERROR_BUFFER_TOO_SMALL; }
    qsc_bn_to_be(&pub->mont.n, pub->kn, n_out->data, (size_t)k);
    n_out->length = k;
    return QSC_OK;
}

qsc_error_t qsc_rsa_public_get_exponent(const qsc_rsa_public_t* pub, qs_u32* e) {
    if (!pub_ok(pub) || !e) return QSC_ERROR_INVALID_ARGUMENT;
    *e = pub->e;
    return QSC_OK;
}

/* ---- exponent bytes (public exponent trimmed; private exponent full width) ---- */

static size_t e_bytes(uint32_t e, uint8_t out[4]) {
    out[0] = (uint8_t)(e >> 24); out[1] = (uint8_t)(e >> 16);
    out[2] = (uint8_t)(e >> 8);  out[3] = (uint8_t)e;
    size_t off = 0;
    while (off < 3 && out[off] == 0) off++;
    memmove(out, out + off, 4 - off);
    return 4 - off;
}

static void rsa_pub_op(const qsc_rsa_public_t* pub, qsc_bn* out, const qsc_bn* in) {
    uint8_t eb[4];
    size_t el = e_bytes(pub->e, eb);
    qsc_mont_pow(&pub->mont, out, in, eb, el);
}

/* out = in^d mod n. Returns 0 if the CRT result fails the fault check (out^e != in). */
static int rsa_priv_op(const qsc_rsa_private_t* priv, qsc_bn* out, const qsc_bn* in) {
    const int kn = priv->kn;
    if (!priv->has_crt) {
        uint8_t db[QSC_BN_MAX * 4];
        qsc_bn_to_be(&priv->d, kn, db, (size_t)kn * 4);
        qsc_mont_pow(&priv->mont, out, in, db, (size_t)kn * 4);
        qsc_secure_zero(db, sizeof db);
        return 1;
    }
    const int kp = priv->kp;
    uint8_t dpb[QSC_BN_MAX * 4], dqb[QSC_BN_MAX * 4];
    qsc_bn cp, cq, mp_, mq_, t, h, h2, hq, tmpq, tadd, chk;
    qsc_bn_to_be(&priv->dp, kp, dpb, (size_t)kp * 4);
    qsc_bn_to_be(&priv->dq, kp, dqb, (size_t)kp * 4);
    qsc_bn_mod(&cp, in, kn, &priv->p, kp);
    qsc_bn_mod(&cq, in, kn, &priv->q, kp);
    qsc_mont_pow(&priv->mp, &mp_, &cp, dpb, (size_t)kp * 4);
    qsc_mont_pow(&priv->mq, &mq_, &cq, dqb, (size_t)kp * 4);

    /* h = (m_p - m_q) * q^-1 mod p */
    qsc_bn_mod(&t, &mq_, kp, &priv->p, kp);
    uint32_t borrow = qsc_bn_sub(&h, &mp_, &t, kp);
    qsc_bn_add(&tadd, &h, &priv->p, kp);
    qsc_bn_sel(&h, &tadd, &h, 0u - borrow, kp);
    qsc_mont_mul(&priv->mp, &h2, &h, &priv->qinv_m);

    /* m = m_q + h * q */
    qsc_bn_mul(&hq, &h2, &priv->q, kp);            /* 2kp = kn limbs */
    qsc_bn_zero(&tmpq);
    qsc_bn_copy(&tmpq, &mq_, kp);
    qsc_bn_add(out, &hq, &tmpq, kn);

    /* Fault countermeasure: a faulty CRT result fails out^e == in. */
    uint8_t eb[4];
    size_t el = e_bytes(priv->e, eb);
    qsc_mont_pow(&priv->mont, &chk, out, eb, el);
    int ok = (qsc_bn_cmp(&chk, in, kn) == 0);

    qsc_secure_zero(dpb, sizeof dpb);
    qsc_secure_zero(dqb, sizeof dqb);
    return ok;
}

/* Blinded private operation: out = in^d mod n with a fresh random blinding factor r.
 * (in * r^e)^d = in^d * r, so out = (in r^e)^d * r^(phi-1), since r * r^(phi-1) = 1 mod n.
 * Imported keys have no phi(n), so they fall back to the unblinded operation. */
static int rsa_priv_op_blind(const qsc_rsa_private_t* priv, qsc_bn* out, const qsc_bn* in) {
    if (!priv->has_crt) return rsa_priv_op(priv, out, in);
    const int kn = priv->kn;
    const size_t nb = (size_t)kn * 4;
    uint8_t rb[QSC_BN_MAX * 4];
    qsc_bn r, re, a, cb, mprime, rinv;
    int got = 0;
    for (int attempt = 0; attempt < 8 && !got; attempt++) {
        if (qsc_random_bytes(rb, nb) != QSC_OK) break;
        qsc_bn_from_be(&r, kn, rb, nb);
        if (qsc_bn_bit_len(&r, kn) == 0 || qsc_bn_cmp(&r, &priv->mont.n, kn) >= 0) continue;
        got = 1;
    }
    qsc_secure_zero(rb, sizeof rb);
    if (!got) return 0;

    uint8_t eb[4];
    size_t el = e_bytes(priv->e, eb);
    qsc_mont_pow(&priv->mont, &re, &r, eb, el);           /* r^e mod n */
    qsc_mont_to(&priv->mont, &a, in);
    qsc_mont_mul(&priv->mont, &cb, &a, &re);              /* in * r^e mod n */

    if (!rsa_priv_op(priv, &mprime, &cb)) return 0;       /* (in r^e)^d = in^d * r */

    uint8_t pb[QSC_BN_MAX * 4];
    qsc_bn_to_be(&priv->phim1, kn, pb, nb);
    qsc_mont_pow(&priv->mont, &rinv, &r, pb, nb);         /* r^(phi-1) = r^-1 */
    qsc_secure_zero(pb, sizeof pb);

    qsc_mont_to(&priv->mont, &a, &mprime);
    qsc_mont_mul(&priv->mont, out, &a, &rinv);            /* in^d mod n */
    return 1;
}

/* ---- OAEP -------------------------------------------------------------------- */

qsc_error_t qsc_rsa_oaep_encrypt(const qsc_rsa_public_t* pub, qsc_slice_t msg, qsc_buffer_t* ct) {
    uint8_t em[QSC_BN_MAX * 4], mask[QSC_BN_MAX * 4], lh[HLEN];
    qsc_bn m, c;
    qsc_error_t err;
    if (!pub_ok(pub) || !ct || !ct->data) return QSC_ERROR_INVALID_ARGUMENT;
    if (msg.length && !msg.data) return QSC_ERROR_INVALID_ARGUMENT;
    const size_t k = (size_t)pub->kn * 4;
    if (msg.length > k - 2 * HLEN - 2) return QSC_ERROR_INVALID_PARAMETERS;
    if (ct->length < k) { ct->length = k; return QSC_ERROR_BUFFER_TOO_SMALL; }

    uint8_t* seed = em + 1;
    uint8_t* db = em + 1 + HLEN;
    const size_t dblen = k - HLEN - 1;

    if ((err = hp(lh, NULL, 0, NULL, 0, NULL, 0)) != QSC_OK) return err;
    em[0] = 0;
    if ((err = qsc_random_bytes(seed, HLEN)) != QSC_OK) return err;
    memcpy(db, lh, HLEN);
    memset(db + HLEN, 0, dblen - HLEN - 1 - msg.length);
    db[dblen - msg.length - 1] = 0x01;
    if (msg.length) memcpy(db + dblen - msg.length, msg.data, (size_t)msg.length);

    if ((err = mgf1(seed, HLEN, mask, dblen)) != QSC_OK) return err;
    for (size_t i = 0; i < dblen; i++) db[i] ^= mask[i];
    if ((err = mgf1(db, dblen, mask, HLEN)) != QSC_OK) return err;
    for (size_t i = 0; i < HLEN; i++) seed[i] ^= mask[i];

    qsc_bn_from_be(&m, pub->kn, em, k);            /* em[0] = 0, so m < n */
    rsa_pub_op(pub, &c, &m);
    qsc_bn_to_be(&c, pub->kn, ct->data, k);
    ct->length = k;

    qsc_secure_zero(em, sizeof em);
    qsc_secure_zero(mask, sizeof mask);
    return QSC_OK;
}

qsc_error_t qsc_rsa_oaep_decrypt(const qsc_rsa_private_t* priv, qsc_slice_t ct, qsc_buffer_t* msg) {
    uint8_t em[QSC_BN_MAX * 4], mask[QSC_BN_MAX * 4], lh[HLEN];
    qsc_bn c, m;
    qsc_error_t err;
    if (!priv_ok(priv) || !msg || !msg->data || !ct.data) return QSC_ERROR_INVALID_ARGUMENT;
    const size_t k = (size_t)priv->kn * 4;
    if (ct.length != k) return QSC_ERROR_DECRYPTION_FAILED;

    if (qsc_bn_from_be(&c, priv->kn, ct.data, k) != 0) return QSC_ERROR_DECRYPTION_FAILED;
    if (qsc_bn_cmp(&c, &priv->mont.n, priv->kn) >= 0) return QSC_ERROR_DECRYPTION_FAILED;

    if (!rsa_priv_op_blind(priv, &m, &c)) { err = QSC_ERROR_DECRYPTION_FAILED; goto done; }
    qsc_bn_to_be(&m, priv->kn, em, k);

    uint8_t* seed = em + 1;
    uint8_t* db = em + 1 + HLEN;
    const size_t dblen = k - HLEN - 1;
    uint32_t bad = (uint32_t)(em[0] != 0);

    if ((err = mgf1(db, dblen, mask, HLEN)) != QSC_OK) goto done;
    for (size_t i = 0; i < HLEN; i++) seed[i] ^= mask[i];
    if ((err = mgf1(seed, HLEN, mask, dblen)) != QSC_OK) goto done;
    for (size_t i = 0; i < dblen; i++) db[i] ^= mask[i];
    if ((err = hp(lh, NULL, 0, NULL, 0, NULL, 0)) != QSC_OK) goto done;

    /* Every check runs over the full block; failures accumulate into 'bad'. */
    uint32_t lhdiff = 0;
    for (size_t j = 0; j < HLEN; j++) lhdiff |= (uint32_t)(db[j] ^ lh[j]);
    bad |= (lhdiff != 0);

    /* Separator: the first nonzero byte after lHash must be 0x01. */
    size_t idx = 0;
    uint32_t found = 0;
    for (size_t j = HLEN; j < dblen; j++) {
        uint32_t nz = (db[j] != 0);
        uint32_t first = nz & ~found;
        bad |= first & (uint32_t)(db[j] != 1);
        size_t fmask = (size_t)0 - (size_t)first;
        idx = (idx & ~fmask) | (j & fmask);
        found |= nz;
    }
    bad |= ~found & 1u;

    if (bad) { err = QSC_ERROR_DECRYPTION_FAILED; goto done; }
    {
        size_t mlen = dblen - idx - 1;
        if (msg->length < mlen) { msg->length = mlen; err = QSC_ERROR_BUFFER_TOO_SMALL; goto done; }
        memcpy(msg->data, db + idx + 1, mlen);
        msg->length = mlen;
        err = QSC_OK;
    }
done:
    qsc_secure_zero(em, sizeof em);
    qsc_secure_zero(mask, sizeof mask);
    return err;
}

/* ---- PSS --------------------------------------------------------------------- */

qsc_error_t qsc_rsa_pss_sign(const qsc_rsa_private_t* priv, qsc_slice_t msg, qsc_buffer_t* sig) {
    uint8_t em[QSC_BN_MAX * 4], mask[QSC_BN_MAX * 4], mh[HLEN], salt[SLEN], h[HLEN];
    uint8_t mprime_pre[8] = { 0 };
    qsc_bn m, s;
    qsc_error_t err;
    if (!priv_ok(priv) || !sig || !sig->data) return QSC_ERROR_INVALID_ARGUMENT;
    if (msg.length && !msg.data) return QSC_ERROR_INVALID_ARGUMENT;
    const size_t k = (size_t)priv->kn * 4;
    if (sig->length < k) { sig->length = k; return QSC_ERROR_BUFFER_TOO_SMALL; }

    if ((err = hp(mh, msg.data, (size_t)msg.length, NULL, 0, NULL, 0)) != QSC_OK) return err;
    if ((err = qsc_random_bytes(salt, SLEN)) != QSC_OK) return err;
    if ((err = hp(h, mprime_pre, 8, mh, HLEN, salt, SLEN)) != QSC_OK) return err;

    const size_t dblen = k - HLEN - 1;
    const size_t ps = dblen - SLEN - 1;
    memset(em, 0, ps);
    em[ps] = 0x01;
    memcpy(em + ps + 1, salt, SLEN);

    if ((err = mgf1(h, HLEN, mask, dblen)) != QSC_OK) return err;
    for (size_t i = 0; i < dblen; i++) em[i] ^= mask[i];
    em[0] &= 0x7F;                                 /* emBits = 8k - 1 */
    memcpy(em + dblen, h, HLEN);
    em[k - 1] = 0xBC;

    qsc_bn_from_be(&m, priv->kn, em, k);           /* top bit clear, so m < n */
    if (!rsa_priv_op_blind(priv, &s, &m)) { qsc_secure_zero(em, sizeof em); return QSC_ERROR_INVALID_SIGNATURE; }
    qsc_bn_to_be(&s, priv->kn, sig->data, k);
    sig->length = k;

    qsc_secure_zero(em, sizeof em);
    qsc_secure_zero(mask, sizeof mask);
    return QSC_OK;
}

qsc_error_t qsc_rsa_pss_verify(const qsc_rsa_public_t* pub, qsc_slice_t msg, qsc_slice_t sig) {
    uint8_t em[QSC_BN_MAX * 4], mask[QSC_BN_MAX * 4], mh[HLEN], h2[HLEN];
    uint8_t mprime_pre[8] = { 0 };
    qsc_bn s, m;
    qsc_error_t err;
    if (!pub_ok(pub) || (!msg.data && msg.length) || !sig.data) return QSC_ERROR_INVALID_ARGUMENT;
    const size_t k = (size_t)pub->kn * 4;
    if (sig.length != k) return QSC_ERROR_INVALID_SIGNATURE;

    if (qsc_bn_from_be(&s, pub->kn, sig.data, k) != 0) return QSC_ERROR_INVALID_SIGNATURE;
    if (qsc_bn_cmp(&s, &pub->mont.n, pub->kn) >= 0) return QSC_ERROR_INVALID_SIGNATURE;

    rsa_pub_op(pub, &m, &s);
    qsc_bn_to_be(&m, pub->kn, em, k);

    const size_t dblen = k - HLEN - 1;
    const uint8_t* h = em + dblen;
    int ok = (em[k - 1] == 0xBC) && ((em[0] & 0x80) == 0);

    if ((err = mgf1(h, HLEN, mask, dblen)) != QSC_OK) return err;
    for (size_t i = 0; i < dblen; i++) em[i] ^= mask[i];
    em[0] &= 0x7F;

    const size_t ps = dblen - SLEN - 1;
    for (size_t i = 0; i < ps; i++) ok = ok && (em[i] == 0);
    ok = ok && (em[ps] == 0x01);
    const uint8_t* salt = em + ps + 1;

    if ((err = hp(mh, msg.data, (size_t)msg.length, NULL, 0, NULL, 0)) != QSC_OK) return err;
    if ((err = hp(h2, mprime_pre, 8, mh, HLEN, salt, SLEN)) != QSC_OK) return err;
    ok = ok && (memcmp(h2, h, HLEN) == 0);

    qsc_secure_zero(em, sizeof em);
    qsc_secure_zero(mask, sizeof mask);
    return ok ? QSC_OK : QSC_ERROR_INVALID_SIGNATURE;
}

#include "qs_crypt_rsa_ex.inc"
