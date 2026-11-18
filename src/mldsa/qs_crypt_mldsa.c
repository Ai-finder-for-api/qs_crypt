/**
 * @file qs_crypt_mldsa.c
 * @brief ML-DSA-65 per FIPS 204: KeyGen, Sign (pure, with context), Verify.
 *
 * Ring: Z_q[x]/(x^256 + 1), q = 8380417, zeta = 1753 (bit-reversed powers, FIPS 204 Alg 41-42).
 * Hashes: H = SHAKE256; ExpandA uses SHAKE128. All rejection and sampling steps follow the
 * FIPS 204 algorithms; coefficient ranges are noted at each step.
 */
#include "qs_crypt/qs_crypt.h"
#include "qs_crypt/qs_crypt_mldsa.h"
#include "../hash/qs_crypt_hash_internal.h"
#include "../core/qs_crypt_internal.h"
#include <string.h>

#define MQ      8380417
#define MN      256
#define MDD     13
#define MK      6
#define ML      5
#define META    4
#define MTAU    49
#define MBETA   196
#define MGAMMA1 (1 << 19)
#define MGAMMA2 ((MQ - 1) / 32)
#define MOMEGA  55
#define MCT     48           /* c-tilde length, bytes (lambda / 4) */
#define MZB     20           /* bits per z coefficient: bitlen(2 gamma1 - 1) */
#define MW1B    4            /* bits per w1 coefficient: bitlen(15) */

typedef int32_t poly[MN];

static int32_t zetas[MN];
static int32_t ninv;
static int tables_ready = 0;

static int64_t pw(int64_t b, int64_t e) {
    int64_t r = 1;
    b %= MQ;
    while (e) {
        if (e & 1) r = (r * b) % MQ;
        b = (b * b) % MQ;
        e >>= 1;
    }
    return r;
}

static int bitrev8(int x) {
    int r = 0;
    for (int i = 0; i < 8; i++) { r = (r << 1) | (x & 1); x >>= 1; }
    return r;
}

static void init_tables(void) {
    if (tables_ready) return;
    for (int k = 0; k < MN; k++) zetas[k] = (int32_t)pw(1753, bitrev8(k));
    ninv = (int32_t)pw(MN, MQ - 2);
    tables_ready = 1;
}

/* Reduce to [0, q). */
static int32_t md(int64_t x) {
    int64_t r = x % MQ;
    return (int32_t)(r < 0 ? r + MQ : r);
}

/* Centred representative in (-q/2, q/2]. */
static int32_t centre(int64_t x) {
    int32_t r = md(x);
    return r > MQ / 2 ? r - MQ : r;
}

static void ntt(poly a) {
    int k = 0;
    for (int len = 128; len >= 1; len >>= 1)
        for (int start = 0; start < MN; start += 2 * len) {
            int32_t z = zetas[++k];
            for (int j = start; j < start + len; j++) {
                int32_t t = md((int64_t)z * a[j + len]);
                a[j + len] = md((int64_t)a[j] - t);
                a[j] = md((int64_t)a[j] + t);
            }
        }
}

static void intt(poly a) {
    int k = MN;
    for (int len = 1; len < MN; len <<= 1)
        for (int start = 0; start < MN; start += 2 * len) {
            int32_t z = md(-(int64_t)zetas[--k]);
            for (int j = start; j < start + len; j++) {
                int32_t t = a[j];
                a[j] = md((int64_t)t + a[j + len]);
                a[j + len] = md((int64_t)t - a[j + len]);
                a[j + len] = md((int64_t)z * a[j + len]);
            }
        }
    for (int j = 0; j < MN; j++) a[j] = md((int64_t)a[j] * ninv);
}

/* acc += a o b (pointwise, NTT domain). */
static void pw_mul_acc(poly acc, const poly a, const poly b) {
    for (int j = 0; j < MN; j++) acc[j] = md((int64_t)acc[j] + (int64_t)a[j] * b[j]);
}

/* ---- hashing ----------------------------------------------------------------- */

static void shake256(const uint8_t* a, size_t al, const uint8_t* b, size_t bl,
                     const uint8_t* c, size_t cl, uint8_t* out, size_t outl) {
    qsc_keccak_state s;
    qsc_keccak_init(&s, 136, 0x1F);
    if (al) qsc_keccak_absorb(&s, a, al);
    if (bl) qsc_keccak_absorb(&s, b, bl);
    if (cl) qsc_keccak_absorb(&s, c, cl);
    qsc_keccak_squeeze(&s, out, outl);
    qsc_secure_zero(&s, sizeof s);
}

/* ---- sampling ---------------------------------------------------------------- */

/* A[r][s] = RejNTTPoly(rho || s || r). Coefficients are 23-bit, rejected when >= q. */
static void expand_a(const uint8_t rho[32], poly A[MK][ML]) {
    for (int r = 0; r < MK; r++)
        for (int s = 0; s < ML; s++) {
            qsc_keccak_state st;
            uint8_t sb = (uint8_t)s, rb = (uint8_t)r;
            qsc_keccak_init(&st, 168, 0x1F);
            qsc_keccak_absorb(&st, rho, 32);
            qsc_keccak_absorb(&st, &sb, 1);
            qsc_keccak_absorb(&st, &rb, 1);
            int j = 0;
            while (j < MN) {
                uint8_t b[3];
                qsc_keccak_squeeze(&st, b, 3);
                int32_t v = (int32_t)b[0] | ((int32_t)b[1] << 8) | ((int32_t)(b[2] & 0x7F) << 16);
                if (v < MQ) A[r][s][j++] = v;
            }
            qsc_secure_zero(&st, sizeof st);
        }
}

/* s1[i] and s2[i] from RejBoundedPoly(rho' || le16(idx)) with eta = 4. */
static void expand_s(const uint8_t rhop[64], poly s1[ML], poly s2[MK]) {
    for (int idx = 0; idx < ML + MK; idx++) {
        qsc_keccak_state st;
        uint8_t ib[2] = { (uint8_t)(idx & 0xFF), (uint8_t)(idx >> 8) };
        poly* dst = (idx < ML) ? &s1[idx] : &s2[idx - ML];
        qsc_keccak_init(&st, 136, 0x1F);
        qsc_keccak_absorb(&st, rhop, 64);
        qsc_keccak_absorb(&st, ib, 2);
        int j = 0;
        while (j < MN) {
            uint8_t b;
            qsc_keccak_squeeze(&st, &b, 1);
            int z0 = b & 0x0F, z1 = b >> 4;
            if (z0 < 9) (*dst)[j++] = META - z0;
            if (z1 < 9 && j < MN) (*dst)[j++] = META - z1;
        }
        qsc_secure_zero(&st, sizeof st);
    }
}

/* Coefficients [0, n) of 'bits' bits each, LSB-first. */
static void unpack_bits(const uint8_t* in, int n, int bits, uint32_t* out) {
    uint64_t acc = 0;
    int nb = 0;
    size_t pos = 0;
    const uint32_t mask = (1u << bits) - 1u;
    for (int i = 0; i < n; i++) {
        while (nb < bits) {
            acc |= (uint64_t)in[pos++] << nb;
            nb += 8;
        }
        out[i] = (uint32_t)acc & mask;
        acc >>= bits;
        nb -= bits;
    }
}

static void pack_bits(const uint32_t* vals, int n, int bits, uint8_t* out) {
    uint64_t acc = 0;
    int nb = 0;
    size_t pos = 0;
    for (int i = 0; i < n; i++) {
        acc |= (uint64_t)vals[i] << nb;
        nb += bits;
        while (nb >= 8) {
            out[pos++] = (uint8_t)acc;
            acc >>= 8;
            nb -= 8;
        }
    }
}

/* y[r] = gamma1 - BitUnpack(H(rho'' || le16(kappa + r), 640 bytes)). */
static void expand_mask(const uint8_t rhopp[64], uint32_t kappa, poly y[ML]) {
    uint8_t buf[640];
    uint32_t v[MN];
    for (int r = 0; r < ML; r++) {
        uint32_t k = kappa + (uint32_t)r;
        uint8_t cb[2] = { (uint8_t)(k & 0xFF), (uint8_t)((k >> 8) & 0xFF) };
        shake256(rhopp, 64, cb, 2, NULL, 0, buf, sizeof buf);
        unpack_bits(buf, MN, MZB, v);
        for (int j = 0; j < MN; j++) y[r][j] = MGAMMA1 - (int32_t)v[j];
    }
}

/* SampleInBall: c has exactly MTAU coefficients in {-1, +1}. */
static void sample_in_ball(const uint8_t ct[MCT], poly c) {
    qsc_keccak_state st;
    uint8_t sb[8];
    memset(c, 0, sizeof(poly));
    qsc_keccak_init(&st, 136, 0x1F);
    qsc_keccak_absorb(&st, ct, MCT);
    qsc_keccak_squeeze(&st, sb, 8);
    uint64_t signs = 0;
    for (int i = 0; i < 8; i++) signs |= (uint64_t)sb[i] << (8 * i);
    for (int i = MN - MTAU; i < MN; i++) {
        uint8_t b;
        do {
            qsc_keccak_squeeze(&st, &b, 1);
        } while (b > i);
        c[i] = c[b];
        c[b] = (signs & 1) ? -1 : 1;
        signs >>= 1;
    }
    qsc_secure_zero(&st, sizeof st);
}

/* ---- rounding ---------------------------------------------------------------- */

static void power2round(int32_t r, int32_t* r1, int32_t* r0) {
    int32_t rp = md(r);
    int32_t t = rp & ((1 << MDD) - 1);
    if (t > (1 << (MDD - 1))) t -= (1 << MDD);
    *r0 = t;
    *r1 = (rp - t) >> MDD;
}

static void decompose(int32_t r, int32_t* r1, int32_t* r0) {
    int32_t rp = md(r);
    int32_t a = 2 * MGAMMA2;
    int32_t t = rp % a;
    if (t > MGAMMA2) t -= a;
    if (rp - t == MQ - 1) {
        *r1 = 0;
        *r0 = t - 1;
    } else {
        *r1 = (rp - t) / a;
        *r0 = t;
    }
}

static int32_t high_bits(int32_t r) { int32_t a, b; decompose(r, &a, &b); return a; }
static int32_t low_bits(int32_t r)  { int32_t a, b; decompose(r, &a, &b); return b; }

static int32_t use_hint(int h, int32_t r) {
    const int32_t m = (MQ - 1) / (2 * MGAMMA2);
    int32_t r1, r0;
    decompose(r, &r1, &r0);
    if (!h) return r1;
    if (r0 > 0) return (r1 + 1) % m;
    return (r1 - 1 + m) % m;
}

/* w1Encode: k polynomials, 4 bits per coefficient. */
static void w1_encode(poly w1[MK], uint8_t* out) {
    uint32_t v[MN];
    for (int i = 0; i < MK; i++) {
        for (int j = 0; j < MN; j++) v[j] = (uint32_t)w1[i][j];
        pack_bits(v, MN, MW1B, out + 128 * i);
    }
}

/* ---- encodings --------------------------------------------------------------- */

/* HintBitPack into 61 bytes; h has at most MOMEGA ones (checked by caller). */
static void hint_pack(uint8_t h[MK][MN], uint8_t* y) {
    int index = 0;
    memset(y, 0, MOMEGA + MK);
    for (int i = 0; i < MK; i++) {
        for (int j = 0; j < MN; j++)
            if (h[i][j]) y[index++] = (uint8_t)j;
        y[MOMEGA + i] = (uint8_t)index;
    }
}

/* HintBitUnpack: 0 on malformed encodings. */
static int hint_unpack(const uint8_t* y, uint8_t h[MK][MN]) {
    int index = 0;
    memset(h, 0, MK * MN);
    for (int i = 0; i < MK; i++) {
        int lim = y[MOMEGA + i];
        if (lim < index || lim > MOMEGA) return 0;
        int first = index;
        while (index < lim) {
            if (index > first && y[index - 1] >= y[index]) return 0;
            h[i][y[index]] = 1;
            index++;
        }
    }
    for (int i = index; i < MOMEGA; i++)
        if (y[i] != 0) return 0;
    return 1;
}

/* ---- key generation ---------------------------------------------------------- */

static void keygen_internal(const uint8_t xi[32], uint8_t* pk, uint8_t* sk) {
    uint8_t inb[34], g[128];
    memcpy(inb, xi, 32);
    inb[32] = MK;
    inb[33] = ML;
    shake256(inb, 34, NULL, 0, NULL, 0, g, sizeof g);
    const uint8_t* rho = g;
    const uint8_t* rhop = g + 32;
    const uint8_t* kk = g + 96;

    poly A[MK][ML];
    poly s1[ML], s2[MK], s1h[ML], t[MK];
    expand_a(rho, A);
    expand_s(rhop, s1, s2);
    for (int i = 0; i < ML; i++) { memcpy(s1h[i], s1[i], sizeof(poly)); ntt(s1h[i]); }

    uint32_t tv[MN];
    poly t1[MK], t0[MK];
    for (int i = 0; i < MK; i++) {
        poly acc;
        memset(acc, 0, sizeof acc);
        for (int j = 0; j < ML; j++) pw_mul_acc(acc, A[i][j], s1h[j]);
        intt(acc);
        for (int j = 0; j < MN; j++) t[i][j] = md((int64_t)acc[j] + s2[i][j]);
        for (int j = 0; j < MN; j++) {
            int32_t r1, r0;
            power2round(t[i][j], &r1, &r0);
            t1[i][j] = r1;
            t0[i][j] = r0;
        }
    }

    /* pk = rho || SimpleBitPack(t1, 10) */
    memcpy(pk, rho, 32);
    for (int i = 0; i < MK; i++) {
        for (int j = 0; j < MN; j++) tv[j] = (uint32_t)t1[i][j];
        pack_bits(tv, MN, 10, pk + 32 + 320 * i);
    }

    uint8_t tr[64];
    shake256(pk, QSC_MLDSA65_PK_BYTES, NULL, 0, NULL, 0, tr, sizeof tr);

    /* sk = rho || K || tr || BitPack(s1, eta) || BitPack(s2, eta) || BitPack(t0) */
    uint8_t* p = sk;
    memcpy(p, rho, 32); p += 32;
    memcpy(p, kk, 32);  p += 32;
    memcpy(p, tr, 64);  p += 64;
    for (int i = 0; i < ML; i++) {
        for (int j = 0; j < MN; j++) tv[j] = (uint32_t)(META - s1[i][j]);
        pack_bits(tv, MN, 4, p); p += 128;
    }
    for (int i = 0; i < MK; i++) {
        for (int j = 0; j < MN; j++) tv[j] = (uint32_t)(META - s2[i][j]);
        pack_bits(tv, MN, 4, p); p += 128;
    }
    for (int i = 0; i < MK; i++) {
        for (int j = 0; j < MN; j++) tv[j] = (uint32_t)((1 << (MDD - 1)) - t0[i][j]);
        pack_bits(tv, MN, MDD, p); p += 416;
    }

    qsc_secure_zero(g, sizeof g);
    qsc_secure_zero(s1, sizeof s1);
    qsc_secure_zero(s2, sizeof s2);
    qsc_secure_zero(s1h, sizeof s1h);
}

/* ---- sign -------------------------------------------------------------------- */

static qsc_error_t sign_internal(const uint8_t* sk, const uint8_t* mp, size_t mpl,
                                 const uint8_t rnd[32], uint8_t* sig) {
    const uint8_t* rho = sk;
    const uint8_t* kk = sk + 32;
    const uint8_t* tr = sk + 64;
    poly A[MK][ML];
    poly s1[ML], s2[MK], t0[MK], s1h[ML], s2h[MK], t0h[MK];
    uint32_t uv[MN];

    for (int i = 0; i < ML; i++) {
        unpack_bits(sk + 128 + 128 * i, MN, 4, uv);
        for (int j = 0; j < MN; j++) s1[i][j] = META - (int32_t)uv[j];
        memcpy(s1h[i], s1[i], sizeof(poly));
        ntt(s1h[i]);
    }
    for (int i = 0; i < MK; i++) {
        unpack_bits(sk + 128 + 640 + 128 * i, MN, 4, uv);
        for (int j = 0; j < MN; j++) s2[i][j] = META - (int32_t)uv[j];
        memcpy(s2h[i], s2[i], sizeof(poly));
        ntt(s2h[i]);
    }
    for (int i = 0; i < MK; i++) {
        unpack_bits(sk + 768 + 768 + 416 * i, MN, MDD, uv);
        for (int j = 0; j < MN; j++) t0[i][j] = (1 << (MDD - 1)) - (int32_t)uv[j];
        memcpy(t0h[i], t0[i], sizeof(poly));
        ntt(t0h[i]);
    }
    expand_a(rho, A);

    uint8_t mu[64], rhopp[64];
    shake256(tr, 64, mp, mpl, NULL, 0, mu, sizeof mu);
    shake256(kk, 32, rnd, 32, mu, 64, rhopp, sizeof rhopp);

    poly y[ML], yh[ML], w[MK], ct0[MK], c, ch, z[ML];
    uint8_t w1enc[MK * 128], hint[MK][MN];
    uint32_t kappa = 0;
    for (uint32_t attempt = 0; attempt < 100000; attempt++) {
        expand_mask(rhopp, kappa, y);
        kappa += ML;

        for (int i = 0; i < ML; i++) { memcpy(yh[i], y[i], sizeof(poly)); ntt(yh[i]); }
        poly w1[MK];
        for (int i = 0; i < MK; i++) {
            poly acc;
            memset(acc, 0, sizeof acc);
            for (int j = 0; j < ML; j++) pw_mul_acc(acc, A[i][j], yh[j]);
            intt(acc);
            memcpy(w[i], acc, sizeof(poly));
            for (int j = 0; j < MN; j++) w1[i][j] = high_bits(md(acc[j]));
        }
        w1_encode(w1, w1enc);

        uint8_t ct[MCT];
        shake256(mu, 64, w1enc, MK * 128, NULL, 0, ct, sizeof ct);
        sample_in_ball(ct, c);
        memcpy(ch, c, sizeof(poly));
        ntt(ch);

        int reject = 0;
        for (int i = 0; i < ML && !reject; i++) {
            poly prod;
            for (int j = 0; j < MN; j++) prod[j] = md((int64_t)ch[j] * s1h[i][j]);
            intt(prod);
            for (int j = 0; j < MN; j++) {
                z[i][j] = y[i][j] + centre(prod[j]);
                if (z[i][j] >= MGAMMA1 - MBETA || z[i][j] <= -(MGAMMA1 - MBETA)) reject = 1;
            }
        }
        for (int i = 0; i < MK && !reject; i++) {
            poly prod;
            for (int j = 0; j < MN; j++) prod[j] = md((int64_t)ch[j] * s2h[i][j]);
            intt(prod);
            for (int j = 0; j < MN; j++) {
                int32_t r = md((int64_t)w[i][j] - centre(prod[j]));
                int32_t r0 = low_bits(r);
                if (r0 >= MGAMMA2 - MBETA || r0 <= -(MGAMMA2 - MBETA)) reject = 1;
            }
        }
        for (int i = 0; i < MK && !reject; i++) {
            poly prod;
            for (int j = 0; j < MN; j++) prod[j] = md((int64_t)ch[j] * t0h[i][j]);
            intt(prod);
            for (int j = 0; j < MN; j++) {
                int32_t v = centre(prod[j]);
                ct0[i][j] = v;
                if (v >= MGAMMA2 || v <= -MGAMMA2) reject = 1;
            }
        }
        if (reject) continue;

        /* hint h = MakeHint(-ct0, w - cs2 + ct0), count the ones */
        int ones = 0;
        for (int i = 0; i < MK; i++) {
            poly prod;
            for (int j = 0; j < MN; j++) prod[j] = md((int64_t)ch[j] * s2h[i][j]);
            intt(prod);
            for (int j = 0; j < MN; j++) {
                int32_t base = md((int64_t)w[i][j] - centre(prod[j]));
                int32_t r = md((int64_t)base + ct0[i][j]);
                int h = (high_bits(r) != high_bits(base));
                hint[i][j] = (uint8_t)h;
                ones += h;
            }
        }
        if (ones > MOMEGA) continue;

        /* sigma = c~ || BitPack(z, gamma1) || HintBitPack(h) */
        memcpy(sig, ct, MCT);
        uint8_t* p = sig + MCT;
        for (int i = 0; i < ML; i++) {
            for (int j = 0; j < MN; j++) uv[j] = (uint32_t)(MGAMMA1 - z[i][j]);
            pack_bits(uv, MN, MZB, p);
            p += 640;
        }
        hint_pack(hint, p);

        qsc_secure_zero(y, sizeof y);
        qsc_secure_zero(s1, sizeof s1);
        qsc_secure_zero(s2, sizeof s2);
        qsc_secure_zero(t0, sizeof t0);
        qsc_secure_zero(s1h, sizeof s1h);
        qsc_secure_zero(s2h, sizeof s2h);
        qsc_secure_zero(t0h, sizeof t0h);
        return QSC_OK;
    }
    return QSC_ERROR_INVALID_PARAMETERS;
}

/* ---- verify ------------------------------------------------------------------ */

static qsc_error_t verify_internal(const uint8_t* pk, const uint8_t* mp, size_t mpl,
                                   const uint8_t* sig) {
    const uint8_t* rho = pk;
    poly A[MK][ML], t1[MK], zz[ML], zh[ML], ch, c;
    uint32_t uv[MN];
    uint8_t h[MK][MN];

    for (int i = 0; i < MK; i++) {
        unpack_bits(pk + 32 + 320 * i, MN, 10, uv);
        for (int j = 0; j < MN; j++) t1[i][j] = (int32_t)uv[j];
    }

    const uint8_t* ct = sig;
    for (int i = 0; i < ML; i++) {
        unpack_bits(sig + MCT + 640 * i, MN, MZB, uv);
        for (int j = 0; j < MN; j++) zz[i][j] = MGAMMA1 - (int32_t)uv[j];
    }
    if (!hint_unpack(sig + MCT + 640 * ML, h)) return QSC_ERROR_INVALID_SIGNATURE;

    for (int i = 0; i < ML; i++)
        for (int j = 0; j < MN; j++)
            if (zz[i][j] >= MGAMMA1 - MBETA || zz[i][j] <= -(MGAMMA1 - MBETA))
                return QSC_ERROR_INVALID_SIGNATURE;

    expand_a(rho, A);
    uint8_t tr[64], mu[64];
    shake256(pk, QSC_MLDSA65_PK_BYTES, NULL, 0, NULL, 0, tr, sizeof tr);
    shake256(tr, 64, mp, mpl, NULL, 0, mu, sizeof mu);

    sample_in_ball(ct, c);
    memcpy(ch, c, sizeof(poly));
    ntt(ch);
    for (int i = 0; i < ML; i++) { memcpy(zh[i], zz[i], sizeof(poly)); ntt(zh[i]); }

    uint8_t w1enc[MK * 128];
    poly w1[MK];
    for (int i = 0; i < MK; i++) {
        poly acc, tt;
        memset(acc, 0, sizeof acc);
        for (int j = 0; j < ML; j++) pw_mul_acc(acc, A[i][j], zh[j]);
        for (int j = 0; j < MN; j++) tt[j] = md((int64_t)t1[i][j] * (1 << MDD));
        ntt(tt);
        poly cc;
        for (int j = 0; j < MN; j++) cc[j] = md((int64_t)ch[j] * tt[j]);
        for (int j = 0; j < MN; j++) acc[j] = md((int64_t)acc[j] - cc[j]);
        intt(acc);
        for (int j = 0; j < MN; j++) w1[i][j] = use_hint(h[i][j], md(acc[j]));
    }
    w1_encode(w1, w1enc);

    uint8_t ct2[MCT];
    shake256(mu, 64, w1enc, MK * 128, NULL, 0, ct2, sizeof ct2);
    return memcmp(ct, ct2, MCT) == 0 ? QSC_OK : QSC_ERROR_INVALID_SIGNATURE;
}

/* ---- public API -------------------------------------------------------------- */

/* M' = 0x00 || |ctx| || ctx || msg (pure ML-DSA). Caller frees the result. */
static qsc_error_t format_message(qsc_slice_t msg, qsc_slice_t ctx, uint8_t** out, size_t* outl) {
    if (ctx.length > QSC_MLDSA65_CTX_MAX) return QSC_ERROR_INVALID_PARAMETERS;
    if ((ctx.length && !ctx.data) || (msg.length && !msg.data)) return QSC_ERROR_INVALID_ARGUMENT;
    size_t n = 2 + (size_t)ctx.length + (size_t)msg.length;
    uint8_t* b = (uint8_t*)qsc_alloc(n);
    if (!b) return QSC_ERROR_OOM;
    b[0] = 0x00;
    b[1] = (uint8_t)ctx.length;
    if (ctx.length) memcpy(b + 2, ctx.data, (size_t)ctx.length);
    if (msg.length) memcpy(b + 2 + ctx.length, msg.data, (size_t)msg.length);
    *out = b;
    *outl = n;
    return QSC_OK;
}

qsc_error_t qsc_mldsa65_keygen_seed(const qs_u8 xi[32], qs_u8 pk[1952], qs_u8 sk[4032]) {
    if (!xi || !pk || !sk) return QSC_ERROR_INVALID_ARGUMENT;
    init_tables();
    keygen_internal(xi, pk, sk);
    return QSC_OK;
}

qsc_error_t qsc_mldsa65_keygen(qs_u8 pk[1952], qs_u8 sk[4032]) {
    uint8_t xi[32];
    if (!pk || !sk) return QSC_ERROR_INVALID_ARGUMENT;
    if (qsc_random_bytes(xi, sizeof xi) != QSC_OK) return QSC_ERROR_ENTROPY_UNAVAILABLE;
    qsc_error_t e = qsc_mldsa65_keygen_seed(xi, pk, sk);
    qsc_secure_zero(xi, sizeof xi);
    return e;
}

static qsc_error_t sign_with_rnd(const qs_u8 sk[4032], qsc_slice_t msg, qsc_slice_t ctx,
                                 const uint8_t rnd[32], qs_u8 sig[3309]) {
    uint8_t* mp = NULL;
    size_t mpl = 0;
    if (!sk || !sig) return QSC_ERROR_INVALID_ARGUMENT;
    init_tables();
    qsc_error_t e = format_message(msg, ctx, &mp, &mpl);
    if (e != QSC_OK) return e;
    e = sign_internal(sk, mp, mpl, rnd, sig);
    qsc_free_zero(mp, mpl);
    return e;
}

qsc_error_t qsc_mldsa65_sign(const qs_u8 sk[4032], qsc_slice_t msg, qsc_slice_t ctx, qs_u8 sig[3309]) {
    uint8_t rnd[32];
    if (qsc_random_bytes(rnd, sizeof rnd) != QSC_OK) return QSC_ERROR_ENTROPY_UNAVAILABLE;
    qsc_error_t e = sign_with_rnd(sk, msg, ctx, rnd, sig);
    qsc_secure_zero(rnd, sizeof rnd);
    return e;
}

qsc_error_t qsc_mldsa65_sign_deterministic(const qs_u8 sk[4032], qsc_slice_t msg, qsc_slice_t ctx, qs_u8 sig[3309]) {
    uint8_t rnd[32] = { 0 };
    return sign_with_rnd(sk, msg, ctx, rnd, sig);
}

qsc_error_t qsc_mldsa65_verify(const qs_u8 pk[1952], qsc_slice_t msg, qsc_slice_t ctx, qsc_slice_t sig) {
    uint8_t* mp = NULL;
    size_t mpl = 0;
    if (!pk) return QSC_ERROR_INVALID_ARGUMENT;
    if (sig.length != QSC_MLDSA65_SIG_BYTES || !sig.data) return QSC_ERROR_INVALID_SIGNATURE;
    init_tables();
    qsc_error_t e = format_message(msg, ctx, &mp, &mpl);
    if (e != QSC_OK) return e;
    e = verify_internal(pk, mp, mpl, sig.data);
    qsc_free_zero(mp, mpl);
    return e;
}
