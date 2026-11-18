/**
 * @file qs_crypt_mlkem.c
 * @brief ML-KEM-768 per FIPS 203: K-PKE (CPA) core and the Fujisaki-Okamoto (CCA) transform
 *        with implicit rejection.
 *
 * Arithmetic: Z_q, q = 3329, degree-256 polynomials, NTT with zeta = 17.
 * Hashes: G = SHA3-512, H = SHA3-256, J = SHAKE256 (32 bytes), PRF = SHAKE256, XOF = SHAKE128.
 */
#include "qs_crypt/qs_crypt.h"
#include "qs_crypt/qs_crypt_mlkem.h"
#include "../hash/qs_crypt_hash_internal.h"
#include "../core/qs_crypt_internal.h"
#include <string.h>

#define Q     3329
#define KDIM  3
#define N256  256
#define ETA   2
#define DU    10
#define DV    4
#define RATE_128 168
#define RATE_256 136
#define DOM_SHAKE 0x1F

typedef int32_t poly[N256];

static int32_t zetas[128];       /* zetas[k] = 17^BitRev7(k) mod q */
static int32_t gammas[128];      /* gammas[i] = 17^(2*BitRev7(i)+1) mod q */
static int tables_ready = 0;

static int32_t md(int64_t x) {
    int64_t r = x % Q;
    return (int32_t)(r < 0 ? r + Q : r);
}

static int32_t pw(int32_t b, int e) {
    int64_t r = 1, x = b;
    while (e) {
        if (e & 1) r = (r * x) % Q;
        x = (x * x) % Q;
        e >>= 1;
    }
    return (int32_t)r;
}

static int bitrev7(int x) {
    int r = 0;
    for (int i = 0; i < 7; i++) { r = (r << 1) | (x & 1); x >>= 1; }
    return r;
}

static void init_tables(void) {
    if (tables_ready) return;
    for (int k = 0; k < 128; k++) {
        zetas[k] = pw(17, bitrev7(k));
        gammas[k] = pw(17, 2 * bitrev7(k) + 1);
    }
    tables_ready = 1;
}

/* ---- hashes ----------------------------------------------------------------- */

static void kec(uint32_t rate, uint8_t dom, const uint8_t* a, size_t al,
                const uint8_t* b, size_t bl, const uint8_t* c, size_t cl,
                uint8_t* out, size_t outlen) {
    qsc_keccak_state s;
    qsc_keccak_init(&s, rate, dom);
    if (al) qsc_keccak_absorb(&s, a, al);
    if (bl) qsc_keccak_absorb(&s, b, bl);
    if (cl) qsc_keccak_absorb(&s, c, cl);
    qsc_keccak_squeeze(&s, out, outlen);
    qsc_secure_zero(&s, sizeof s);
}

static void prf(const uint8_t sigma[32], uint8_t N, uint8_t out[128]) {
    kec(RATE_256, DOM_SHAKE, sigma, 32, &N, 1, NULL, 0, out, 128);
}

static void hash_g(const uint8_t* a, size_t al, const uint8_t* b, size_t bl, uint8_t out[64]) {
    qsc_digest_t dg;
    qsc_slice_t s1 = { a, (qs_u64)al };
    qsc_hash(QSC_ALG_SHA3_512, s1, &dg);
    (void)b; (void)bl;
    memcpy(out, dg.data, 64);
}

/* G(x) = SHA3-512 over the concatenation of up to two parts. */
static void G2(const uint8_t* a, size_t al, const uint8_t* b, size_t bl, uint8_t out[64]) {
    uint8_t buf[1024];
    size_t n = 0;
    memcpy(buf, a, al); n += al;
    if (bl) { memcpy(buf + n, b, bl); n += bl; }
    hash_g(buf, n, NULL, 0, out);
    qsc_secure_zero(buf, sizeof buf);
}

static void H32(const uint8_t* a, size_t al, uint8_t out[32]) {
    qsc_digest_t dg;
    qsc_slice_t s = { a, (qs_u64)al };
    qsc_hash(QSC_ALG_SHA3_256, s, &dg);
    memcpy(out, dg.data, 32);
}

/* ---- arithmetic ------------------------------------------------------------- */

static void poly_zero(poly r) { memset(r, 0, sizeof(poly)); }

static void poly_add(poly r, const poly a, const poly b) {
    for (int i = 0; i < N256; i++) r[i] = md((int64_t)a[i] + b[i]);
}

static void poly_sub(poly r, const poly a, const poly b) {
    for (int i = 0; i < N256; i++) r[i] = md((int64_t)a[i] - b[i]);
}

static void ntt(poly f) {
    int k = 1;
    for (int len = 128; len >= 2; len >>= 1)
        for (int start = 0; start < N256; start += 2 * len) {
            int32_t zeta = zetas[k++];
            for (int j = start; j < start + len; j++) {
                int32_t t = md((int64_t)zeta * f[j + len]);
                f[j + len] = md((int64_t)f[j] - t);
                f[j] = md((int64_t)f[j] + t);
            }
        }
}

static void intt(poly f) {
    int k = 127;
    for (int len = 2; len <= 128; len <<= 1)
        for (int start = 0; start < N256; start += 2 * len) {
            int32_t zeta = zetas[k--];
            for (int j = start; j < start + len; j++) {
                int32_t t = f[j];
                f[j] = md((int64_t)t + f[j + len]);
                f[j + len] = md((int64_t)f[j + len] - t);
                f[j + len] = md((int64_t)zeta * f[j + len]);
            }
        }
    for (int i = 0; i < N256; i++) f[i] = md((int64_t)f[i] * 3303);   /* 128^-1 mod q */
}

/* r += a o b, multiplication in the NTT domain (degree-1 base cases with gamma_i). */
static void basemul_acc(poly r, const poly a, const poly b) {
    for (int i = 0; i < 128; i++) {
        int32_t a0 = a[2 * i], a1 = a[2 * i + 1], b0 = b[2 * i], b1 = b[2 * i + 1];
        int32_t g = gammas[i];
        int32_t c0 = md((int64_t)a0 * b0 + (int64_t)md((int64_t)a1 * b1) * g);
        int32_t c1 = md((int64_t)a0 * b1 + (int64_t)a1 * b0);
        r[2 * i]     = md((int64_t)r[2 * i] + c0);
        r[2 * i + 1] = md((int64_t)r[2 * i + 1] + c1);
    }
}

/* ---- encodings and compression ---------------------------------------------- */

static void byte_encode(const poly f, int d, uint8_t* out) {
    uint32_t acc = 0;
    int bits = 0;
    size_t pos = 0;
    for (int i = 0; i < N256; i++) {
        acc |= ((uint32_t)f[i] & ((1u << d) - 1u)) << bits;
        bits += d;
        while (bits >= 8) {
            out[pos++] = (uint8_t)acc;
            acc >>= 8;
            bits -= 8;
        }
    }
}

static void byte_decode(const uint8_t* in, int d, poly f) {
    uint32_t acc = 0;
    int bits = 0;
    size_t pos = 0;
    uint32_t mask = (1u << d) - 1u;
    for (int i = 0; i < N256; i++) {
        while (bits < d) {
            acc |= (uint32_t)in[pos++] << bits;
            bits += 8;
        }
        f[i] = (int32_t)(acc & mask);
        acc >>= d;
        bits -= d;
    }
}

static int32_t compress(int32_t x, int d) {
    uint32_t v = (((uint32_t)x << d) + 1664u) / Q;
    return (int32_t)(v & ((1u << d) - 1u));
}

static int32_t decompress(int32_t y, int d) {
    return (int32_t)(((int64_t)y * Q + ((int64_t)1 << (d - 1))) >> d);
}

/* ---- sampling --------------------------------------------------------------- */

/* SampleNTT on the stream SHAKE128(rho || x || y). */
static void sample_ntt(const uint8_t rho[32], uint8_t x, uint8_t y, poly a) {
    qsc_keccak_state s;
    qsc_keccak_init(&s, RATE_128, DOM_SHAKE);
    qsc_keccak_absorb(&s, rho, 32);
    qsc_keccak_absorb(&s, &x, 1);
    qsc_keccak_absorb(&s, &y, 1);
    int j = 0;
    while (j < N256) {
        uint8_t c[3];
        qsc_keccak_squeeze(&s, c, 3);
        int32_t d1 = c[0] + 256 * (c[1] & 0x0F);
        int32_t d2 = (c[1] >> 4) + 16 * c[2];
        if (d1 < Q) a[j++] = d1;
        if (d2 < Q && j < N256) a[j++] = d2;
    }
    qsc_secure_zero(&s, sizeof s);
}

/* SamplePolyCBD with eta = 2 on 128 bytes. */
static void sample_cbd(const uint8_t* B, poly f) {
    for (int i = 0; i < N256; i++) {
        int x = 0, y = 0;
        int base = 4 * i;
        for (int j = 0; j < ETA; j++) {
            int bx = base + j, by = base + ETA + j;
            x += (B[bx >> 3] >> (bx & 7)) & 1;
            y += (B[by >> 3] >> (by & 7)) & 1;
        }
        f[i] = md(x - y);
    }
}

/* A[i][j] = SampleNTT(rho || j || i), as in K-PKE.KeyGen. */
static void gen_matrix(const uint8_t rho[32], poly A[KDIM][KDIM]) {
    for (int i = 0; i < KDIM; i++)
        for (int j = 0; j < KDIM; j++)
            sample_ntt(rho, (uint8_t)j, (uint8_t)i, A[i][j]);
}

/* ---- K-PKE ------------------------------------------------------------------ */

static void pke_keygen(const uint8_t d[32], uint8_t ek[1184], uint8_t dk[1152]) {
    uint8_t g[64], buf[128];
    uint8_t dd[33];
    memcpy(dd, d, 32);
    dd[32] = KDIM;
    G2(dd, 33, NULL, 0, g);
    const uint8_t* rho = g;
    const uint8_t* sigma = g + 32;

    poly s[KDIM], e[KDIM], t[KDIM], A[KDIM][KDIM];
    uint8_t N = 0;
    for (int i = 0; i < KDIM; i++) { prf(sigma, N++, buf); sample_cbd(buf, s[i]); }
    for (int i = 0; i < KDIM; i++) { prf(sigma, N++, buf); sample_cbd(buf, e[i]); }
    for (int i = 0; i < KDIM; i++) { ntt(s[i]); ntt(e[i]); }

    gen_matrix(rho, A);
    for (int i = 0; i < KDIM; i++) {
        poly_zero(t[i]);
        for (int j = 0; j < KDIM; j++) basemul_acc(t[i], A[i][j], s[j]);
        poly_add(t[i], t[i], e[i]);
    }
    for (int i = 0; i < KDIM; i++) byte_encode(t[i], 12, ek + 384 * i);
    memcpy(ek + 1152, rho, 32);
    for (int i = 0; i < KDIM; i++) byte_encode(s[i], 12, dk + 384 * i);

    qsc_secure_zero(s, sizeof s);
    qsc_secure_zero(e, sizeof e);
    qsc_secure_zero(g, sizeof g);
}

static void pke_encrypt(const uint8_t ek[1184], const uint8_t m[32], const uint8_t r[32],
                        uint8_t c[1088]) {
    poly t[KDIM], A[KDIM][KDIM], y[KDIM], u[KDIM], e1[KDIM], mu, v, e2, acc;
    uint8_t buf[128];
    const uint8_t* rho = ek + 1152;
    for (int i = 0; i < KDIM; i++) byte_decode(ek + 384 * i, 12, t[i]);
    gen_matrix(rho, A);

    uint8_t N = 0;
    for (int i = 0; i < KDIM; i++) { prf(r, N++, buf); sample_cbd(buf, y[i]); }
    for (int i = 0; i < KDIM; i++) { prf(r, N++, buf); sample_cbd(buf, e1[i]); }
    prf(r, N++, buf);
    sample_cbd(buf, e2);

    for (int i = 0; i < KDIM; i++) ntt(y[i]);
    for (int i = 0; i < KDIM; i++) {
        poly_zero(acc);
        for (int j = 0; j < KDIM; j++) basemul_acc(acc, A[j][i], y[j]);   /* A^T * y */
        intt(acc);
        poly_add(u[i], acc, e1[i]);
    }

    byte_decode(m, 1, mu);
    for (int i = 0; i < N256; i++) mu[i] = (int32_t)(mu[i] * decompress(1, 1));
    poly_zero(acc);
    for (int j = 0; j < KDIM; j++) basemul_acc(acc, t[j], y[j]);
    intt(acc);
    poly_add(v, acc, e2);
    poly_add(v, v, mu);

    for (int i = 0; i < KDIM; i++) {
        uint8_t tmp[320];
        poly cu;
        for (int k = 0; k < N256; k++) cu[k] = compress(u[i][k], DU);
        byte_encode(cu, DU, tmp);
        memcpy(c + 320 * i, tmp, 320);
    }
    poly cv;
    for (int k = 0; k < N256; k++) cv[k] = compress(v[k], DV);
    byte_encode(cv, DV, c + 960);

    qsc_secure_zero(y, sizeof y);
    qsc_secure_zero(e1, sizeof e1);
    qsc_secure_zero(&e2, sizeof e2);
}

static void pke_decrypt(const uint8_t dk[1152], const uint8_t c[1088], uint8_t m[32]) {
    poly s[KDIM], u[KDIM], acc, v, w;
    for (int i = 0; i < KDIM; i++) byte_decode(dk + 384 * i, 12, s[i]);
    for (int i = 0; i < KDIM; i++) {
        poly cu;
        byte_decode(c + 320 * i, DU, cu);
        for (int k = 0; k < N256; k++) u[i][k] = decompress(cu[k], DU);
        ntt(u[i]);
    }
    poly cv;
    byte_decode(c + 960, DV, cv);
    for (int k = 0; k < N256; k++) v[k] = decompress(cv[k], DV);

    poly_zero(acc);
    for (int i = 0; i < KDIM; i++) basemul_acc(acc, s[i], u[i]);
    intt(acc);
    poly_sub(w, v, acc);
    for (int k = 0; k < N256; k++) w[k] = compress(w[k], 1);
    byte_encode(w, 1, m);

    qsc_secure_zero(s, sizeof s);
}

/* ---- ML-KEM ----------------------------------------------------------------- */

/* FIPS 203 encapsulation key modulus check: every 12-bit coefficient must be < q. */
static int ek_modulus_ok(const uint8_t ek[1184]) {
    poly t;
    for (int i = 0; i < KDIM; i++) {
        byte_decode(ek + 384 * i, 12, t);
        for (int k = 0; k < N256; k++) if (t[k] >= Q) return 0;
    }
    return 1;
}

static void keygen_internal(const uint8_t d[32], const uint8_t z[32],
                            uint8_t ek[1184], uint8_t dk[2400]) {
    pke_keygen(d, ek, dk);
    memcpy(dk + 1152, ek, 1184);
    H32(ek, 1184, dk + 2336);
    memcpy(dk + 2368, z, 32);
}

static void encaps_internal(const uint8_t ek[1184], const uint8_t m[32],
                            uint8_t c[1088], uint8_t K[32]) {
    uint8_t h[32], gout[64];
    H32(ek, 1184, h);
    G2(m, 32, h, 32, gout);
    pke_encrypt(ek, m, gout + 32, c);
    memcpy(K, gout, 32);
}

static void decaps_internal(const uint8_t dk[2400], const uint8_t c[1088], uint8_t K[32]) {
    const uint8_t* dkpke = dk;
    const uint8_t* ek = dk + 1152;
    const uint8_t* h = dk + 2336;
    const uint8_t* z = dk + 2368;
    uint8_t mp[32], gout[64], cp[1088], Kbar[32];
    pke_decrypt(dkpke, c, mp);
    G2(mp, 32, h, 32, gout);
    pke_encrypt(ek, mp, gout + 32, cp);
    kec(RATE_256, DOM_SHAKE, z, 32, c, 1088, NULL, 0, Kbar, 32);

    /* constant-time compare of c and cp, then select K or Kbar */
    uint32_t diff = 0;
    for (int i = 0; i < 1088; i++) diff |= (uint32_t)(c[i] ^ cp[i]);
    uint32_t mask = (uint32_t)(((uint64_t)diff - 1u) >> 63) * 0xFFFFFFFFu;   /* all-ones iff diff == 0 */
    for (int i = 0; i < 32; i++) K[i] = (uint8_t)((gout[i] & mask) | (Kbar[i] & ~mask));

    qsc_secure_zero(mp, sizeof mp);
    qsc_secure_zero(gout, sizeof gout);
}

qsc_error_t qsc_mlkem768_keygen_seed(const qs_u8 seed[64], qs_u8 ek[1184], qs_u8 dk[2400]) {
    if (!seed || !ek || !dk) return QSC_ERROR_INVALID_ARGUMENT;
    init_tables();
    keygen_internal(seed, seed + 32, ek, dk);
    return QSC_OK;
}

qsc_error_t qsc_mlkem768_keygen(qs_u8 ek[1184], qs_u8 dk[2400]) {
    uint8_t seed[64];
    if (!ek || !dk) return QSC_ERROR_INVALID_ARGUMENT;
    if (qsc_random_bytes(seed, 64) != QSC_OK) return QSC_ERROR_ENTROPY_UNAVAILABLE;
    init_tables();
    keygen_internal(seed, seed + 32, ek, dk);
    qsc_secure_zero(seed, sizeof seed);
    return QSC_OK;
}

qsc_error_t qsc_mlkem768_encaps_seed(const qs_u8 ek[1184], const qs_u8 m[32], qs_u8 ct[1088], qs_u8 ss[32]) {
    if (!ek || !m || !ct || !ss) return QSC_ERROR_INVALID_ARGUMENT;
    init_tables();
    if (!ek_modulus_ok(ek)) return QSC_ERROR_INVALID_KEY;
    encaps_internal(ek, m, ct, ss);
    return QSC_OK;
}

qsc_error_t qsc_mlkem768_encaps(const qs_u8 ek[1184], qs_u8 ct[1088], qs_u8 ss[32]) {
    uint8_t m[32];
    if (!ek || !ct || !ss) return QSC_ERROR_INVALID_ARGUMENT;
    if (qsc_random_bytes(m, 32) != QSC_OK) return QSC_ERROR_ENTROPY_UNAVAILABLE;
    qsc_error_t e = qsc_mlkem768_encaps_seed(ek, m, ct, ss);
    qsc_secure_zero(m, sizeof m);
    return e;
}

qsc_error_t qsc_mlkem768_decaps(const qs_u8 dk[2400], const qs_u8 ct[1088], qs_u8 ss[32]) {
    if (!dk || !ct || !ss) return QSC_ERROR_INVALID_ARGUMENT;
    init_tables();
    decaps_internal(dk, ct, ss);
    return QSC_OK;
}
