/* BFV (RNS) tests: per-prime NTT identity, round trips, dense plaintext products (depth 1 and 2)
 * against plaintext arithmetic, noise budget, wrong-key behaviour, serialization, argument checks. */
#include "test_common.h"
#include "qs_crypt/qs_crypt.h"
#include "../../src/fhe/qs_crypt_fhe_internal.h"
#include <string.h>
#include <stdlib.h>

#define N QSC_FHE_N
#define T QSC_FHE_T

static void rand_plain(uint32_t m[N]) {
    uint8_t b[N];
    qsc_random_bytes(b, sizeof b);
    for (unsigned i = 0; i < N; i++) m[i] = b[i] % T;
}

/* Negacyclic product in plaintext: r = a * b mod (x^N + 1, t). */
static void naive_negacyclic(const uint32_t a[N], const uint32_t b[N], uint32_t r[N]) {
    uint64_t* acc = (uint64_t*)calloc(N, sizeof(uint64_t));
    for (unsigned i = 0; i < N; i++)
        for (unsigned j = 0; j < N; j++) {
            uint64_t p = (uint64_t)a[i] * b[j];
            unsigned k = i + j;
            if (k < N) acc[k] += p;
            else       acc[k - N] += (uint64_t)T * T - p;   /* subtract, kept non-negative */
        }
    for (unsigned k = 0; k < N; k++) r[k] = (uint32_t)(acc[k] % T);
    free(acc);
}

static int same(const uint32_t a[N], const uint32_t b[N]) {
    return memcmp(a, b, N * sizeof(uint32_t)) == 0;
}

static void ntt_identity(const qsc_fhe_ctx_t* ctx) {
    const struct qsc_fhe_ctx* c = (const struct qsc_fhe_ctx*)ctx;
    for (int prime = 0; prime < (int)QSC_FHE_NUM_PRIMES; prime++) {
        uint32_t* a = (uint32_t*)malloc(N * sizeof(uint32_t));
        uint32_t* b = (uint32_t*)malloc(N * sizeof(uint32_t));
        uint8_t raw[4 * N];
        qsc_random_bytes(raw, sizeof raw);
        for (unsigned j = 0; j < N; j++) {
            const uint8_t* w = raw + 4 * j;
            uint32_t word = (uint32_t)w[0] | ((uint32_t)w[1] << 8) | ((uint32_t)w[2] << 16) | ((uint32_t)w[3] << 24);
            a[j] = word % c->q[prime];
            b[j] = a[j];
        }
        qsc_fhe_ntt_fwd(c, prime, b);
        qsc_fhe_ntt_inv(c, prime, b);
        CHECK(memcmp(a, b, N * sizeof(uint32_t)) == 0);
        free(a);
        free(b);
    }
}

static void roundtrip_and_homomorphic(const qsc_fhe_ctx_t* ctx) {
    qsc_fhe_sk_t* sk = NULL;
    qsc_fhe_pk_t* pk = NULL;
    uint32_t ma[N], mb[N], out[N], want[N], p[N], p2[N], tmp[N];
    qsc_fhe_ct_t *ca = NULL, *cb = NULL, *cs = NULL, *cm = NULL, *cm2 = NULL;
    int bits = -1;

    CHECK(qsc_fhe_keygen(ctx, &sk, &pk) == QSC_OK);
    rand_plain(ma);
    rand_plain(mb);

    CHECK(qsc_fhe_encrypt(ctx, pk, ma, &ca) == QSC_OK);
    CHECK(qsc_fhe_decrypt(ctx, sk, ca, out) == QSC_OK);
    CHECK(same(ma, out));
    CHECK(qsc_fhe_encrypt(ctx, pk, mb, &cb) == QSC_OK);

    CHECK(qsc_fhe_add(ctx, ca, cb, &cs) == QSC_OK);
    for (unsigned i = 0; i < N; i++) want[i] = (ma[i] + mb[i]) % T;
    CHECK(qsc_fhe_decrypt(ctx, sk, cs, out) == QSC_OK);
    CHECK(same(want, out));

    qsc_fhe_ct_destroy(cs); cs = NULL;
    CHECK(qsc_fhe_sub(ctx, ca, cb, &cs) == QSC_OK);
    for (unsigned i = 0; i < N; i++) want[i] = (ma[i] + T - mb[i]) % T;
    CHECK(qsc_fhe_decrypt(ctx, sk, cs, out) == QSC_OK);
    CHECK(same(want, out));

    /* Dense plaintext product, depth 1: every coefficient of p is nonzero. */
    rand_plain(p);
    CHECK(qsc_fhe_mul_plain(ctx, ca, p, &cm) == QSC_OK);
    naive_negacyclic(ma, p, want);
    CHECK(qsc_fhe_decrypt(ctx, sk, cm, out) == QSC_OK);
    CHECK(same(want, out));

    /* Dense plaintext product, depth 2: the case the single-prime modulus could not support. */
    rand_plain(p2);
    CHECK(qsc_fhe_mul_plain(ctx, cm, p2, &cm2) == QSC_OK);
    naive_negacyclic(want, p2, tmp);
    CHECK(qsc_fhe_decrypt(ctx, sk, cm2, out) == QSC_OK);
    CHECK(same(tmp, out));

    /* Noise: fresh budget is large; both dense products leave a positive budget. */
    CHECK(qsc_fhe_noise_budget(ctx, sk, ca, &bits) == QSC_OK);
    CHECK(bits > 40);
    CHECK(qsc_fhe_noise_budget(ctx, sk, cm2, &bits) == QSC_OK);
    CHECK(bits > 0);

    /* Wrong key does not decrypt. */
    qsc_fhe_sk_t* sk2 = NULL; qsc_fhe_pk_t* pk2 = NULL;
    CHECK(qsc_fhe_keygen(ctx, &sk2, &pk2) == QSC_OK);
    CHECK(qsc_fhe_decrypt(ctx, sk2, ca, out) == QSC_OK);
    int mism = 0;
    for (unsigned i = 0; i < N; i++) if (out[i] != ma[i]) mism++;
    CHECK(mism > (int)(N / 2));
    qsc_fhe_sk_destroy(sk2); qsc_fhe_pk_destroy(pk2);

    /* Serialization round trip. */
    qsc_buffer_t wire = { NULL, 0 };
    qsc_fhe_ct_t* back = NULL;
    CHECK(qsc_fhe_ct_serialize(ca, &wire) == QSC_OK);
    CHECK(wire.length > 98304);
    CHECK(qsc_fhe_ct_deserialize(ctx, (qsc_slice_t){ wire.data, wire.length }, &back) == QSC_OK);
    CHECK(qsc_fhe_decrypt(ctx, sk, back, out) == QSC_OK);
    CHECK(same(ma, out));
    qsc_buffer_free(&wire);
    qsc_fhe_ct_destroy(back);

    qsc_fhe_ct_destroy(ca); qsc_fhe_ct_destroy(cb);
    qsc_fhe_ct_destroy(cs); qsc_fhe_ct_destroy(cm); qsc_fhe_ct_destroy(cm2);
    qsc_fhe_sk_destroy(sk); qsc_fhe_pk_destroy(pk);
}

static void fhe_negative(const qsc_fhe_ctx_t* ctx) {
    qsc_fhe_sk_t* sk = NULL; qsc_fhe_pk_t* pk = NULL;
    qsc_fhe_ct_t* ct = NULL;
    uint32_t m[N], out[N];
    CHECK(qsc_fhe_keygen(ctx, &sk, &pk) == QSC_OK);

    rand_plain(m);
    m[7] = T;
    CHECK(qsc_fhe_encrypt(ctx, pk, m, &ct) == QSC_ERROR_INVALID_PARAMETERS);
    CHECK(ct == NULL);

    rand_plain(m);
    CHECK(qsc_fhe_encrypt(NULL, pk, m, &ct) == QSC_ERROR_INVALID_ARGUMENT);
    CHECK(qsc_fhe_encrypt(ctx, NULL, m, &ct) == QSC_ERROR_INVALID_ARGUMENT);
    CHECK(qsc_fhe_decrypt(ctx, sk, NULL, out) == QSC_ERROR_INVALID_ARGUMENT);

    /* Truncated payload, and a coefficient >= its prime. */
    qsc_fhe_ct_t* good = NULL;
    qsc_buffer_t wire = { NULL, 0 };
    CHECK(qsc_fhe_encrypt(ctx, pk, m, &good) == QSC_OK);
    CHECK(qsc_fhe_ct_serialize(good, &wire) == QSC_OK);
    qsc_fhe_ct_t* bad = NULL;
    CHECK(qsc_fhe_ct_deserialize(ctx, (qsc_slice_t){ wire.data, wire.length - 1 }, &bad) != QSC_OK);
    CHECK(bad == NULL);
    /* Last residue set to 0xFFFFFFFF, which is >= every RNS prime. */
    wire.data[wire.length - 1] = 0xFF;
    wire.data[wire.length - 2] = 0xFF;
    wire.data[wire.length - 3] = 0xFF;
    wire.data[wire.length - 4] = 0xFF;
    CHECK(qsc_fhe_ct_deserialize(ctx, (qsc_slice_t){ wire.data, wire.length }, &bad)
          == QSC_ERROR_MALFORMED_DATA);
    qsc_buffer_free(&wire);
    qsc_fhe_ct_destroy(good);

    /* Dense product with an out-of-range plaintext coefficient. */
    qsc_fhe_ct_t* c2 = NULL;
    CHECK(qsc_fhe_encrypt(ctx, pk, m, &c2) == QSC_OK);
    uint32_t p[N];
    memset(p, 0, sizeof p);
    p[0] = T + 1;
    CHECK(qsc_fhe_mul_plain(ctx, c2, p, &ct) == QSC_ERROR_INVALID_PARAMETERS);
    qsc_fhe_ct_destroy(c2);

    qsc_fhe_sk_destroy(sk); qsc_fhe_pk_destroy(pk);
}

void run_fhe_tests(void) {
    qsc_fhe_ctx_t* ctx = NULL;
    CHECK(qsc_fhe_ctx_create(&ctx) == QSC_OK && ctx != NULL);
    if (!ctx) return;
    ntt_identity(ctx);
    for (int i = 0; i < 2; i++) roundtrip_and_homomorphic(ctx);
    fhe_negative(ctx);
    qsc_fhe_ctx_destroy(ctx);
}
