/**
 * @file qs_crypt_bfv.c
 * @brief BFV over an RNS modulus Q = q0 q1 q2 with N = 4096, t = 257.
 *
 * Residues are kept per prime. Decryption reconstructs each coefficient v in [0, Q) by the
 * Chinese Remainder Theorem and then computes m = round(t v / Q) mod t by binary search over
 * the small quotient. Scratch polynomials live on the heap (each RNS polynomial is 48 KB).
 */
#include "qs_crypt/qs_crypt.h"
#include "../core/qs_crypt_internal.h"
#include "qs_crypt_fhe_internal.h"
#include <string.h>

#define N QSC_FHE_N
#define L QSC_FHE_L
#define RLEN QSC_FHE_RLEN
#define T ((uint32_t)QSC_FHE_T)

/* ---- randomness -------------------------------------------------------------- */

typedef struct {
    uint8_t buf[512];
    size_t  pos;
} rbuf;

static qsc_error_t rb_next(rbuf* r, uint8_t* b) {
    if (r->pos >= sizeof r->buf) {
        qsc_error_t e = qsc_random_bytes(r->buf, sizeof r->buf);
        if (e != QSC_OK) return e;
        r->pos = 0;
    }
    *b = r->buf[r->pos++];
    return QSC_OK;
}

/* Uniform in [0, q) by rejection on 31-bit words; q < 2^31 for all RNS primes. */
static qsc_error_t sample_uniform_mod(rbuf* r, uint32_t q, uint32_t* out) {
    for (unsigned j = 0; j < N; j++) {
        for (;;) {
            uint8_t b[4];
            for (int k = 0; k < 4; k++) {
                qsc_error_t e = rb_next(r, &b[k]);
                if (e != QSC_OK) return e;
            }
            uint32_t v = qsc_ld32le(b) & 0x7FFFFFFFu;
            if (v < q) { out[j] = v; break; }
        }
    }
    return QSC_OK;
}

static qsc_error_t sample_ternary(rbuf* r, int32_t* out) {
    for (unsigned j = 0; j < N; j++) {
        for (;;) {
            uint8_t b;
            qsc_error_t e = rb_next(r, &b);
            if (e != QSC_OK) return e;
            uint8_t v = b & 3;
            if (v == 3) continue;
            out[j] = (v == 0) ? 0 : (v == 1) ? 1 : -1;
            break;
        }
    }
    return QSC_OK;
}

static qsc_error_t sample_cbd2(rbuf* r, int32_t* out) {
    for (unsigned j = 0; j < N; j++) {
        uint8_t b;
        qsc_error_t e = rb_next(r, &b);
        if (e != QSC_OK) return e;
        int x = (b & 1) + ((b >> 1) & 1);
        int y = ((b >> 2) & 1) + ((b >> 3) & 1);
        out[j] = x - y;                              /* in [-2, 2] */
    }
    return QSC_OK;
}

/* Small signed coefficients to residues mod q. */
static void small_to_res(const int32_t* v, uint32_t q, uint32_t* out) {
    for (unsigned j = 0; j < N; j++) {
        int64_t x = (int64_t)v[j] % (int64_t)q;
        if (x < 0) x += q;
        out[j] = (uint32_t)x;
    }
}

/* ---- validation -------------------------------------------------------------- */

static int ctx_ok(const qsc_fhe_ctx_t* c) { return c && c->magic == QSC_FHE_MAGIC_CTX; }
static int sk_ok(const qsc_fhe_sk_t* k)   { return k && k->magic == QSC_FHE_MAGIC_SK; }
static int pk_ok(const qsc_fhe_pk_t* k)   { return k && k->magic == QSC_FHE_MAGIC_PK; }
static int ct_ok(const qsc_fhe_ct_t* c)   { return c && c->magic == QSC_FHE_MAGIC_CT; }

static int plain_ok(const qs_u32 m[N]) {
    for (unsigned j = 0; j < N; j++) if (m[j] >= T) return 0;
    return 1;
}

static uint32_t* scratch(size_t n) { return (uint32_t*)qsc_alloc(n * sizeof(uint32_t)); }
static void scratch_free(uint32_t* p, size_t n) { if (p) qsc_free_zero(p, n * sizeof(uint32_t)); }

static uint64_t pw64(uint64_t b, uint64_t e, uint64_t q) {
    uint64_t r = 1;
    b %= q;
    while (e) {
        if (e & 1) r = r * b % q;
        b = b * b % q;
        e >>= 1;
    }
    return r;
}

/* ---- context ----------------------------------------------------------------- */

qsc_error_t qsc_fhe_ctx_create(qsc_fhe_ctx_t** out) {
    struct qsc_fhe_ctx* c;
    qsc_error_t e;
    if (!out) return QSC_ERROR_INVALID_ARGUMENT;
    *out = NULL;
    c = (struct qsc_fhe_ctx*)qsc_alloc(sizeof *c);
    if (!c) return QSC_ERROR_OOM;
    memset(c, 0, sizeof *c);
    c->magic = QSC_FHE_MAGIC_CTX;
    c->t = T;
    if ((e = qsc_fhe_ntt_setup(c)) != QSC_OK) {
        qsc_free_zero(c, sizeof *c);
        return e;
    }

    qsc_bn_set_u32(&c->Q, 1);
    for (int i = 0; i < L; i++) qsc_bn_mul_small(&c->Q, &c->Q, c->q[i], 4);

    for (int i = 0; i < L; i++) {
        qsc_bn tmp;
        qsc_bn_divmod_small(&c->Qhat[i], &c->Q, c->q[i], 4);          /* Q / q_i, exact */
        uint32_t rem = qsc_bn_divmod_small(&tmp, &c->Qhat[i], c->q[i], 4);
        c->qhat_inv[i] = (uint32_t)pw64(rem, (uint64_t)c->q[i] - 2, c->q[i]);
    }
    qsc_bn_divmod_small(&c->Qhalf, &c->Q, 2, 4);
    qsc_bn_divmod_small(&c->delta, &c->Q, T, 4);
    for (int i = 0; i < L; i++) {
        qsc_bn tmp;
        c->delta_mod[i] = qsc_bn_divmod_small(&tmp, &c->delta, c->q[i], 4);
    }
    *out = c;
    return QSC_OK;
}

void qsc_fhe_ctx_destroy(qsc_fhe_ctx_t* c) {
    if (ctx_ok(c)) qsc_free_zero(c, sizeof *c);
}

/* CRT reconstruction of column j: v = sum_i [v_i qhat_i^-1]_{q_i} * (Q/q_i) mod Q. */
static void crt_col(const struct qsc_fhe_ctx* c, const uint32_t* v, unsigned j, qsc_bn* out) {
    qsc_bn acc;
    qsc_bn_zero(&acc);
    for (int i = 0; i < L; i++) {
        uint64_t a = (uint64_t)v[(size_t)i * N + j] * c->qhat_inv[i] % c->q[i];
        qsc_bn term;
        qsc_bn_mul_small(&term, &c->Qhat[i], (uint32_t)a, 4);
        qsc_bn_add(&acc, &acc, &term, 4);
    }
    while (qsc_bn_cmp(&acc, &c->Q, 4) >= 0) qsc_bn_sub(&acc, &acc, &c->Q, 4);
    *out = acc;
}

/* m = round(t V / Q) mod t, with V in [0, Q). Binary search for the largest k with k Q <= tV + Q/2. */
static uint32_t round_t(const struct qsc_fhe_ctx* c, const qsc_bn* V) {
    qsc_bn y, kq;
    qsc_bn_mul_small(&y, V, T, 4);
    qsc_bn_add(&y, &y, &c->Qhalf, 4);
    uint32_t lo = 0, hi = T + 1;
    while (hi - lo > 1) {
        uint32_t mid = (lo + hi) / 2;
        qsc_bn_mul_small(&kq, &c->Q, mid, 4);
        if (qsc_bn_cmp(&kq, &y, 4) <= 0) lo = mid;
        else hi = mid;
    }
    return lo % T;
}

/* ---- keys -------------------------------------------------------------------- */

qsc_error_t qsc_fhe_keygen(const qsc_fhe_ctx_t* c, qsc_fhe_sk_t** sko, qsc_fhe_pk_t** pko) {
    struct qsc_fhe_sk* sk = NULL;
    struct qsc_fhe_pk* pk = NULL;
    int32_t* small = NULL;
    uint32_t* e = NULL;
    qsc_error_t err = QSC_OK;
    rbuf r;
    r.pos = sizeof r.buf;

    if (!ctx_ok(c) || !sko || !pko) return QSC_ERROR_INVALID_ARGUMENT;
    *sko = NULL;
    *pko = NULL;
    sk = (struct qsc_fhe_sk*)qsc_alloc(sizeof *sk);
    pk = (struct qsc_fhe_pk*)qsc_alloc(sizeof *pk);
    small = (int32_t*)qsc_alloc(N * sizeof(int32_t));
    e = scratch(RLEN);
    if (!sk || !pk || !small || !e) { err = QSC_ERROR_OOM; goto out; }

    if ((err = sample_ternary(&r, small)) != QSC_OK) goto out;
    for (int i = 0; i < L; i++) {
        small_to_res(small, c->q[i], sk->s + (size_t)i * N);
        qsc_fhe_ntt_fwd(c, i, sk->s + (size_t)i * N);
    }
    for (int i = 0; i < L; i++) {
        if ((err = sample_uniform_mod(&r, c->q[i], pk->p1 + (size_t)i * N)) != QSC_OK) goto out;
    }
    if ((err = sample_cbd2(&r, small)) != QSC_OK) goto out;
    for (int i = 0; i < L; i++) {
        small_to_res(small, c->q[i], e + (size_t)i * N);
        qsc_fhe_ntt_fwd(c, i, e + (size_t)i * N);
    }
    for (int i = 0; i < L; i++) {
        uint64_t q = c->q[i];
        for (unsigned j = 0; j < N; j++) {
            size_t idx = (size_t)i * N + j;
            uint64_t x = ((uint64_t)pk->p1[idx] * sk->s[idx] + e[idx]) % q;
            pk->p0[idx] = (uint32_t)((q - x) % q);
        }
    }
    sk->magic = QSC_FHE_MAGIC_SK;
    pk->magic = QSC_FHE_MAGIC_PK;
    *sko = sk;
    *pko = pk;
    sk = NULL;
    pk = NULL;

out:
    if (sk) qsc_free_zero(sk, sizeof *sk);
    if (pk) qsc_free_zero(pk, sizeof *pk);
    if (small) qsc_free_zero(small, N * sizeof(int32_t));
    scratch_free(e, RLEN);
    return err;
}

void qsc_fhe_sk_destroy(qsc_fhe_sk_t* sk) { if (sk_ok(sk)) qsc_free_zero(sk, sizeof *sk); }
void qsc_fhe_pk_destroy(qsc_fhe_pk_t* pk) { if (pk_ok(pk)) qsc_free_zero(pk, sizeof *pk); }
void qsc_fhe_ct_destroy(qsc_fhe_ct_t* ct) { if (ct_ok(ct)) qsc_free_zero(ct, sizeof *ct); }

static struct qsc_fhe_ct* ct_alloc(void) {
    struct qsc_fhe_ct* ct = (struct qsc_fhe_ct*)qsc_alloc(sizeof *ct);
    if (ct) ct->magic = QSC_FHE_MAGIC_CT;
    return ct;
}

/* ---- encrypt / decrypt ------------------------------------------------------- */

qsc_error_t qsc_fhe_encrypt(const qsc_fhe_ctx_t* c, const qsc_fhe_pk_t* pk,
                            const qs_u32 m[N], qsc_fhe_ct_t** out) {
    struct qsc_fhe_ct* ct = NULL;
    uint32_t *u = NULL, *e1 = NULL, *e2 = NULL, *row = NULL;
    int32_t* small = NULL;
    qsc_error_t err = QSC_OK;
    rbuf r;
    r.pos = sizeof r.buf;

    if (!ctx_ok(c) || !pk_ok(pk) || !m || !out) return QSC_ERROR_INVALID_ARGUMENT;
    if (!plain_ok(m)) return QSC_ERROR_INVALID_PARAMETERS;
    *out = NULL;

    ct = ct_alloc();
    u = scratch(RLEN);
    e1 = scratch(RLEN);
    e2 = scratch(RLEN);
    row = scratch(RLEN);
    small = (int32_t*)qsc_alloc(N * sizeof(int32_t));
    if (!ct || !u || !e1 || !e2 || !row || !small) { err = QSC_ERROR_OOM; goto out; }

    if ((err = sample_ternary(&r, small)) != QSC_OK) goto out;
    for (int i = 0; i < L; i++) {
        small_to_res(small, c->q[i], u + (size_t)i * N);
        qsc_fhe_ntt_fwd(c, i, u + (size_t)i * N);
    }
    if ((err = sample_cbd2(&r, small)) != QSC_OK) goto out;
    for (int i = 0; i < L; i++) small_to_res(small, c->q[i], e1 + (size_t)i * N);
    if ((err = sample_cbd2(&r, small)) != QSC_OK) goto out;
    for (int i = 0; i < L; i++) small_to_res(small, c->q[i], e2 + (size_t)i * N);

    /* pass 0: c0 = INTT(p0 u) + e1 + delta m.  pass 1: c1 = INTT(p1 u) + e2. */
    for (int pass = 0; pass < 2; pass++) {
        const uint32_t* p = pass ? pk->p1 : pk->p0;
        const uint32_t* ee = pass ? e2 : e1;
        uint32_t* dst = pass ? ct->c1 : ct->c0;
        for (int i = 0; i < L; i++) {
            uint64_t q = c->q[i];
            uint32_t* rr = row + (size_t)i * N;
            for (unsigned j = 0; j < N; j++) {
                size_t idx = (size_t)i * N + j;
                rr[j] = (uint32_t)((uint64_t)p[idx] * u[idx] % q);
            }
            qsc_fhe_ntt_inv(c, i, rr);
            for (unsigned j = 0; j < N; j++) {
                size_t idx = (size_t)i * N + j;
                uint64_t v = (uint64_t)rr[j] + ee[idx];
                if (pass == 0) v += (uint64_t)c->delta_mod[i] * m[j] % q;
                dst[idx] = (uint32_t)(v % q);
            }
        }
    }
    *out = ct;
    ct = NULL;

out:
    if (ct) qsc_fhe_ct_destroy(ct);
    scratch_free(u, RLEN);
    scratch_free(e1, RLEN);
    scratch_free(e2, RLEN);
    scratch_free(row, RLEN);
    if (small) qsc_free_zero(small, N * sizeof(int32_t));
    return err;
}

/* v = c0 + c1 s mod Q per residue, coefficient domain. v holds RLEN residues. */
static void compute_v(const struct qsc_fhe_ctx* c, const struct qsc_fhe_sk* sk,
                      const struct qsc_fhe_ct* ct, uint32_t* v) {
    for (int i = 0; i < L; i++) {
        uint64_t q = c->q[i];
        uint32_t* rr = v + (size_t)i * N;
        memcpy(rr, ct->c1 + (size_t)i * N, N * sizeof(uint32_t));
        qsc_fhe_ntt_fwd(c, i, rr);
        for (unsigned j = 0; j < N; j++) {
            size_t idx = (size_t)i * N + j;
            rr[j] = (uint32_t)((uint64_t)rr[j] * sk->s[idx] % q);
        }
        qsc_fhe_ntt_inv(c, i, rr);
        for (unsigned j = 0; j < N; j++) {
            size_t idx = (size_t)i * N + j;
            rr[j] = (uint32_t)(((uint64_t)ct->c0[idx] + rr[j]) % q);
        }
    }
}

qsc_error_t qsc_fhe_decrypt(const qsc_fhe_ctx_t* c, const qsc_fhe_sk_t* sk,
                            const qsc_fhe_ct_t* ct, qs_u32 m_out[N]) {
    uint32_t* v;
    qsc_error_t err = QSC_OK;
    if (!ctx_ok(c) || !sk_ok(sk) || !ct_ok(ct) || !m_out) return QSC_ERROR_INVALID_ARGUMENT;
    v = scratch(RLEN);
    if (!v) return QSC_ERROR_OOM;
    compute_v(c, sk, ct, v);
    for (unsigned j = 0; j < N; j++) {
        qsc_bn V;
        crt_col(c, v, j, &V);
        m_out[j] = round_t(c, &V);
    }
    scratch_free(v, RLEN);
    return err;
}

/* ---- homomorphic operations -------------------------------------------------- */

qsc_error_t qsc_fhe_add(const qsc_fhe_ctx_t* c, const qsc_fhe_ct_t* a,
                        const qsc_fhe_ct_t* b, qsc_fhe_ct_t** out) {
    struct qsc_fhe_ct* r;
    if (!ctx_ok(c) || !ct_ok(a) || !ct_ok(b) || !out) return QSC_ERROR_INVALID_ARGUMENT;
    *out = NULL;
    r = ct_alloc();
    if (!r) return QSC_ERROR_OOM;
    for (int i = 0; i < L; i++) {
        uint64_t q = c->q[i];
        for (unsigned j = 0; j < N; j++) {
            size_t idx = (size_t)i * N + j;
            r->c0[idx] = (uint32_t)(((uint64_t)a->c0[idx] + b->c0[idx]) % q);
            r->c1[idx] = (uint32_t)(((uint64_t)a->c1[idx] + b->c1[idx]) % q);
        }
    }
    *out = r;
    return QSC_OK;
}

qsc_error_t qsc_fhe_sub(const qsc_fhe_ctx_t* c, const qsc_fhe_ct_t* a,
                        const qsc_fhe_ct_t* b, qsc_fhe_ct_t** out) {
    struct qsc_fhe_ct* r;
    if (!ctx_ok(c) || !ct_ok(a) || !ct_ok(b) || !out) return QSC_ERROR_INVALID_ARGUMENT;
    *out = NULL;
    r = ct_alloc();
    if (!r) return QSC_ERROR_OOM;
    for (int i = 0; i < L; i++) {
        uint64_t q = c->q[i];
        for (unsigned j = 0; j < N; j++) {
            size_t idx = (size_t)i * N + j;
            r->c0[idx] = (uint32_t)(((uint64_t)a->c0[idx] + q - b->c0[idx]) % q);
            r->c1[idx] = (uint32_t)(((uint64_t)a->c1[idx] + q - b->c1[idx]) % q);
        }
    }
    *out = r;
    return QSC_OK;
}

qsc_error_t qsc_fhe_mul_plain(const qsc_fhe_ctx_t* c, const qsc_fhe_ct_t* a,
                              const qs_u32 p[N], qsc_fhe_ct_t** out) {
    struct qsc_fhe_ct* r = NULL;
    uint32_t *P = NULL, *row = NULL;
    qsc_error_t err = QSC_OK;
    if (!ctx_ok(c) || !ct_ok(a) || !p || !out) return QSC_ERROR_INVALID_ARGUMENT;
    if (!plain_ok(p)) return QSC_ERROR_INVALID_PARAMETERS;
    *out = NULL;
    r = ct_alloc();
    P = scratch(RLEN);
    row = scratch(RLEN);
    if (!r || !P || !row) { err = QSC_ERROR_OOM; goto out; }

    /* The plaintext is small (< T) so its residues are its own values, reduced by q_i (no-op). */
    for (int i = 0; i < L; i++) {
        memcpy(P + (size_t)i * N, p, N * sizeof(uint32_t));
        qsc_fhe_ntt_fwd(c, i, P + (size_t)i * N);
    }
    for (int pass = 0; pass < 2; pass++) {
        const uint32_t* src = pass ? a->c1 : a->c0;
        uint32_t* dst = pass ? r->c1 : r->c0;
        for (int i = 0; i < L; i++) {
            uint64_t q = c->q[i];
            uint32_t* rr = row + (size_t)i * N;
            memcpy(rr, src + (size_t)i * N, N * sizeof(uint32_t));
            qsc_fhe_ntt_fwd(c, i, rr);
            for (unsigned j = 0; j < N; j++) {
                size_t idx = (size_t)i * N + j;
                rr[j] = (uint32_t)((uint64_t)rr[j] * P[idx] % q);
            }
            qsc_fhe_ntt_inv(c, i, rr);
            memcpy(dst + (size_t)i * N, rr, N * sizeof(uint32_t));
        }
    }
    *out = r;
    r = NULL;

out:
    if (r) qsc_fhe_ct_destroy(r);
    scratch_free(P, RLEN);
    scratch_free(row, RLEN);
    return err;
}

/* ---- diagnostics ------------------------------------------------------------- */

qsc_error_t qsc_fhe_noise_budget(const qsc_fhe_ctx_t* c, const qsc_fhe_sk_t* sk,
                                 const qsc_fhe_ct_t* ct, int* bits) {
    uint32_t* v;
    qsc_bn maxn, bound;
    if (!ctx_ok(c) || !sk_ok(sk) || !ct_ok(ct) || !bits) return QSC_ERROR_INVALID_ARGUMENT;
    v = scratch(RLEN);
    if (!v) return QSC_ERROR_OOM;
    compute_v(c, sk, ct, v);

    qsc_bn_zero(&maxn);
    for (unsigned j = 0; j < N; j++) {
        qsc_bn V, dm, n;
        crt_col(c, v, j, &V);
        uint32_t m = round_t(c, &V);
        qsc_bn_mul_small(&dm, &c->delta, m, 4);
        if (qsc_bn_cmp(&V, &dm, 4) >= 0) {
            qsc_bn_sub(&n, &V, &dm, 4);
        } else {
            qsc_bn t1;
            qsc_bn_add(&t1, &V, &c->Q, 4);
            qsc_bn_sub(&n, &t1, &dm, 4);
        }
        if (qsc_bn_cmp(&n, &c->Qhalf, 4) > 0) qsc_bn_sub(&n, &c->Q, &n, 4);   /* centre */
        if (qsc_bn_cmp(&n, &maxn, 4) > 0) maxn = n;
    }
    scratch_free(v, RLEN);

    if (qsc_bn_bit_len(&maxn, 4) == 0) qsc_bn_set_u32(&maxn, 1);
    qsc_bn_divmod_small(&bound, &c->delta, 2, 4);             /* bound = floor(delta / 2) */
    if (qsc_bn_cmp(&maxn, &bound, 4) >= 0) *bits = 0;
    else *bits = qsc_bn_bit_len(&bound, 4) - qsc_bn_bit_len(&maxn, 4);
    return QSC_OK;
}

/* ---- serialization ----------------------------------------------------------- */

qsc_error_t qsc_fhe_ct_serialize(const qsc_fhe_ct_t* ct, qsc_buffer_t* out) {
    uint8_t* payload;
    const size_t len = 2 * (size_t)RLEN * 4;
    qsc_error_t e;
    if (!ct_ok(ct) || !out || out->data != NULL) return QSC_ERROR_INVALID_ARGUMENT;
    payload = (uint8_t*)qsc_alloc(len);
    if (!payload) return QSC_ERROR_OOM;
    for (size_t i = 0; i < RLEN; i++) {
        qsc_st32le(payload + 4 * i, ct->c0[i]);
        qsc_st32le(payload + 4 * (RLEN + i), ct->c1[i]);
    }
    e = qsc_serialize_wrap(QSC_ALG_BFV_N4096, (qsc_slice_t){ payload, (qs_u64)len }, out);
    qsc_free_zero(payload, len);
    return e;
}

qsc_error_t qsc_fhe_ct_deserialize(const qsc_fhe_ctx_t* c, qsc_slice_t in, qsc_fhe_ct_t** out) {
    qsc_algorithm_id_t alg;
    qsc_slice_t payload;
    qsc_error_t e;
    struct qsc_fhe_ct* ct;
    const size_t len = 2 * (size_t)RLEN * 4;
    if (!ctx_ok(c) || !out) return QSC_ERROR_INVALID_ARGUMENT;
    *out = NULL;
    if ((e = qsc_serialize_unwrap(in, &alg, &payload)) != QSC_OK) return e;
    if (alg != QSC_ALG_BFV_N4096) return QSC_ERROR_CAPABILITY_MISMATCH;
    if (payload.length != (qs_u64)len) return QSC_ERROR_MALFORMED_DATA;
    ct = ct_alloc();
    if (!ct) return QSC_ERROR_OOM;
    for (size_t i = 0; i < RLEN; i++) {
        ct->c0[i] = qsc_ld32le(payload.data + 4 * i);
        ct->c1[i] = qsc_ld32le(payload.data + 4 * (RLEN + i));
        unsigned prime = (unsigned)(i / N);
        if (ct->c0[i] >= c->q[prime] || ct->c1[i] >= c->q[prime]) {
            qsc_free_zero(ct, sizeof *ct);
            return QSC_ERROR_MALFORMED_DATA;
        }
    }
    *out = ct;
    return QSC_OK;
}
