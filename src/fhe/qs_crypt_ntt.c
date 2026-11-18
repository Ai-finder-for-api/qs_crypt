/**
 * @file qs_crypt_ntt.c
 * @brief Negacyclic NTT over Z_{q_i}[x]/(x^N + 1) for each RNS prime q_i.
 *
 * psi is a primitive 2N-th root of unity: psi = g^((q-1)/2N) with psi^N = -1. The search
 * checks that condition directly, so the transform is correct for any prime q = 1 mod 2N.
 */
#include "qs_crypt/qs_crypt.h"
#include "qs_crypt_fhe_internal.h"

#define N QSC_FHE_N

static const uint32_t PRIMES[QSC_FHE_L] = { 2013265921u, 1004535809u, 469762049u };

static uint64_t pw(uint64_t b, uint64_t e, uint64_t q) {
    uint64_t r = 1;
    b %= q;
    while (e) {
        if (e & 1) r = r * b % q;
        b = b * b % q;
        e >>= 1;
    }
    return r;
}

static void bitrev(uint32_t* a) {
    for (unsigned i = 1, j = 0; i < N; i++) {
        unsigned bit = N >> 1;
        for (; j & bit; bit >>= 1) j ^= bit;
        j ^= bit;
        if (i < j) {
            uint32_t t = a[i];
            a[i] = a[j];
            a[j] = t;
        }
    }
}

static void stages(uint32_t* a, uint64_t root, uint64_t q) {
    for (unsigned len = 2; len <= N; len <<= 1) {
        uint64_t wl = pw(root, N / len, q);
        unsigned half = len >> 1;
        for (unsigned i = 0; i < N; i += len) {
            uint64_t w = 1;
            for (unsigned j = 0; j < half; j++) {
                uint64_t u = a[i + j];
                uint64_t v = (uint64_t)a[i + j + half] * w % q;
                a[i + j] = (uint32_t)((u + v) % q);
                a[i + j + half] = (uint32_t)((u + q - v) % q);
                w = w * wl % q;
            }
        }
    }
}

qsc_error_t qsc_fhe_ntt_setup(struct qsc_fhe_ctx* c) {
    for (int i = 0; i < QSC_FHE_L; i++) {
        uint64_t q = PRIMES[i];
        uint64_t psi = 0;
        c->q[i] = PRIMES[i];
        for (uint64_t g = 2; g < q && !psi; g++) {
            uint64_t cand = pw(g, (q - 1) / (2 * N), q);
            if (pw(cand, N, q) == q - 1) psi = cand;
        }
        if (!psi) return QSC_ERROR_INVALID_PARAMETERS;
        uint64_t ipsi = pw(psi, q - 2, q);
        uint64_t ninv = pw(N, q - 2, q);
        c->omega[i] = psi * psi % q;
        c->iomega[i] = ipsi * ipsi % q;
        uint64_t cp = 1, cip = ninv;
        for (unsigned j = 0; j < N; j++) {
            c->psi_pow[i][j] = (uint32_t)cp;
            c->ipsi_pow[i][j] = (uint32_t)cip;
            cp = cp * psi % q;
            cip = cip * ipsi % q;
        }
    }
    return QSC_OK;
}

void qsc_fhe_ntt_fwd(const struct qsc_fhe_ctx* c, int prime, uint32_t* a) {
    uint64_t q = c->q[prime];
    for (unsigned j = 0; j < N; j++)
        a[j] = (uint32_t)((uint64_t)a[j] * c->psi_pow[prime][j] % q);
    bitrev(a);
    stages(a, c->omega[prime], q);
}

void qsc_fhe_ntt_inv(const struct qsc_fhe_ctx* c, int prime, uint32_t* a) {
    uint64_t q = c->q[prime];
    bitrev(a);
    stages(a, c->iomega[prime], q);
    for (unsigned j = 0; j < N; j++)
        a[j] = (uint32_t)((uint64_t)a[j] * c->ipsi_pow[prime][j] % q);
}
