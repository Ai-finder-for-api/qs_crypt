/**
 * @file qs_crypt_fhe_internal.h
 * @brief BFV internals (RNS). Not part of the public API.
 */
#ifndef QS_CRYPT_FHE_INTERNAL_H
#define QS_CRYPT_FHE_INTERNAL_H

#include "qs_crypt/qs_crypt_fhe.h"
#include "../rsa/qs_crypt_rsa_internal.h"
#include <stdint.h>

#define QSC_FHE_MAGIC_CTX 0x46484331u
#define QSC_FHE_MAGIC_SK  0x46484332u
#define QSC_FHE_MAGIC_PK  0x46484333u
#define QSC_FHE_MAGIC_CT  0x46484334u

#define QSC_FHE_L ((int)QSC_FHE_NUM_PRIMES)
#define QSC_FHE_RES_BYTES ((size_t)QSC_FHE_L * QSC_FHE_N * 4u)   /* one RNS polynomial, bytes */

/* Residue arrays are flat: element (prime i, coefficient j) is at [i * N + j]. */
#define QSC_FHE_RLEN ((size_t)QSC_FHE_L * QSC_FHE_N)

struct qsc_fhe_ctx {
    uint32_t magic;
    uint32_t t;
    uint32_t q[QSC_FHE_L];                      /* RNS primes */
    uint32_t psi_pow[QSC_FHE_L][QSC_FHE_N];     /* psi_i^j */
    uint32_t ipsi_pow[QSC_FHE_L][QSC_FHE_N];    /* psi_i^-j * N^-1 */
    uint64_t omega[QSC_FHE_L], iomega[QSC_FHE_L];
    uint32_t delta_mod[QSC_FHE_L];              /* floor(Q/t) mod q_i */
    uint32_t qhat_inv[QSC_FHE_L];               /* (Q/q_i)^-1 mod q_i */
    qsc_bn   Q;                                 /* Q, 4 limbs */
    qsc_bn   Qhat[QSC_FHE_L];                   /* Q / q_i, 4 limbs */
    qsc_bn   Qhalf;                             /* floor(Q/2) */
    qsc_bn   delta;                             /* floor(Q/t) */
};

struct qsc_fhe_sk {
    uint32_t magic;
    uint32_t s[QSC_FHE_RLEN];                   /* NTT domain */
};

struct qsc_fhe_pk {
    uint32_t magic;
    uint32_t p0[QSC_FHE_RLEN];                  /* NTT domain */
    uint32_t p1[QSC_FHE_RLEN];                  /* NTT domain */
};

struct qsc_fhe_ct {
    uint32_t magic;
    uint32_t c0[QSC_FHE_RLEN];                  /* coefficient domain */
    uint32_t c1[QSC_FHE_RLEN];                  /* coefficient domain */
};

/* Per-prime NTT over Z_{q_i}[x]/(x^N + 1). a points to N residues. */
void qsc_fhe_ntt_fwd(const struct qsc_fhe_ctx* c, int prime, uint32_t* a);
void qsc_fhe_ntt_inv(const struct qsc_fhe_ctx* c, int prime, uint32_t* a);
qsc_error_t qsc_fhe_ntt_setup(struct qsc_fhe_ctx* c);

#endif
