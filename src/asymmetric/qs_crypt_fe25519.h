/**
 * @file qs_crypt_fe25519.h
 * @brief Internal field arithmetic over GF(2^255 - 19). Not part of the public API.
 */
#ifndef QS_CRYPT_FE25519_H
#define QS_CRYPT_FE25519_H

#include <stdint.h>

typedef uint64_t qsc_fe[5];

void qsc_fe_frombytes(qsc_fe h, const uint8_t s[32]);
void qsc_fe_tobytes(uint8_t s[32], const qsc_fe in);
void qsc_fe_add(qsc_fe h, const qsc_fe f, const qsc_fe g);
void qsc_fe_sub(qsc_fe h, const qsc_fe f, const qsc_fe g);
void qsc_fe_neg(qsc_fe h, const qsc_fe f);
void qsc_fe_mul(qsc_fe h, const qsc_fe f, const qsc_fe g);
void qsc_fe_sq(qsc_fe h, const qsc_fe f);
void qsc_fe_mul_small(qsc_fe h, const qsc_fe f, uint64_t k);
void qsc_fe_from_u64(qsc_fe h, uint64_t v);
void qsc_fe_cswap(qsc_fe a, qsc_fe b, uint64_t swap);
void qsc_fe_invert(qsc_fe out, const qsc_fe z);
void qsc_fe_pow(qsc_fe out, const qsc_fe base, const uint8_t e[32]);
int  qsc_fe_iszero(const qsc_fe f);
int  qsc_fe_isneg(const qsc_fe f);
int  qsc_fe_eq(const qsc_fe a, const qsc_fe b);

#endif
