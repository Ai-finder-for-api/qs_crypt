/**
 * @file qs_crypt_bn.c
 * @brief Fixed-limb bignum and Montgomery multiplication (CIOS).
 */
#include "qs_crypt_rsa_internal.h"
#include <string.h>

void qsc_bn_zero(qsc_bn* a) { memset(a->w, 0, sizeof a->w); }

void qsc_bn_set_u32(qsc_bn* a, uint32_t v) {
    qsc_bn_zero(a);
    a->w[0] = v;
}

void qsc_bn_copy(qsc_bn* r, const qsc_bn* a, int k) {
    memcpy(r->w, a->w, (size_t)k * sizeof(uint32_t));
}

int qsc_bn_from_be(qsc_bn* r, int k, const uint8_t* b, size_t len) {
    qsc_bn_zero(r);
    for (size_t i = 0; i < len; i++) {
        uint8_t byte = b[len - 1 - i];
        size_t limb = i / 4;
        if (limb >= (size_t)k) {
            if (byte != 0) return -1;
            continue;
        }
        r->w[limb] |= (uint32_t)byte << (8 * (i % 4));
    }
    return 0;
}

void qsc_bn_to_be(const qsc_bn* a, int k, uint8_t* out, size_t len) {
    for (size_t i = 0; i < len; i++) {
        size_t limb = i / 4;
        out[len - 1 - i] = (limb < (size_t)k)
            ? (uint8_t)(a->w[limb] >> (8 * (i % 4)))
            : 0;
    }
}

int qsc_bn_cmp(const qsc_bn* a, const qsc_bn* b, int k) {
    for (int i = k - 1; i >= 0; i--) {
        if (a->w[i] != b->w[i]) return a->w[i] < b->w[i] ? -1 : 1;
    }
    return 0;
}

uint32_t qsc_bn_sub(qsc_bn* r, const qsc_bn* a, const qsc_bn* b, int k) {
    uint64_t borrow = 0;
    for (int i = 0; i < k; i++) {
        uint64_t d = (uint64_t)a->w[i] - b->w[i] - borrow;
        r->w[i] = (uint32_t)d;
        borrow = (d >> 32) & 1u;
    }
    return (uint32_t)borrow;
}

uint32_t qsc_bn_add(qsc_bn* r, const qsc_bn* a, const qsc_bn* b, int k) {
    uint64_t carry = 0;
    for (int i = 0; i < k; i++) {
        uint64_t s = (uint64_t)a->w[i] + b->w[i] + carry;
        r->w[i] = (uint32_t)s;
        carry = s >> 32;
    }
    return (uint32_t)carry;
}

void qsc_bn_mul(qsc_bn* r, const qsc_bn* a, const qsc_bn* b, int k) {
    qsc_bn t;
    qsc_bn_zero(&t);
    for (int i = 0; i < k; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < k; j++) {
            uint64_t uv = (uint64_t)t.w[i + j] + (uint64_t)a->w[i] * b->w[j] + carry;
            t.w[i + j] = (uint32_t)uv;
            carry = uv >> 32;
        }
        t.w[i + k] = (uint32_t)carry;
    }
    memcpy(r->w, t.w, sizeof(uint32_t) * (size_t)(2 * k));
}

uint32_t qsc_bn_mul_small(qsc_bn* r, const qsc_bn* a, uint32_t m, int k) {
    uint64_t carry = 0;
    for (int i = 0; i < k; i++) {
        uint64_t uv = (uint64_t)a->w[i] * m + carry;
        r->w[i] = (uint32_t)uv;
        carry = uv >> 32;
    }
    return (uint32_t)carry;
}

uint32_t qsc_bn_divmod_small(qsc_bn* q, const qsc_bn* a, uint32_t d, int k) {
    uint64_t rem = 0;
    for (int i = k - 1; i >= 0; i--) {
        uint64_t cur = (rem << 32) | a->w[i];   /* read before write: q may alias a */
        q->w[i] = (uint32_t)(cur / d);
        rem = cur % d;
    }
    return (uint32_t)rem;
}

int qsc_bn_bit_len(const qsc_bn* a, int k) {
    for (int i = k - 1; i >= 0; i--) {
        uint32_t v = a->w[i];
        if (v) {
            int bits = 0;
            while (v) { bits++; v >>= 1; }
            return i * 32 + bits;
        }
    }
    return 0;
}

void qsc_bn_shr1(qsc_bn* a, int k) {
    for (int i = 0; i < k - 1; i++)
        a->w[i] = (a->w[i] >> 1) | (a->w[i + 1] << 31);
    a->w[k - 1] >>= 1;
}

void qsc_bn_sel(qsc_bn* r, const qsc_bn* a, const qsc_bn* b, uint32_t mask, int k) {
    for (int i = 0; i < k; i++)
        r->w[i] = (a->w[i] & mask) | (b->w[i] & ~mask);
}

void qsc_bn_mod(qsc_bn* r, const qsc_bn* a, int ka, const qsc_bn* m, int km) {
    qsc_bn_zero(r);
    for (int i = ka * 32 - 1; i >= 0; i--) {
        uint32_t bit = (a->w[i >> 5] >> (i & 31)) & 1u;
        uint32_t carry = r->w[km - 1] >> 31;
        for (int j = km - 1; j > 0; j--)
            r->w[j] = (r->w[j] << 1) | (r->w[j - 1] >> 31);
        r->w[0] = (r->w[0] << 1) | bit;
        if (carry || qsc_bn_cmp(r, m, km) >= 0)
            qsc_bn_sub(r, r, m, km);
    }
}

/* ---- Montgomery ------------------------------------------------------------- */

void qsc_mont_init(qsc_mont* m, const qsc_bn* n, int k) {
    uint32_t x;
    m->k = k;
    qsc_bn_zero(&m->n);
    qsc_bn_copy(&m->n, n, k);

    /* n0 = -n^-1 mod 2^32 by Newton iteration (n odd: x = n is correct to 3 bits). */
    x = n->w[0];
    for (int i = 0; i < 5; i++) x *= 2u - n->w[0] * x;
    m->n0 = 0u - x;

    /* R^2 mod n by 64k modular doublings of 1. */
    qsc_bn t;
    qsc_bn_zero(&t);
    t.w[0] = 1;
    for (int i = 0; i < 64 * k; i++) {
        uint32_t carry = 0;
        for (int j = 0; j < k; j++) {
            uint32_t next = t.w[j] >> 31;
            t.w[j] = (t.w[j] << 1) | carry;
            carry = next;
        }
        if (carry || qsc_bn_cmp(&t, &m->n, k) >= 0)
            qsc_bn_sub(&t, &t, &m->n, k);
    }
    qsc_bn_zero(&m->r2);
    qsc_bn_copy(&m->r2, &t, k);
}

void qsc_mont_mul(const qsc_mont* m, qsc_bn* r, const qsc_bn* a, const qsc_bn* b) {
    const int k = m->k;
    uint32_t t[QSC_BN_MAX + 2];
    memset(t, 0, sizeof t);

    for (int i = 0; i < k; i++) {
        uint64_t c = 0;
        for (int j = 0; j < k; j++) {
            uint64_t uv = (uint64_t)t[j] + (uint64_t)a->w[j] * b->w[i] + c;
            t[j] = (uint32_t)uv;
            c = uv >> 32;
        }
        uint64_t uv = (uint64_t)t[k] + c;
        t[k] = (uint32_t)uv;
        t[k + 1] = (uint32_t)(uv >> 32);

        uint32_t mq = t[0] * m->n0;
        uv = (uint64_t)t[0] + (uint64_t)mq * m->n.w[0];
        c = uv >> 32;
        for (int j = 1; j < k; j++) {
            uv = (uint64_t)t[j] + (uint64_t)mq * m->n.w[j] + c;
            t[j - 1] = (uint32_t)uv;
            c = uv >> 32;
        }
        uv = (uint64_t)t[k] + c;
        t[k - 1] = (uint32_t)uv;
        c = uv >> 32;
        t[k] = t[k + 1] + (uint32_t)c;
    }

    /* Result is t[0..k] < 2n. Subtract n once, selecting without a data-dependent branch. */
    qsc_bn tr, diff;
    memcpy(tr.w, t, sizeof(uint32_t) * (size_t)k);
    uint32_t borrow = qsc_bn_sub(&diff, &tr, &m->n, k);
    uint32_t use = (t[k] != 0) | (borrow == 0);
    uint32_t mask = 0u - use;
    qsc_bn_sel(r, &diff, &tr, mask, k);
}

void qsc_mont_to(const qsc_mont* m, qsc_bn* r, const qsc_bn* a) {
    qsc_mont_mul(m, r, a, &m->r2);
}

void qsc_mont_from(const qsc_mont* m, qsc_bn* r, const qsc_bn* a) {
    qsc_bn one;
    qsc_bn_set_u32(&one, 1);
    qsc_mont_mul(m, r, a, &one);
}

void qsc_mont_pow(const qsc_mont* m, qsc_bn* r, const qsc_bn* base,
                  const uint8_t* exp, size_t elen) {
    const int k = m->k;
    qsc_bn xm, acc, tmp, one;
    qsc_bn_set_u32(&one, 1);
    qsc_mont_to(m, &xm, base);
    qsc_mont_mul(m, &acc, &one, &m->r2);     /* acc = R mod n (Montgomery 1) */

    for (size_t i = 0; i < elen; i++) {
        for (int b = 7; b >= 0; b--) {
            qsc_mont_mul(m, &acc, &acc, &acc);
            qsc_mont_mul(m, &tmp, &acc, &xm);
            uint32_t bit = (exp[i] >> b) & 1u;
            qsc_bn_sel(&acc, &tmp, &acc, 0u - bit, k);
        }
    }
    qsc_mont_from(m, r, &acc);
}
