/**
 * @file qs_crypt_aes_gcm.c
 * @brief AES-128 / AES-256 (FIPS 197, encryption only) and AES-GCM (NIST SP 800-38D).
 *
 * Notes:
 *  - The S-box is computed at init from GF(2^8) inversion + affine map; it is not typed in.
 *  - This is a TABLE-BASED implementation. S-box lookups are data-dependent, so it is
 *    vulnerable to cache-timing side channels on shared hardware. Prefer AES-NI or a
 *    vetted backend where timing attacks are in scope. ChaCha20-Poly1305 has no such issue.
 *  - GHASH multiplication is bit-serial with mask-based selection (no data-dependent branches).
 *  - Only 96-bit nonces are accepted (the only size the rest of QScrypt uses).
 */
#include "qs_crypt/qs_crypt.h"
#include "../core/qs_crypt_internal.h"
#include <string.h>

static uint8_t g_sbox[256];
static int     g_sbox_ready = 0;

static uint8_t xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ ((0u - (uint32_t)(x >> 7)) & 0x1Bu));
}

static uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    while (b) {
        if (b & 1) p ^= a;
        a = xtime(a);
        b >>= 1;
    }
    return p;
}

static uint8_t ginv(uint8_t x) {       /* x^254 == x^-1 in GF(2^8)*, and 0 -> 0 */
    uint8_t r = 1, b = x;
    int e = 254;
    if (x == 0) return 0;
    while (e) {
        if (e & 1) r = gmul(r, b);
        b = gmul(b, b);
        e >>= 1;
    }
    return r;
}

static uint8_t rotl8(uint8_t x, int n) {
    return (uint8_t)((x << n) | (x >> (8 - n)));
}

void qsc_aes_init_tables(void) {
    if (g_sbox_ready) return;
    for (int i = 0; i < 256; i++) {
        uint8_t inv = ginv((uint8_t)i);
        g_sbox[i] = inv ^ rotl8(inv, 1) ^ rotl8(inv, 2) ^ rotl8(inv, 3) ^ rotl8(inv, 4) ^ 0x63;
    }
    g_sbox_ready = 1;
}

/* ---- AES block cipher ----------------------------------------------------- */

typedef struct {
    uint8_t rk[240];
    int     nr;
} aes_ctx;

static int aes_expand(aes_ctx* c, const uint8_t* key, size_t keylen) {
    int nk = (int)(keylen / 4);
    int total;
    uint8_t w[240];
    uint8_t rcon = 1;
    c->nr = nk + 6;
    total = 4 * (c->nr + 1);
    memcpy(w, key, keylen);
    for (int i = nk; i < total; i++) {
        uint8_t t[4];
        memcpy(t, w + 4 * (i - 1), 4);
        if (i % nk == 0) {
            uint8_t t0 = t[0];
            t[0] = (uint8_t)(g_sbox[t[1]] ^ rcon);
            t[1] = g_sbox[t[2]];
            t[2] = g_sbox[t[3]];
            t[3] = g_sbox[t0];
            rcon = xtime(rcon);
        } else if (nk > 6 && i % nk == 4) {
            for (int k = 0; k < 4; k++) t[k] = g_sbox[t[k]];
        }
        for (int k = 0; k < 4; k++) w[4 * i + k] = w[4 * (i - nk) + k] ^ t[k];
    }
    memcpy(c->rk, w, (size_t)total * 4);
    qsc_secure_zero(w, sizeof w);
    return 1;
}

static void aes_encrypt_block(const aes_ctx* c, const uint8_t in[16], uint8_t out[16]) {
    uint8_t s[16], t[16];
    for (int i = 0; i < 16; i++) s[i] = in[i] ^ c->rk[i];
    for (int round = 1; round <= c->nr; round++) {
        for (int i = 0; i < 16; i++) s[i] = g_sbox[s[i]];                 /* SubBytes */
        for (int col = 0; col < 4; col++)                                  /* ShiftRows */
            for (int r = 0; r < 4; r++)
                t[r + 4 * col] = s[r + 4 * ((col + r) & 3)];
        memcpy(s, t, 16);
        if (round != c->nr) {                                              /* MixColumns */
            for (int col = 0; col < 4; col++) {
                uint8_t a0 = s[4*col], a1 = s[4*col+1], a2 = s[4*col+2], a3 = s[4*col+3];
                s[4*col]   = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3;
                s[4*col+1] = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3;
                s[4*col+2] = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3);
                s[4*col+3] = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3);
            }
        }
        for (int i = 0; i < 16; i++) s[i] ^= c->rk[16 * round + i];       /* AddRoundKey */
    }
    memcpy(out, s, 16);
    qsc_secure_zero(s, sizeof s);
    qsc_secure_zero(t, sizeof t);
}

/* ---- GHASH over GF(2^128), SP 800-38D Algorithm 1 -------------------------- */

typedef struct { uint64_t hi, lo; } u128b;

static u128b gf_mul(u128b x, u128b y) {
    u128b z = { 0, 0 }, v = y;
    for (int i = 0; i < 128; i++) {
        uint64_t bit = (i < 64) ? ((x.hi >> (63 - i)) & 1) : ((x.lo >> (127 - i)) & 1);
        uint64_t mask = (uint64_t)0 - bit;
        uint64_t lmask = (uint64_t)0 - (v.lo & 1);
        z.hi ^= v.hi & mask;
        z.lo ^= v.lo & mask;
        v.lo = (v.lo >> 1) | (v.hi << 63);
        v.hi = v.hi >> 1;
        v.hi ^= 0xE100000000000000ULL & lmask;
    }
    return z;
}

static void ghash_absorb(u128b* y, u128b h, const uint8_t* d, size_t n) {
    while (n) {
        uint8_t blk[16];
        size_t take = n < 16 ? n : 16;
        memset(blk, 0, 16);
        memcpy(blk, d, take);
        u128b x = { qsc_ld64be(blk), qsc_ld64be(blk + 8) };
        y->hi ^= x.hi;
        y->lo ^= x.lo;
        *y = gf_mul(*y, h);
        d += take;
        n -= take;
    }
}

/* Tag = GHASH(H, A, C) XOR E(K, J0) with J0 = nonce || 0x00000001. */
static void gcm_tag(const aes_ctx* c, const uint8_t nonce[12], u128b h,
                    const uint8_t* aad, size_t alen, const uint8_t* ct, size_t clen,
                    uint8_t tag[16]) {
    u128b y = { 0, 0 };
    uint8_t j0[16], ek[16], lens[16];
    memcpy(j0, nonce, 12);
    j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;
    ghash_absorb(&y, h, aad, alen);
    ghash_absorb(&y, h, ct, clen);
    qsc_st64be(lens, (uint64_t)alen * 8u);
    qsc_st64be(lens + 8, (uint64_t)clen * 8u);
    {
        u128b x = { qsc_ld64be(lens), qsc_ld64be(lens + 8) };
        y.hi ^= x.hi; y.lo ^= x.lo;
        y = gf_mul(y, h);
    }
    aes_encrypt_block(c, j0, ek);
    qsc_st64be(tag, y.hi ^ qsc_ld64be(ek));
    qsc_st64be(tag + 8, y.lo ^ qsc_ld64be(ek + 8));
    qsc_secure_zero(ek, sizeof ek);
}

static void gcm_ctr(const aes_ctx* c, const uint8_t nonce[12],
                    const uint8_t* in, size_t n, uint8_t* out) {
    uint8_t ctr[16], ks[16];
    uint32_t counter = 2;   /* inc32(J0) */
    memcpy(ctr, nonce, 12);
    while (n) {
        size_t take = n < 16 ? n : 16;
        ctr[12] = (uint8_t)(counter >> 24); ctr[13] = (uint8_t)(counter >> 16);
        ctr[14] = (uint8_t)(counter >> 8);  ctr[15] = (uint8_t)counter;
        aes_encrypt_block(c, ctr, ks);
        for (size_t i = 0; i < take; i++) out[i] = in[i] ^ ks[i];
        in += take; out += take; n -= take;
        counter++;
    }
    qsc_secure_zero(ks, sizeof ks);
}

static qsc_error_t gcm_setup(aes_ctx* c, u128b* h, const qs_u8* key, qs_u64 keylen) {
    uint8_t zero[16] = {0}, hb[16];
    if (!g_sbox_ready) return QSC_ERROR_NOT_INITIALIZED;
    if (keylen != 16 && keylen != 32) return QSC_ERROR_KEY_SIZE_MISMATCH;
    aes_expand(c, key, (size_t)keylen);
    aes_encrypt_block(c, zero, hb);
    h->hi = qsc_ld64be(hb);
    h->lo = qsc_ld64be(hb + 8);
    qsc_secure_zero(hb, sizeof hb);
    return QSC_OK;
}

#define GCM_MAX_PT (((qs_u64)1 << 36) - 32u)

qsc_error_t qsc_gcm_encrypt(const qs_u8* key, qs_u64 keylen, const qs_u8 nonce[12],
                            qsc_slice_t aad, qsc_slice_t pt, qs_u8* ct_out,
                            qs_u8 tag_out[16]) {
    aes_ctx c;
    u128b h;
    qsc_error_t e;
    if (!key || !nonce || !tag_out) return QSC_ERROR_INVALID_ARGUMENT;
    if (pt.length && (!pt.data || !ct_out)) return QSC_ERROR_INVALID_ARGUMENT;
    if (aad.length && !aad.data) return QSC_ERROR_INVALID_ARGUMENT;
    if (pt.length > GCM_MAX_PT) return QSC_ERROR_INVALID_PARAMETERS;
    if ((e = gcm_setup(&c, &h, key, keylen)) != QSC_OK) return e;
    gcm_ctr(&c, nonce, pt.data, (size_t)pt.length, ct_out);
    gcm_tag(&c, nonce, h, aad.data, (size_t)aad.length, ct_out, (size_t)pt.length, tag_out);
    qsc_secure_zero(&c, sizeof c);
    return QSC_OK;
}

qsc_error_t qsc_gcm_decrypt(const qs_u8* key, qs_u64 keylen, const qs_u8 nonce[12],
                            qsc_slice_t aad, qsc_slice_t ct, const qs_u8 tag[16],
                            qs_u8* pt_out) {
    aes_ctx c;
    u128b h;
    uint8_t expect[16];
    qsc_error_t e;
    if (!key || !nonce || !tag) return QSC_ERROR_INVALID_ARGUMENT;
    if (ct.length && (!ct.data || !pt_out)) return QSC_ERROR_INVALID_ARGUMENT;
    if (aad.length && !aad.data) return QSC_ERROR_INVALID_ARGUMENT;
    if (ct.length > GCM_MAX_PT) return QSC_ERROR_INVALID_PARAMETERS;
    if ((e = gcm_setup(&c, &h, key, keylen)) != QSC_OK) return e;
    gcm_tag(&c, nonce, h, aad.data, (size_t)aad.length, ct.data, (size_t)ct.length, expect);
    if (!qsc_constant_time_equal(expect, tag, 16)) {
        qsc_secure_zero(&c, sizeof c);
        return QSC_ERROR_AUTH_FAILED;      /* no plaintext has been written */
    }
    gcm_ctr(&c, nonce, ct.data, (size_t)ct.length, pt_out);
    qsc_secure_zero(&c, sizeof c);
    return QSC_OK;
}

#include "qs_crypt_aes_modes.inc"
