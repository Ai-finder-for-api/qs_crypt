/* qs_crypt_aes_modes.inc - included at the end of qs_crypt_aes_gcm.c (needs its static AES core).
 *
 * Adds for JOSE/JWE: AES block decrypt, AES-CBC (PKCS#7), AES Key Wrap (RFC 3394),
 * and PBKDF2-HMAC (RFC 8018, SHA-256/384/512).
 *
 * Same caveat as the rest of this file: table-based AES, data-dependent S-box lookups.
 */
#include "../mac/qs_crypt_hmac_internal.h"

static uint8_t g_inv_sbox[256];
static int     g_inv_ready = 0;

static void inv_tables(void) {
    if (g_inv_ready) return;
    qsc_aes_init_tables();
    for (int i = 0; i < 256; i++) g_inv_sbox[g_sbox[i]] = (uint8_t)i;
    g_inv_ready = 1;
}

static uint8_t mul9(uint8_t x)  { return (uint8_t)(xtime(xtime(xtime(x))) ^ x); }
static uint8_t mul11(uint8_t x) { return (uint8_t)(xtime(xtime(xtime(x))) ^ xtime(x) ^ x); }
static uint8_t mul13(uint8_t x) { return (uint8_t)(xtime(xtime(xtime(x))) ^ xtime(xtime(x)) ^ x); }
static uint8_t mul14(uint8_t x) { return (uint8_t)(xtime(xtime(xtime(x))) ^ xtime(xtime(x)) ^ xtime(x)); }

static void aes_decrypt_block(const aes_ctx* c, const uint8_t in[16], uint8_t out[16]) {
    uint8_t s[16], t[16];
    for (int i = 0; i < 16; i++) s[i] = in[i] ^ c->rk[16 * c->nr + i];
    for (int round = c->nr - 1; round >= 0; round--) {
        for (int col = 0; col < 4; col++)                       /* InvShiftRows */
            for (int r = 0; r < 4; r++)
                t[r + 4 * ((col + r) & 3)] = s[r + 4 * col];
        for (int i = 0; i < 16; i++) s[i] = g_inv_sbox[t[i]];   /* InvSubBytes */
        for (int i = 0; i < 16; i++) s[i] ^= c->rk[16 * round + i];
        if (round != 0) {                                       /* InvMixColumns */
            for (int col = 0; col < 4; col++) {
                uint8_t a0 = s[4*col], a1 = s[4*col+1], a2 = s[4*col+2], a3 = s[4*col+3];
                s[4*col]   = mul14(a0) ^ mul11(a1) ^ mul13(a2) ^ mul9(a3);
                s[4*col+1] = mul9(a0)  ^ mul14(a1) ^ mul11(a2) ^ mul13(a3);
                s[4*col+2] = mul13(a0) ^ mul9(a1)  ^ mul14(a2) ^ mul11(a3);
                s[4*col+3] = mul11(a0) ^ mul13(a1) ^ mul9(a2)  ^ mul14(a3);
            }
        }
    }
    memcpy(out, s, 16);
    qsc_secure_zero(s, sizeof s);
    qsc_secure_zero(t, sizeof t);
}

static int aes_key_ok(size_t n) { return n == 16 || n == 24 || n == 32; }

/* ---- CBC with PKCS#7 padding ------------------------------------------------------------ */

/* ct_out must hold ((pt_len / 16) + 1) * 16 bytes. Returns the ciphertext length via *ct_len. */
qsc_error_t qsc_aes_cbc_encrypt(qsc_slice_t key, const qs_u8 iv[16], qsc_slice_t pt,
                                qs_u8* ct_out, qs_u64* ct_len) {
    aes_ctx c;
    uint8_t prev[16], blk[16];
    size_t n, full, pad, total;
    if (!key.data || !aes_key_ok((size_t)key.length) || !iv || !ct_out || !ct_len) return QSC_ERROR_INVALID_ARGUMENT;
    if (pt.length && !pt.data) return QSC_ERROR_INVALID_ARGUMENT;
    qsc_aes_init_tables();
    aes_expand(&c, key.data, (size_t)key.length);
    n = (size_t)pt.length;
    full = n / 16;
    pad = 16 - (n % 16);
    total = (full + 1) * 16;
    memcpy(prev, iv, 16);
    for (size_t b = 0; b <= full; b++) {
        if (b < full) memcpy(blk, pt.data + 16 * b, 16);
        else { size_t rem = n - 16 * full; if (rem) memcpy(blk, pt.data + 16 * full, rem); memset(blk + rem, (int)pad, pad); }
        for (int i = 0; i < 16; i++) blk[i] ^= prev[i];
        aes_encrypt_block(&c, blk, ct_out + 16 * b);
        memcpy(prev, ct_out + 16 * b, 16);
    }
    *ct_len = total;
    qsc_secure_zero(&c, sizeof c);
    qsc_secure_zero(blk, sizeof blk);
    return QSC_OK;
}

/* pt_out must hold ct.length bytes. Padding is validated without data-dependent branches on the
 * pad value; any failure returns QSC_ERROR_DECRYPTION_FAILED. Always authenticate (HMAC) the
 * ciphertext BEFORE calling this: CBC alone is malleable and padding errors are an oracle. */
qsc_error_t qsc_aes_cbc_decrypt(qsc_slice_t key, const qs_u8 iv[16], qsc_slice_t ct,
                                qs_u8* pt_out, qs_u64* pt_len) {
    aes_ctx c;
    uint8_t prev[16], blk[16];
    size_t nb, pad;
    uint32_t bad = 0;
    if (!key.data || !aes_key_ok((size_t)key.length) || !iv || !ct.data || !pt_out || !pt_len) return QSC_ERROR_INVALID_ARGUMENT;
    if (ct.length == 0 || (ct.length % 16) != 0) return QSC_ERROR_DECRYPTION_FAILED;
    inv_tables();
    aes_expand(&c, key.data, (size_t)key.length);
    nb = (size_t)ct.length / 16;
    memcpy(prev, iv, 16);
    for (size_t b = 0; b < nb; b++) {
        aes_decrypt_block(&c, ct.data + 16 * b, blk);
        for (int i = 0; i < 16; i++) pt_out[16 * b + i] = blk[i] ^ prev[i];
        memcpy(prev, ct.data + 16 * b, 16);
    }
    pad = pt_out[ct.length - 1];
    bad |= (uint32_t)(pad == 0) | (uint32_t)(pad > 16);
    for (size_t i = 0; i < 16; i++) {
        uint32_t in_pad = (uint32_t)(i < pad);
        bad |= in_pad & (uint32_t)(pt_out[ct.length - 1 - i] != (uint8_t)pad);
    }
    qsc_secure_zero(&c, sizeof c);
    qsc_secure_zero(blk, sizeof blk);
    if (bad) { qsc_secure_zero(pt_out, (size_t)ct.length); return QSC_ERROR_DECRYPTION_FAILED; }
    *pt_len = ct.length - pad;
    return QSC_OK;
}

/* ---- AES Key Wrap, RFC 3394 -------------------------------------------------------------- */

/* kek: 16/24/32 bytes. plaintext key: multiple of 8 bytes, >= 16. out = in + 8 bytes. */
qsc_error_t qsc_aes_kw_wrap(qsc_slice_t kek, qsc_slice_t key_in, qs_u8* out) {
    static const uint8_t IV[8] = {0xA6,0xA6,0xA6,0xA6,0xA6,0xA6,0xA6,0xA6};
    aes_ctx c;
    uint8_t A[8], B[16];
    size_t n;
    if (!kek.data || !aes_key_ok((size_t)kek.length) || !key_in.data || !out) return QSC_ERROR_INVALID_ARGUMENT;
    if (key_in.length < 16 || (key_in.length % 8) != 0) return QSC_ERROR_INVALID_PARAMETERS;
    qsc_aes_init_tables();
    aes_expand(&c, kek.data, (size_t)kek.length);
    n = (size_t)key_in.length / 8;
    memcpy(A, IV, 8);
    memcpy(out + 8, key_in.data, (size_t)key_in.length);
    for (int j = 0; j < 6; j++) {
        for (size_t i = 1; i <= n; i++) {
            uint64_t t = (uint64_t)n * (uint64_t)j + i;
            memcpy(B, A, 8);
            memcpy(B + 8, out + 8 * i, 8);
            aes_encrypt_block(&c, B, B);
            memcpy(A, B, 8);
            for (int k = 0; k < 8; k++) A[7 - k] ^= (uint8_t)(t >> (8 * k));
            memcpy(out + 8 * i, B + 8, 8);
        }
    }
    memcpy(out, A, 8);
    qsc_secure_zero(&c, sizeof c);
    qsc_secure_zero(B, sizeof B);
    return QSC_OK;
}

/* wrapped: n+1 blocks of 8 bytes. out receives (len - 8) bytes. The integrity register is
 * compared in constant time. */
qsc_error_t qsc_aes_kw_unwrap(qsc_slice_t kek, qsc_slice_t wrapped, qs_u8* out) {
    static const uint8_t IV[8] = {0xA6,0xA6,0xA6,0xA6,0xA6,0xA6,0xA6,0xA6};
    aes_ctx c;
    uint8_t A[8], B[16];
    size_t n;
    if (!kek.data || !aes_key_ok((size_t)kek.length) || !wrapped.data || !out) return QSC_ERROR_INVALID_ARGUMENT;
    if (wrapped.length < 24 || (wrapped.length % 8) != 0) return QSC_ERROR_INVALID_PARAMETERS;
    inv_tables();
    aes_expand(&c, kek.data, (size_t)kek.length);
    n = (size_t)wrapped.length / 8 - 1;
    memcpy(A, wrapped.data, 8);
    memcpy(out, wrapped.data + 8, 8 * n);
    for (int j = 5; j >= 0; j--) {
        for (size_t i = n; i >= 1; i--) {
            uint64_t t = (uint64_t)n * (uint64_t)j + i;
            memcpy(B, A, 8);
            for (int k = 0; k < 8; k++) B[7 - k] ^= (uint8_t)(t >> (8 * k));
            memcpy(B + 8, out + 8 * (i - 1), 8);
            aes_decrypt_block(&c, B, B);
            memcpy(A, B, 8);
            memcpy(out + 8 * (i - 1), B + 8, 8);
        }
    }
    qsc_secure_zero(&c, sizeof c);
    qsc_secure_zero(B, sizeof B);
    if (!qsc_constant_time_equal(A, IV, 8)) { qsc_secure_zero(out, 8 * n); return QSC_ERROR_AUTH_FAILED; }
    return QSC_OK;
}

/* ---- PBKDF2-HMAC, RFC 8018 section 5.2 ----------------------------------------------------- */

/* prf: QSC_ALG_HMAC_SHA2_256 / 384 / 512. out must hold dklen bytes. */
qsc_error_t qsc_pbkdf2(qsc_algorithm_id_t prf, qsc_slice_t password, qsc_slice_t salt,
                       qs_u32 iterations, qs_u8* out, qs_u64 dklen) {
    size_t hl = qsc_hmac_outlen(prf);
    uint8_t u[64], t[64];
    uint8_t ctr[4];
    qsc_hmac_ctx base, c;
    qsc_error_t e;
    if (!hl) return QSC_ERROR_UNSUPPORTED;
    if (!out || (password.length && !password.data) || (salt.length && !salt.data)) return QSC_ERROR_INVALID_ARGUMENT;
    if (iterations == 0 || dklen == 0 || dklen > (qs_u64)0xFFFFFFFFu * hl) return QSC_ERROR_INVALID_PARAMETERS;
    if ((e = qsc_hmac_begin(prf, password.data, (size_t)password.length, &base)) != QSC_OK) return e;
    for (qs_u64 blk = 1, off = 0; off < dklen; blk++, off += hl) {
        size_t take = (size_t)((dklen - off) < hl ? (dklen - off) : hl);
        ctr[0] = (uint8_t)(blk >> 24); ctr[1] = (uint8_t)(blk >> 16);
        ctr[2] = (uint8_t)(blk >> 8);  ctr[3] = (uint8_t)blk;
        c = base;
        qsc_hmac_update(&c, salt.data, (size_t)salt.length);
        qsc_hmac_update(&c, ctr, 4);
        qsc_hmac_finish(&c, u);
        memcpy(t, u, hl);
        for (qs_u32 i = 1; i < iterations; i++) {
            c = base;
            qsc_hmac_update(&c, u, hl);
            qsc_hmac_finish(&c, u);
            for (size_t k = 0; k < hl; k++) t[k] ^= u[k];
        }
        memcpy(out + off, t, take);
    }
    qsc_secure_zero(&base, sizeof base);
    qsc_secure_zero(u, sizeof u);
    qsc_secure_zero(t, sizeof t);
    return QSC_OK;
}
