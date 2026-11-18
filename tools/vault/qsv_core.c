/**
 * @file qsv_core.c
 * @brief qsvault layered encryption: encrypt, decrypt, info, key files, PBKDF2.
 */
#include "qsv_core.h"
#include "qsv_cloud.h"
#include "qsv_config.h"
#include <stdlib.h>
#include <string.h>

#define OFF_FLAGS   4
#define OFF_ITER    8
#define OFF_SALTPW  12
#define OFF_SALTKDF 28
#define OFF_CKEYID  60
#define OFF_USBID   92
#define OFF_WLEN    124
#define SIG_BYTES   3309u
#define PK_BYTES    1952u
#define SK_BYTES    4032u

static const uint8_t FILE_MAGIC[4]   = { 'Q', 'S', 'V', '1' };
static const uint8_t KEY_MAGIC[8]    = { 'Q', 'S', 'C', 'K', 'E', 'Y', '0', '1' };
static const char    SIGN_CTX[]      = "qsvault-v1";

static uint32_t rd32(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}
static uint64_t rd64(const uint8_t* p) {
    return ((uint64_t)rd32(p) << 32) | (uint64_t)rd32(p + 4);
}
static void wr32(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}
static void wr64(uint8_t* p, uint64_t v) {
    wr32(p, (uint32_t)(v >> 32));
    wr32(p + 4, (uint32_t)v);
}

void qsv_free(uint8_t* p, size_t n) {
    if (p) {
        qsc_secure_zero(p, n);
        free(p);
    }
}

static qsc_error_t sha256_of(const uint8_t* in, size_t n, uint8_t out[32]) {
    qsc_digest_t d;
    qsc_error_t e = qsc_hash(QSC_ALG_SHA2_256, (qsc_slice_t){ in, (qs_u64)n }, &d);
    if (e == QSC_OK) memcpy(out, d.data, 32);
    return e;
}

qsc_error_t qsv_pbkdf2_sha256(const uint8_t* pw, size_t pwl, const uint8_t* salt, size_t saltl,
                              uint32_t iters, uint8_t out[32]) {
    uint8_t* m;
    qsc_tag_t u, t;
    qsc_slice_t key;
    qsc_error_t e;
    uint32_t i;
    int j;

    if (!pw || pwl == 0 || !salt || !out || iters == 0) return QSC_ERROR_INVALID_ARGUMENT;
    m = (uint8_t*)malloc(saltl + 4);
    if (!m) return QSC_ERROR_OOM;
    memcpy(m, salt, saltl);
    wr32(m + saltl, 1u);
    key.data = pw;
    key.length = (qs_u64)pwl;

    e = qsc_mac(QSC_ALG_HMAC_SHA2_256, key, (qsc_slice_t){ m, (qs_u64)(saltl + 4) }, &u);
    free(m);
    if (e != QSC_OK) return e;
    memcpy(t.data, u.data, 32);
    t.length = 32;

    for (i = 1; i < iters; i++) {
        qsc_tag_t u2;
        e = qsc_mac(QSC_ALG_HMAC_SHA2_256, key, (qsc_slice_t){ u.data, 32 }, &u2);
        if (e != QSC_OK) {
            qsc_secure_zero(&t, sizeof t);
            qsc_secure_zero(&u, sizeof u);
            return e;
        }
        for (j = 0; j < 32; j++) t.data[j] ^= u2.data[j];
        u = u2;
    }
    memcpy(out, t.data, 32);
    qsc_secure_zero(&t, sizeof t);
    qsc_secure_zero(&u, sizeof u);
    return QSC_OK;
}

/* KEK = HKDF(salt_kdf, pwkey || ckey [|| usb], label bound to the flag set). */
static qsc_error_t derive_kek(const uint8_t pwkey[32], const uint8_t* ckey, const uint8_t* usb,
                              uint8_t flags, const uint8_t salt[32], uint8_t kek[32]) {
    uint8_t ikm[96];
    uint8_t label[10];
    size_t n = 0;
    qsc_buffer_t out;
    qsc_error_t e;

    memcpy(ikm + n, pwkey, 32); n += 32;
    memcpy(ikm + n, ckey, 32);  n += 32;
    if (flags & QSV_FLAG_USB) { memcpy(ikm + n, usb, 32); n += 32; }

    memcpy(label, "QSV1-KEK", 8);
    label[8] = flags;
    label[9] = 0x01;

    out.data = NULL;
    out.length = 32;
    e = qsc_derive_key(QSC_ALG_HKDF_SHA2_256, (qsc_slice_t){ salt, 32 },
                       (qsc_slice_t){ ikm, (qs_u64)n }, (qsc_slice_t){ label, 10 }, &out);
    qsc_secure_zero(ikm, sizeof ikm);
    if (e == QSC_OK) {
        if (out.length != 32 || out.data == NULL) e = QSC_ERROR_OUTPUT_SIZE_MISMATCH;
        else memcpy(kek, out.data, 32);
        qsc_buffer_free(&out);
    }
    return e;
}

static qsc_error_t seal_under(const uint8_t key[32], const uint8_t* aad, size_t aadl,
                              const uint8_t* pt, size_t ptl, qsc_buffer_t* out) {
    qsc_key_t* k = NULL;
    qsc_error_t e = qsc_key_import(QSC_ALG_CHACHA20_POLY1305, (qsc_slice_t){ key, 32 }, &k);
    if (e != QSC_OK) return e;
    out->data = NULL;
    out->length = 0;
    e = qsc_seal(k, (qsc_slice_t){ aad, (qs_u64)aadl }, (qsc_slice_t){ pt, (qs_u64)ptl }, out);
    qsc_key_destroy(k);
    return e;
}

static qsc_error_t open_under(const uint8_t key[32], const uint8_t* aad, size_t aadl,
                              const uint8_t* ct, size_t ctl, qsc_buffer_t* out) {
    qsc_key_t* k = NULL;
    qsc_error_t e = qsc_key_import(QSC_ALG_CHACHA20_POLY1305, (qsc_slice_t){ key, 32 }, &k);
    if (e != QSC_OK) return e;
    out->data = NULL;
    out->length = 0;
    e = qsc_open(k, (qsc_slice_t){ aad, (qs_u64)aadl }, (qsc_slice_t){ ct, (qs_u64)ctl }, out);
    qsc_key_destroy(k);
    return e;
}

static qsc_error_t check_secrets_for_encrypt(const qsv_secrets_t* s) {
    if (!s || !s->password || !s->ckey) return QSC_ERROR_INVALID_ARGUMENT;
    if (s->password_len < QSV_MIN_PASSWORD) return QSC_ERROR_WEAK_KEY;
    if (s->iterations > QSV_MAX_ITER) return QSC_ERROR_INVALID_PARAMETERS;
    if (s->sign_sk && !s->sign_pk) return QSC_ERROR_INVALID_ARGUMENT;
    return QSC_OK;
}

qsc_error_t qsv_encrypt(const qsv_secrets_t* s, const uint8_t* pt, size_t ptl,
                        uint8_t** out, size_t* outl) {
    uint8_t hdr[QSV_HEADER_BYTES];
    uint8_t pwkey[32], kek[32], fk[32];
    uint8_t flags;
    uint32_t iters;
    qsc_buffer_t wrapped, body;
    uint8_t* buf = NULL;
    size_t total = 0, off = 0, sig_extra = 0;
    qsc_error_t e;

    if (!out || !outl || (!pt && ptl)) return QSC_ERROR_INVALID_ARGUMENT;
    *out = NULL;
    *outl = 0;
    e = check_secrets_for_encrypt(s);
    if (e != QSC_OK) return e;

    flags = QSV_FLAG_PASSWORD | QSV_FLAG_CKEY;
    if (s->usb) flags |= QSV_FLAG_USB;
    if (s->sign_sk) flags |= QSV_FLAG_SIGNED;
#if QSV_CLOUD_ENABLED
    flags |= QSV_FLAG_CLOUD;
    {
        uint8_t commit[32];
        e = qsv_cloud_commitment(s->ckey, commit);
        if (e == QSC_OK) e = qsv_cloud_register(commit);
        qsc_secure_zero(commit, sizeof commit);
        if (e != QSC_OK) return e;
    }
#endif

    iters = s->iterations ? s->iterations : QSV_DEFAULT_ITER;
    memset(hdr, 0, sizeof hdr);
    memcpy(hdr, FILE_MAGIC, 4);
    hdr[OFF_FLAGS] = flags;
    wr32(hdr + OFF_ITER, iters);
    e = qsc_random_bytes(hdr + OFF_SALTPW, 16);
    if (e == QSC_OK) e = qsc_random_bytes(hdr + OFF_SALTKDF, 32);
    if (e == QSC_OK) e = qsc_random_bytes(fk, 32);
    if (e != QSC_OK) return e;
    if (sha256_of(s->ckey, 32, hdr + OFF_CKEYID) != QSC_OK) return QSC_ERROR_INVALID_ARGUMENT;
    if (s->usb && sha256_of(s->usb, 32, hdr + OFF_USBID) != QSC_OK) return QSC_ERROR_INVALID_ARGUMENT;

    wrapped.data = NULL; wrapped.length = 0;
    body.data = NULL;    body.length = 0;

    e = qsv_pbkdf2_sha256(s->password, s->password_len, hdr + OFF_SALTPW, 16, iters, pwkey);
    if (e == QSC_OK) e = derive_kek(pwkey, s->ckey, s->usb, flags, hdr + OFF_SALTKDF, kek);
    if (e == QSC_OK) e = seal_under(kek, hdr, QSV_HEADER_BYTES, fk, 32, &wrapped);
    if (e == QSC_OK) e = seal_under(fk, hdr, QSV_HEADER_BYTES, pt, ptl, &body);
    if (e != QSC_OK) goto cleanup;

    if (wrapped.length > 0xFFFFFFFFu) { e = QSC_ERROR_OUTPUT_SIZE_MISMATCH; goto cleanup; }
    if (s->sign_sk) sig_extra = PK_BYTES + SIG_BYTES;
    total = QSV_HEADER_BYTES + 4 + (size_t)wrapped.length + 8 + (size_t)body.length + sig_extra;
    buf = (uint8_t*)malloc(total);
    if (!buf) { e = QSC_ERROR_OOM; goto cleanup; }

    off = 0;
    memcpy(buf + off, hdr, QSV_HEADER_BYTES); off += QSV_HEADER_BYTES;
    wr32(buf + off, (uint32_t)wrapped.length); off += 4;
    memcpy(buf + off, wrapped.data, (size_t)wrapped.length); off += (size_t)wrapped.length;
    wr64(buf + off, (uint64_t)body.length); off += 8;
    memcpy(buf + off, body.data, (size_t)body.length); off += (size_t)body.length;

    if (s->sign_sk) {
        /* Signature covers everything written so far; the signer key is embedded after it. */
        memcpy(buf + off, s->sign_pk, PK_BYTES);
        e = qsc_mldsa65_sign(s->sign_sk, (qsc_slice_t){ buf, (qs_u64)off },
                             (qsc_slice_t){ (const qs_u8*)SIGN_CTX, 10 }, buf + off + PK_BYTES);
        if (e != QSC_OK) { qsv_free(buf, total); buf = NULL; goto cleanup; }
    }

    *out = buf;
    *outl = total;
    buf = NULL;
    e = QSC_OK;

cleanup:
    qsc_secure_zero(pwkey, sizeof pwkey);
    qsc_secure_zero(kek, sizeof kek);
    qsc_secure_zero(fk, sizeof fk);
    if (wrapped.data) qsc_buffer_free(&wrapped);
    if (body.data) qsc_buffer_free(&body);
    if (buf) qsv_free(buf, total);
    return e;
}

/* Parse and bounds-check the file layout. Fills the pointers and lengths. */
static qsc_error_t parse_layout(const uint8_t* in, size_t inl, uint8_t* flags, uint32_t* iters,
                                size_t* wlen, size_t* blen, size_t* base) {
    uint64_t bl;
    size_t wl, b;
    if (inl < QSV_HEADER_BYTES + 4 + 8) return QSC_ERROR_TRUNCATED;
    if (memcmp(in, FILE_MAGIC, 4) != 0) return QSC_ERROR_MALFORMED_DATA;
    *flags = in[OFF_FLAGS];
    if ((*flags & ~QSV_FLAG_KNOWN) != 0) return QSC_ERROR_MALFORMED_DATA;
    *iters = rd32(in + OFF_ITER);
    wl = rd32(in + OFF_WLEN);
    if (QSV_HEADER_BYTES + 4 + wl + 8 > inl) return QSC_ERROR_TRUNCATED;
    bl = rd64(in + QSV_HEADER_BYTES + 4 + wl);
    if (bl > (uint64_t)(inl)) return QSC_ERROR_TRUNCATED;
    b = (size_t)bl;
    *base = QSV_HEADER_BYTES + 4 + wl + 8 + b;
    if (*base > inl) return QSC_ERROR_TRUNCATED;
    *wlen = wl;
    *blen = b;
    return QSC_OK;
}

qsc_error_t qsv_info(const uint8_t* in, size_t inl, qsv_info_t* info) {
    uint8_t flags;
    uint32_t iters;
    size_t wl, bl, base;
    qsc_error_t e;
    if (!in || !info) return QSC_ERROR_INVALID_ARGUMENT;
    e = parse_layout(in, inl, &flags, &iters, &wl, &bl, &base);
    if (e != QSC_OK) return e;
    info->flags = flags;
    info->iterations = iters;
    info->total_bytes = inl;
    return QSC_OK;
}

qsc_error_t qsv_decrypt(const qsv_secrets_t* s, const uint8_t* trust_pk,
                        const uint8_t* in, size_t inl, uint8_t** pt, size_t* ptl) {
    uint8_t flags;
    uint32_t iters;
    size_t wl, bl, base, expect;
    uint8_t pwkey[32], kek[32], fk[32], idh[32];
    qsc_buffer_t fkbuf, ptbuf;
    qsc_error_t e;
    const uint8_t* wrapped_ct;
    const uint8_t* body_ct;

    if (!s || !s->password || !s->ckey || !in || !pt || !ptl) return QSC_ERROR_INVALID_ARGUMENT;
    *pt = NULL;
    *ptl = 0;
    e = parse_layout(in, inl, &flags, &iters, &wl, &bl, &base);
    if (e != QSC_OK) return e;

    /* Mandatory layers must be present in the file. */
    if (!(flags & QSV_FLAG_PASSWORD) || !(flags & QSV_FLAG_CKEY)) return QSC_ERROR_MALFORMED_DATA;
    if (iters == 0 || iters > QSV_MAX_ITER) return QSC_ERROR_MALFORMED_DATA;

    /* Length must match the flags exactly. */
    expect = base + ((flags & QSV_FLAG_SIGNED) ? PK_BYTES + SIG_BYTES : 0);
    if (inl != expect) return QSC_ERROR_MALFORMED_DATA;

    /* Cheap checks first: which key file, which USB key, which cloud state. No KDF yet. */
    if (sha256_of(s->ckey, 32, idh) != QSC_OK) return QSC_ERROR_INVALID_ARGUMENT;
    if (!qsc_constant_time_equal(idh, in + OFF_CKEYID, 32)) return QSC_ERROR_INVALID_KEY;

    if (flags & QSV_FLAG_USB) {
        if (!s->usb) return QSC_ERROR_INVALID_KEY;
        if (sha256_of(s->usb, 32, idh) != QSC_OK) return QSC_ERROR_INVALID_ARGUMENT;
        if (!qsc_constant_time_equal(idh, in + OFF_USBID, 32)) return QSC_ERROR_INVALID_KEY;
    }

    if (flags & QSV_FLAG_CLOUD) {
#if QSV_CLOUD_ENABLED
        uint8_t commit[32];
        e = qsv_cloud_commitment(s->ckey, commit);
        if (e == QSC_OK) e = qsv_cloud_validate(commit);
        if (e != QSC_OK) return e;
#else
        return QSC_ERROR_UNSUPPORTED; /* file needs the cloud layer; this build has it disabled */
#endif
    }

    if (flags & QSV_FLAG_SIGNED) {
        const uint8_t* emb_pk = in + base;
        const uint8_t* sig = in + base + PK_BYTES;
        if (!trust_pk) return QSC_ERROR_INVALID_ARGUMENT;
        if (!qsc_constant_time_equal(emb_pk, trust_pk, PK_BYTES)) return QSC_ERROR_INVALID_SIGNATURE;
        e = qsc_mldsa65_verify(trust_pk, (qsc_slice_t){ in, (qs_u64)base },
                               (qsc_slice_t){ (const qs_u8*)SIGN_CTX, 10 },
                               (qsc_slice_t){ sig, SIG_BYTES });
        if (e != QSC_OK) return QSC_ERROR_INVALID_SIGNATURE;
    }

    /* Only now derive keys. */
    wrapped_ct = in + QSV_HEADER_BYTES + 4;
    body_ct = in + QSV_HEADER_BYTES + 4 + wl + 8;

    e = qsv_pbkdf2_sha256(s->password, s->password_len, in + OFF_SALTPW, 16, iters, pwkey);
    if (e == QSC_OK) e = derive_kek(pwkey, s->ckey, s->usb, flags, in + OFF_SALTKDF, kek);
    if (e != QSC_OK) goto cleanup;

    fkbuf.data = NULL; fkbuf.length = 0;
    e = open_under(kek, in, QSV_HEADER_BYTES, wrapped_ct, wl, &fkbuf);
    if (e != QSC_OK) { e = QSC_ERROR_AUTH_FAILED; goto cleanup; }
    if (fkbuf.length != 32) { e = QSC_ERROR_MALFORMED_DATA; qsc_buffer_free(&fkbuf); goto cleanup; }
    memcpy(fk, fkbuf.data, 32);
    qsc_buffer_free(&fkbuf);

    ptbuf.data = NULL; ptbuf.length = 0;
    e = open_under(fk, in, QSV_HEADER_BYTES, body_ct, bl, &ptbuf);
    if (e != QSC_OK) { e = QSC_ERROR_AUTH_FAILED; goto cleanup; }

    /* Copy into a malloc'd buffer so every output is released with qsv_free(). */
    *pt = (uint8_t*)malloc(ptbuf.length ? (size_t)ptbuf.length : 1);
    if (!*pt) { qsc_buffer_free(&ptbuf); e = QSC_ERROR_OOM; goto cleanup; }
    if (ptbuf.length) memcpy(*pt, ptbuf.data, (size_t)ptbuf.length);
    *ptl = (size_t)ptbuf.length;
    qsc_buffer_free(&ptbuf);
    e = QSC_OK;

cleanup:
    qsc_secure_zero(pwkey, sizeof pwkey);
    qsc_secure_zero(kek, sizeof kek);
    qsc_secure_zero(fk, sizeof fk);
    if (e != QSC_OK && *pt) { qsv_free(*pt, *ptl); *pt = NULL; *ptl = 0; }
    return e;
}

qsc_error_t qsv_keyfile_make(uint8_t out[QSV_KEYFILE_BYTES]) {
    if (!out) return QSC_ERROR_INVALID_ARGUMENT;
    memcpy(out, KEY_MAGIC, 8);
    return qsc_random_bytes(out + 8, 32);
}

qsc_error_t qsv_keyfile_parse(const uint8_t* in, size_t inl, uint8_t secret[32]) {
    if (!in || !secret) return QSC_ERROR_INVALID_ARGUMENT;
    if (inl != QSV_KEYFILE_BYTES || memcmp(in, KEY_MAGIC, 8) != 0) return QSC_ERROR_MALFORMED_DATA;
    memcpy(secret, in + 8, 32);
    return QSC_OK;
}
