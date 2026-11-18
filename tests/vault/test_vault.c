/**
 * @file test_vault.c
 * @brief qsvault tests: PBKDF2 known answer, key files, every layer, tamper and wrong-factor
 *        rejection, signature trust, cloud-disabled behaviour, sealing the signing key.
 */
#include "qsv_core.h"
#include "qsv_cloud.h"
#include "qs_crypt/qs_crypt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;
#define CHECK(c) do { if (!(c)) { failures++; fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)

/* Header offsets (see qsv_core.h layout). */
#define OFF_FLAGS_T 4
#define OFF_ITER_T  8
#define ITER        1000u
static const char PW[] = "correct horse battery";
static const uint8_t MSG[] = "the quick brown fox jumps over the lazy dog";

static void secrets_for(qsv_secrets_t* s, const uint8_t* ckey, const uint8_t* usb) {
    memset(s, 0, sizeof *s);
    s->password = (const uint8_t*)PW;
    s->password_len = strlen(PW);
    s->ckey = ckey;
    s->usb = usb;
    s->iterations = ITER;
}

static void test_pbkdf2(void) {
    /* RFC 7914 section 11: PBKDF2-HMAC-SHA-256, P="passwd", S="salt", c=1, first 32 bytes. */
    static const uint8_t expect[32] = {
        0x55, 0xac, 0x04, 0x6e, 0x56, 0xe3, 0x08, 0x9f, 0xec, 0x16, 0x91, 0xc2, 0x25, 0x44, 0xb6, 0x05,
        0xf9, 0x41, 0x85, 0x21, 0x6d, 0xde, 0x04, 0x65, 0xe6, 0x8b, 0x9d, 0x57, 0xc2, 0x0d, 0xac, 0xbc
    };
    uint8_t out[32];
    CHECK(qsv_pbkdf2_sha256((const uint8_t*)"passwd", 6, (const uint8_t*)"salt", 4, 1, out) == QSC_OK);
    CHECK(memcmp(out, expect, 32) == 0);
}

static void test_keyfile(void) {
    uint8_t kf[QSV_KEYFILE_BYTES], sec[32];
    CHECK(qsv_keyfile_make(kf) == QSC_OK);
    CHECK(qsv_keyfile_parse(kf, sizeof kf, sec) == QSC_OK);
    CHECK(qsv_keyfile_parse(kf, sizeof kf - 1, sec) == QSC_ERROR_MALFORMED_DATA);
    kf[0] ^= 0xFF;
    CHECK(qsv_keyfile_parse(kf, sizeof kf, sec) == QSC_ERROR_MALFORMED_DATA);
}

static void test_roundtrip_base(void) {
    uint8_t kf[QSV_KEYFILE_BYTES], ckey[32], *ct = NULL, *pt = NULL;
    size_t ctl = 0, ptl = 0;
    qsv_secrets_t s;
    qsv_info_t info;
    CHECK(qsv_keyfile_make(kf) == QSC_OK);
    memcpy(ckey, kf + 8, 32);
    secrets_for(&s, ckey, NULL);

    CHECK(qsv_encrypt(&s, MSG, sizeof MSG, &ct, &ctl) == QSC_OK);
    CHECK(ct != NULL && ctl > sizeof MSG);
    CHECK(qsv_decrypt(&s, NULL, ct, ctl, &pt, &ptl) == QSC_OK);
    CHECK(ptl == sizeof MSG && memcmp(pt, MSG, sizeof MSG) == 0);
    if (pt) qsv_free(pt, ptl);

    CHECK(qsv_info(ct, ctl, &info) == QSC_OK);
    CHECK((info.flags & QSV_FLAG_PASSWORD) && (info.flags & QSV_FLAG_CKEY));
    CHECK(!(info.flags & QSV_FLAG_USB) && !(info.flags & QSV_FLAG_SIGNED) && !(info.flags & QSV_FLAG_CLOUD));
    CHECK(info.iterations == ITER);
    qsv_free(ct, ctl);
}

static void test_empty_plaintext(void) {
    uint8_t ckey[32] = { 9 }, *ct = NULL, *pt = NULL;
    size_t ctl = 0, ptl = 99;
    qsv_secrets_t s;
    secrets_for(&s, ckey, NULL);
    CHECK(qsv_encrypt(&s, NULL, 0, &ct, &ctl) == QSC_OK);
    CHECK(qsv_decrypt(&s, NULL, ct, ctl, &pt, &ptl) == QSC_OK);
    CHECK(ptl == 0);
    if (pt) qsv_free(pt, ptl);
    if (ct) qsv_free(ct, ctl);
}

static void test_usb_layer(void) {
    uint8_t ckey[32] = { 1 }, usb[32] = { 2 }, wrong_usb[32] = { 3 };
    uint8_t *ct = NULL, *pt = NULL;
    size_t ctl = 0, ptl = 0;
    qsv_secrets_t s;

    secrets_for(&s, ckey, usb);
    CHECK(qsv_encrypt(&s, MSG, sizeof MSG, &ct, &ctl) == QSC_OK);
    CHECK(qsv_decrypt(&s, NULL, ct, ctl, &pt, &ptl) == QSC_OK && ptl == sizeof MSG);
    if (pt) qsv_free(pt, ptl);

    /* USB key missing, or wrong USB key: rejected before any KDF work. */
    secrets_for(&s, ckey, NULL);
    CHECK(qsv_decrypt(&s, NULL, ct, ctl, &pt, &ptl) == QSC_ERROR_INVALID_KEY);
    secrets_for(&s, ckey, wrong_usb);
    CHECK(qsv_decrypt(&s, NULL, ct, ctl, &pt, &ptl) == QSC_ERROR_INVALID_KEY);
    qsv_free(ct, ctl);
}

static void test_factor_rejection(void) {
    uint8_t ckey[32] = { 4 }, other[32] = { 5 };
    uint8_t *ct = NULL, *pt = NULL;
    size_t ctl = 0, ptl = 0;
    qsv_secrets_t s;

    secrets_for(&s, ckey, NULL);
    CHECK(qsv_encrypt(&s, MSG, sizeof MSG, &ct, &ctl) == QSC_OK);

    /* wrong .qs.ckey */
    secrets_for(&s, other, NULL);
    CHECK(qsv_decrypt(&s, NULL, ct, ctl, &pt, &ptl) == QSC_ERROR_INVALID_KEY);

    /* wrong password, right key file */
    secrets_for(&s, ckey, NULL);
    s.password = (const uint8_t*)"wrong password!!";
    s.password_len = strlen("wrong password!!");
    CHECK(qsv_decrypt(&s, NULL, ct, ctl, &pt, &ptl) == QSC_ERROR_AUTH_FAILED);

    qsv_free(ct, ctl);
}

static void test_tamper(void) {
    uint8_t ckey[32] = { 6 }, *ct = NULL, *pt = NULL;
    size_t ctl = 0, ptl = 0;
    qsv_secrets_t s;

    secrets_for(&s, ckey, NULL);
    CHECK(qsv_encrypt(&s, MSG, sizeof MSG, &ct, &ctl) == QSC_OK);

    /* body byte flipped (unsigned file: body is the last section) */
    ct[ctl - 5] ^= 0x01;
    CHECK(qsv_decrypt(&s, NULL, ct, ctl, &pt, &ptl) == QSC_ERROR_AUTH_FAILED);
    ct[ctl - 5] ^= 0x01;

    /* header iteration count flipped: changes the KDF output and the AAD */
    ct[OFF_ITER_T + 3] ^= 0x01;
    CHECK(qsv_decrypt(&s, NULL, ct, ctl, &pt, &ptl) == QSC_ERROR_AUTH_FAILED);
    ct[OFF_ITER_T + 3] ^= 0x01;

    /* cloud flag set while the cloud layer is disabled: refused before any decryption */
    ct[OFF_FLAGS_T] |= QSV_FLAG_CLOUD;
    CHECK(qsv_decrypt(&s, NULL, ct, ctl, &pt, &ptl) == QSC_ERROR_UNSUPPORTED);
    ct[OFF_FLAGS_T] &= (uint8_t)~QSV_FLAG_CLOUD;

    /* unknown flag bit */
    ct[OFF_FLAGS_T] |= 0x80;
    CHECK(qsv_decrypt(&s, NULL, ct, ctl, &pt, &ptl) == QSC_ERROR_MALFORMED_DATA);
    ct[OFF_FLAGS_T] &= (uint8_t)~0x80;

    /* truncation */
    CHECK(qsv_decrypt(&s, NULL, ct, ctl - 1, &pt, &ptl) == QSC_ERROR_TRUNCATED);
    CHECK(qsv_decrypt(&s, NULL, ct, 20, &pt, &ptl) == QSC_ERROR_TRUNCATED);

    /* still valid after restoring every change */
    CHECK(qsv_decrypt(&s, NULL, ct, ctl, &pt, &ptl) == QSC_OK);
    if (pt) qsv_free(pt, ptl);
    qsv_free(ct, ctl);
}

static void test_short_password(void) {
    uint8_t ckey[32] = { 7 }, *ct = NULL;
    size_t ctl = 0;
    qsv_secrets_t s;
    secrets_for(&s, ckey, NULL);
    s.password = (const uint8_t*)"short";
    s.password_len = 5;
    CHECK(qsv_encrypt(&s, MSG, sizeof MSG, &ct, &ctl) == QSC_ERROR_WEAK_KEY);
}

static void test_signed_layer(void) {
    uint8_t ckey[32] = { 8 }, *ct = NULL, *pt = NULL;
    size_t ctl = 0, ptl = 0;
    uint8_t pk[1952], sk[4032], other_pk[1952], other_sk[4032];
    qsv_secrets_t s;

    CHECK(qsc_mldsa65_keygen(pk, sk) == QSC_OK);
    CHECK(qsc_mldsa65_keygen(other_pk, other_sk) == QSC_OK);

    secrets_for(&s, ckey, NULL);
    s.sign_sk = sk;
    s.sign_pk = pk;
    CHECK(qsv_encrypt(&s, MSG, sizeof MSG, &ct, &ctl) == QSC_OK);

    /* verifies against the trusted key */
    CHECK(qsv_decrypt(&s, pk, ct, ctl, &pt, &ptl) == QSC_OK && ptl == sizeof MSG);
    if (pt) qsv_free(pt, ptl);

    /* signed file with no trust key: refused */
    CHECK(qsv_decrypt(&s, NULL, ct, ctl, &pt, &ptl) == QSC_ERROR_INVALID_ARGUMENT);

    /* a different trusted key: refused */
    CHECK(qsv_decrypt(&s, other_pk, ct, ctl, &pt, &ptl) == QSC_ERROR_INVALID_SIGNATURE);

    /* wrapped-key section tampered (byte 130 sits inside it): the signature covers it */
    ct[130] ^= 0x01;
    CHECK(qsv_decrypt(&s, pk, ct, ctl, &pt, &ptl) == QSC_ERROR_INVALID_SIGNATURE);
    ct[130] ^= 0x01;

    /* signature bytes tampered */
    ct[ctl - 10] ^= 0x01;
    CHECK(qsv_decrypt(&s, pk, ct, ctl, &pt, &ptl) == QSC_ERROR_INVALID_SIGNATURE);
    ct[ctl - 10] ^= 0x01;

    /* signed flag cleared: the layout no longer matches the flags, refused */
    ct[OFF_FLAGS_T] &= (uint8_t)~QSV_FLAG_SIGNED;
    CHECK(qsv_decrypt(&s, pk, ct, ctl, &pt, &ptl) == QSC_ERROR_MALFORMED_DATA);
    ct[OFF_FLAGS_T] |= QSV_FLAG_SIGNED;

    CHECK(qsv_decrypt(&s, pk, ct, ctl, &pt, &ptl) == QSC_OK);
    if (pt) qsv_free(pt, ptl);
    qsv_free(ct, ctl);
}

static void test_all_layers(void) {
    uint8_t ckey[32] = { 10 }, usb[32] = { 11 }, pk[1952], sk[4032], *ct = NULL, *pt = NULL;
    size_t ctl = 0, ptl = 0;
    qsv_secrets_t s;
    qsv_info_t info;

    CHECK(qsc_mldsa65_keygen(pk, sk) == QSC_OK);
    secrets_for(&s, ckey, usb);
    s.sign_sk = sk;
    s.sign_pk = pk;
    CHECK(qsv_encrypt(&s, MSG, sizeof MSG, &ct, &ctl) == QSC_OK);
    CHECK(qsv_info(ct, ctl, &info) == QSC_OK);
    CHECK(info.flags == (QSV_FLAG_PASSWORD | QSV_FLAG_CKEY | QSV_FLAG_USB | QSV_FLAG_SIGNED));
    CHECK(qsv_decrypt(&s, pk, ct, ctl, &pt, &ptl) == QSC_OK && ptl == sizeof MSG);
    if (pt) qsv_free(pt, ptl);
    qsv_free(ct, ctl);
}

static void test_sealed_signing_key(void) {
    /* Mirrors keygen-sign then encrypt --sign: the secret key is sealed with the same factors. */
    uint8_t ckey[32] = { 12 }, usb[32] = { 13 }, pk[1952], sk[4032];
    uint8_t *sealed = NULL, *plain = NULL;
    size_t sealed_len = 0, plain_len = 0;
    qsv_secrets_t s;

    CHECK(qsc_mldsa65_keygen(pk, sk) == QSC_OK);
    secrets_for(&s, ckey, usb);
    CHECK(qsv_encrypt(&s, sk, sizeof sk, &sealed, &sealed_len) == QSC_OK);
    CHECK(qsv_decrypt(&s, NULL, sealed, sealed_len, &plain, &plain_len) == QSC_OK);
    CHECK(plain_len == sizeof sk && memcmp(plain, sk, sizeof sk) == 0);
    if (plain) qsv_free(plain, plain_len);
    qsv_free(sealed, sealed_len);
}

static void test_cloud_disabled(void) {
    uint8_t c[32] = { 0 };
    CHECK(qsv_cloud_register(c) == QSC_ERROR_UNSUPPORTED);
    CHECK(qsv_cloud_validate(c) == QSC_ERROR_UNSUPPORTED);
}

int main(void) {
    if (qsc_init() != QSC_OK) { fprintf(stderr, "init failed\n"); return 2; }
    test_pbkdf2();
    test_keyfile();
    test_roundtrip_base();
    test_empty_plaintext();
    test_usb_layer();
    test_factor_rejection();
    test_tamper();
    test_short_password();
    test_signed_layer();
    test_all_layers();
    test_sealed_signing_key();
    test_cloud_disabled();
    if (failures) {
        fprintf(stderr, "qsvault tests: %d failures\n", failures);
        return 1;
    }
    printf("qsvault tests: all passed\n");
    return 0;
}
