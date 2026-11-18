/* RSA tests: OAEP and PSS round trips, tamper and wrong-key rejection, key import/export,
 * size limits. Uses a 2048-bit key (keygen takes a few seconds). */
#include "test_common.h"
#include "qs_crypt/qs_crypt.h"
#include <string.h>
#include "../vectors/kat_pss.h"
#include "../vectors/kat_oaep.h"

static void kat_pss_run(void) {
    size_t count = sizeof kat_pss / sizeof kat_pss[0];
    int checked = 0;
    for (size_t i = 0; i < count; i++) {
        uint8_t n[512], e[8], msg[4096], sig[1024];
        size_t nl = hex_decode(kat_pss[i].n, n, sizeof n);
        size_t el = hex_decode(kat_pss[i].e, e, sizeof e);
        size_t ml = hex_decode(kat_pss[i].msg, msg, sizeof msg);
        size_t sl = hex_decode(kat_pss[i].sig, sig, sizeof sig);
        if (kat_pss[i].valid == 2) continue;
        qsc_rsa_public_t* pub = NULL;
        int ok = 0;
        if (qsc_rsa_public_create((qsc_slice_t){ n, nl }, (qsc_slice_t){ e, el }, &pub) == QSC_OK)
            ok = qsc_rsa_pss_verify(pub, (qsc_slice_t){ msg, ml }, (qsc_slice_t){ sig, sl }) == QSC_OK;
        if (kat_pss[i].valid == 1 && !ok) {
            g_failures++;
            fprintf(stderr, "  FAIL pss tc=%d should verify\n", kat_pss[i].tc);
        } else if (kat_pss[i].valid == 0 && ok) {
            g_failures++;
            fprintf(stderr, "  FAIL pss tc=%d should reject\n", kat_pss[i].tc);
        }
        qsc_rsa_public_destroy(pub);
        checked++;
    }
    CHECK(checked == 108);
}

static void kat_oaep_run(void) {
    size_t count = sizeof kat_oaep / sizeof kat_oaep[0];
    int checked = 0;
    for (size_t i = 0; i < count; i++) {
        uint8_t n[512], d[512], ct[512], msg[512], out[512];
        size_t nl = hex_decode(kat_oaep[i].n, n, sizeof n);
        size_t dl = hex_decode(kat_oaep[i].d, d, sizeof d);
        size_t cl = hex_decode(kat_oaep[i].ct, ct, sizeof ct);
        size_t ml = hex_decode(kat_oaep[i].msg, msg, sizeof msg);
        qsc_rsa_private_t* priv = NULL;
        int ok = 0;
        if (qsc_rsa_private_create((qsc_slice_t){ n, nl }, (qsc_slice_t){ d, dl }, &priv) == QSC_OK) {
            qsc_buffer_t o = { out, sizeof out };
            qsc_error_t e = qsc_rsa_oaep_decrypt(priv, (qsc_slice_t){ ct, cl }, &o);
            ok = (e == QSC_OK) && o.length == ml && (ml == 0 || memcmp(out, msg, ml) == 0);
        }
        if (kat_oaep[i].valid == 1 && !ok) {
            g_failures++;
            fprintf(stderr, "  FAIL oaep tc=%d should decrypt\n", kat_oaep[i].tc);
        } else if (kat_oaep[i].valid == 0 && ok) {
            g_failures++;
            fprintf(stderr, "  FAIL oaep tc=%d should fail\n", kat_oaep[i].tc);
        }
        qsc_rsa_private_destroy(priv);
        checked++;
    }
    CHECK(checked == 29);
}

static void rsa_oaep_roundtrips(const qsc_rsa_public_t* pub, const qsc_rsa_private_t* priv) {
    const qs_u64 k = qsc_rsa_public_modulus_bytes(pub);
    CHECK(k == 256);
    qs_u8 msg[190], ct[512], out[512];
    for (unsigned i = 0; i < sizeof msg; i++) msg[i] = (qs_u8)(i * 7 + 3);

    const qs_u64 lens[] = { 0, 1, 32, 190 };
    for (unsigned li = 0; li < sizeof lens / sizeof lens[0]; li++) {
        qsc_buffer_t c = { ct, sizeof ct };
        qsc_buffer_t o = { out, sizeof out };
        CHECK(qsc_rsa_oaep_encrypt(pub, (qsc_slice_t){ msg, lens[li] }, &c) == QSC_OK);
        CHECK(c.length == k);
        CHECK(qsc_rsa_oaep_decrypt(priv, (qsc_slice_t){ ct, c.length }, &o) == QSC_OK);
        CHECK(o.length == lens[li]);
        CHECK(lens[li] == 0 || memcmp(out, msg, (size_t)lens[li]) == 0);
    }

    /* oversize message */
    qsc_buffer_t c = { ct, sizeof ct };
    CHECK(qsc_rsa_oaep_encrypt(pub, (qsc_slice_t){ msg, 191 }, &c) == QSC_ERROR_INVALID_PARAMETERS);

    /* tampered ciphertext */
    qsc_buffer_t c2 = { ct, sizeof ct };
    CHECK(qsc_rsa_oaep_encrypt(pub, (qsc_slice_t){ msg, 16 }, &c2) == QSC_OK);
    ct[100] ^= 0x01;
    qsc_buffer_t o2 = { out, sizeof out };
    CHECK(qsc_rsa_oaep_decrypt(priv, (qsc_slice_t){ ct, c2.length }, &o2) == QSC_ERROR_DECRYPTION_FAILED);
    ct[100] ^= 0x01;

    /* short output buffer reports required size */
    qs_u8 tiny[4];
    qsc_buffer_t o3 = { tiny, sizeof tiny };
    CHECK(qsc_rsa_oaep_decrypt(priv, (qsc_slice_t){ ct, c2.length }, &o3) == QSC_ERROR_BUFFER_TOO_SMALL);
    CHECK(o3.length == 16);
}

static void rsa_wrong_key(const qsc_rsa_public_t* pub) {
    qsc_rsa_public_t* pub_unused = NULL;
    qsc_rsa_private_t* other = NULL;
    qs_u8 ct[512], out[512];
    qsc_buffer_t c = { ct, sizeof ct };
    CHECK(qsc_rsa_keygen(2048, &pub_unused, &other) == QSC_OK);
    CHECK(qsc_rsa_oaep_encrypt(pub, (qsc_slice_t){ (const qs_u8*)"hello", 5 }, &c) == QSC_OK);
    qsc_buffer_t o = { out, sizeof out };
    CHECK(qsc_rsa_oaep_decrypt(other, (qsc_slice_t){ ct, c.length }, &o) == QSC_ERROR_DECRYPTION_FAILED);
    qsc_rsa_public_destroy(pub_unused);
    qsc_rsa_private_destroy(other);
}

static void rsa_pss(const qsc_rsa_public_t* pub, const qsc_rsa_private_t* priv) {
    const char* m = "quantum suite signature test";
    qs_u8 sig[512];
    qsc_buffer_t s = { sig, sizeof sig };
    CHECK(qsc_rsa_pss_sign(priv, (qsc_slice_t){ (const qs_u8*)m, strlen(m) }, &s) == QSC_OK);
    CHECK(s.length == 256);
    CHECK(qsc_rsa_pss_verify(pub, (qsc_slice_t){ (const qs_u8*)m, strlen(m) },
                             (qsc_slice_t){ sig, s.length }) == QSC_OK);

    /* empty message */
    qsc_buffer_t s0 = { sig, sizeof sig };
    CHECK(qsc_rsa_pss_sign(priv, (qsc_slice_t){ NULL, 0 }, &s0) == QSC_OK);
    CHECK(qsc_rsa_pss_verify(pub, (qsc_slice_t){ NULL, 0 }, (qsc_slice_t){ sig, s0.length }) == QSC_OK);

    /* wrong message */
    CHECK(qsc_rsa_pss_verify(pub, (qsc_slice_t){ (const qs_u8*)"other", 5 },
                             (qsc_slice_t){ sig, s.length }) == QSC_ERROR_INVALID_SIGNATURE);

    /* flipped signature bit */
    sig[10] ^= 0x04;
    CHECK(qsc_rsa_pss_verify(pub, (qsc_slice_t){ (const qs_u8*)m, strlen(m) },
                             (qsc_slice_t){ sig, s.length }) == QSC_ERROR_INVALID_SIGNATURE);
    sig[10] ^= 0x04;

    /* wrong length */
    CHECK(qsc_rsa_pss_verify(pub, (qsc_slice_t){ (const qs_u8*)m, strlen(m) },
                             (qsc_slice_t){ sig, 255 }) == QSC_ERROR_INVALID_SIGNATURE);
}

static void rsa_import_export(const qsc_rsa_public_t* pub, const qsc_rsa_private_t* priv) {
    qs_u8 n[512];
    qsc_buffer_t nb = { n, sizeof n };
    qs_u32 e = 0;
    CHECK(qsc_rsa_public_get_modulus(pub, &nb) == QSC_OK);
    CHECK(nb.length == 256);
    CHECK(qsc_rsa_public_get_exponent(pub, &e) == QSC_OK);
    CHECK(e == 65537u);

    /* rebuild a public key from its components and verify a signature with it */
    qsc_rsa_public_t* pub2 = NULL;
    const qs_u8 e_bytes[3] = { 0x01, 0x00, 0x01 };
    CHECK(qsc_rsa_public_create((qsc_slice_t){ n, nb.length }, (qsc_slice_t){ e_bytes, 3 }, &pub2) == QSC_OK);
    if (pub2) {
        const char* m = "imported key";
        qs_u8 sig[512];
        qsc_buffer_t s = { sig, sizeof sig };
        CHECK(qsc_rsa_pss_sign(priv, (qsc_slice_t){ (const qs_u8*)m, strlen(m) }, &s) == QSC_OK);
        CHECK(qsc_rsa_pss_verify(pub2, (qsc_slice_t){ (const qs_u8*)m, strlen(m) },
                                 (qsc_slice_t){ sig, s.length }) == QSC_OK);
        qsc_rsa_public_destroy(pub2);
    }

    /* rejected key sizes and bad exponents */
    qsc_rsa_public_t* bad = NULL;
    qs_u8 small[100];
    memset(small, 0xA5, sizeof small);
    small[0] = 0x80;
    CHECK(qsc_rsa_public_create((qsc_slice_t){ small, sizeof small }, (qsc_slice_t){ e_bytes, 3 }, &bad)
          == QSC_ERROR_KEY_SIZE_MISMATCH);
    CHECK(bad == NULL);
    const qs_u8 even_e[1] = { 0x10 };
    CHECK(qsc_rsa_public_create((qsc_slice_t){ n, nb.length }, (qsc_slice_t){ even_e, 1 }, &bad)
          == QSC_ERROR_INVALID_KEY);
}

static void rsa_null_args(void) {
    qs_u8 buf[512];
    qsc_buffer_t b = { buf, sizeof buf };
    CHECK(qsc_rsa_oaep_encrypt(NULL, (qsc_slice_t){ buf, 1 }, &b) == QSC_ERROR_INVALID_ARGUMENT);
    CHECK(qsc_rsa_oaep_decrypt(NULL, (qsc_slice_t){ buf, 256 }, &b) == QSC_ERROR_INVALID_ARGUMENT);
    CHECK(qsc_rsa_pss_sign(NULL, (qsc_slice_t){ buf, 1 }, &b) == QSC_ERROR_INVALID_ARGUMENT);
    CHECK(qsc_rsa_pss_verify(NULL, (qsc_slice_t){ buf, 1 }, (qsc_slice_t){ buf, 256 })
          == QSC_ERROR_INVALID_ARGUMENT);
    CHECK(qsc_rsa_keygen(1000, NULL, NULL) != QSC_OK);
}

void run_rsa_tests(void) {
    kat_pss_run();
    kat_oaep_run();
    qsc_rsa_public_t* pub = NULL;
    qsc_rsa_private_t* priv = NULL;
    CHECK(qsc_rsa_keygen(2048, &pub, &priv) == QSC_OK && pub && priv);
    if (!pub || !priv) return;
    rsa_oaep_roundtrips(pub, priv);
    rsa_wrong_key(pub);
    rsa_pss(pub, priv);
    rsa_import_export(pub, priv);
    rsa_null_args();
    qsc_rsa_public_destroy(pub);
    qsc_rsa_private_destroy(priv);
}
