/* ECDSA P-256 tests: Wycheproof known-answer vectors, public-key derivation with a known point,
 * sign/verify round trips, tamper and bad-key rejection. */
#include "test_common.h"
#include "qs_crypt/qs_crypt.h"
#include "../vectors/kat_ecdsa.h"
#include <string.h>

/* Decodes a DER ECDSA signature into raw r || s (32 + 32 bytes). Returns 0 on any format error. */
static int der_to_raw(const uint8_t* d, size_t n, uint8_t raw[64]) {
    size_t p = 0;
    if (n < 8 || d[p++] != 0x30) return 0;
    size_t len = d[p++];
    if ((len & 0x80) || len != n - 2) return 0;
    for (int i = 0; i < 2; i++) {
        if (p >= n || d[p++] != 0x02) return 0;
        if (p >= n) return 0;
        size_t l = d[p++];
        if ((l & 0x80) || p + l > n) return 0;
        const uint8_t* v = d + p;
        p += l;
        if (l == 0) return 0;
        if (v[0] & 0x80) return 0;                    /* negative INTEGER */
        if (l > 1 && v[0] == 0 && !(v[1] & 0x80)) return 0;   /* non-minimal INTEGER */
        if (l > 33) return 0;
        while (l > 1 && *v == 0) { v++; l--; }
        if (l > 32) return 0;
        memset(raw + 32 * i, 0, 32);
        memcpy(raw + 32 * i + 32 - l, v, l);
    }
    return p == n;
}

static void kat_ecdsa_run(void) {
    size_t count = sizeof kat_ecdsa / sizeof kat_ecdsa[0];
    int checked = 0;
    for (size_t i = 0; i < count; i++) {
        uint8_t pub[65], msg[4096], der[4096], sig[64];
        size_t pl = hex_decode(kat_ecdsa[i].pub, pub, sizeof pub);
        size_t ml = hex_decode(kat_ecdsa[i].msg, msg, sizeof msg);
        size_t dl = hex_decode(kat_ecdsa[i].der, der, sizeof der);
        if (pl != 65) { g_failures++; fprintf(stderr, "  bad kat pub tc=%d\n", kat_ecdsa[i].tc); continue; }
        if (kat_ecdsa[i].valid == 2) continue;
        int parsed = der_to_raw(der, dl, sig);
        qsc_error_t e = parsed
            ? qsc_ecdsa_p256_verify(pub, (qsc_slice_t){ msg, ml }, sig)
            : QSC_ERROR_INVALID_SIGNATURE;
        int ok = (e == QSC_OK);
        if (kat_ecdsa[i].valid == 1 && !ok) {
            g_failures++;
            fprintf(stderr, "  FAIL ecdsa tc=%d should verify\n", kat_ecdsa[i].tc);
        } else if (kat_ecdsa[i].valid == 0 && ok) {
            g_failures++;
            fprintf(stderr, "  FAIL ecdsa tc=%d should reject\n", kat_ecdsa[i].tc);
        }
        checked++;
    }
    CHECK(checked > 400);
}

static void ecdsa_known_point(void) {
    /* d = n - 1 gives Q = -G, so the x coordinate equals Gx. */
    static const uint8_t n_minus_1[32] = {
        0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xbc,0xe6,0xfa,0xad,0xa7,0x17,0x9e,0x84,0xf3,0xb9,0xca,0xc2,0xfc,0x63,0x25,0x50 };
    uint8_t pub[65], gx[32];
    CHECK(qsc_ecdsa_p256_public_from_private(n_minus_1, pub) == QSC_OK);
    hex_decode("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", gx, 32);
    CHECK(pub[0] == 0x04);
    CHECK(memcmp(pub + 1, gx, 32) == 0);
}

static void ecdsa_roundtrip(void) {
    uint8_t priv[32], pub[65], pub2[65], sig[64];
    CHECK(qsc_ecdsa_p256_keygen(priv, pub) == QSC_OK);
    CHECK(qsc_ecdsa_p256_public_from_private(priv, pub2) == QSC_OK);
    CHECK(memcmp(pub, pub2, 65) == 0);

    const char* m = "quantum suite ecdsa test message";
    size_t ml = strlen(m);
    CHECK(qsc_ecdsa_p256_sign(priv, (qsc_slice_t){ (const qs_u8*)m, ml }, sig) == QSC_OK);
    CHECK(qsc_ecdsa_p256_verify(pub, (qsc_slice_t){ (const qs_u8*)m, ml }, sig) == QSC_OK);

    /* empty message */
    CHECK(qsc_ecdsa_p256_sign(priv, (qsc_slice_t){ NULL, 0 }, sig) == QSC_OK);
    CHECK(qsc_ecdsa_p256_verify(pub, (qsc_slice_t){ NULL, 0 }, sig) == QSC_OK);

    /* tampered message */
    CHECK(qsc_ecdsa_p256_verify(pub, (qsc_slice_t){ (const qs_u8*)"other", 5 }, sig)
          == QSC_ERROR_INVALID_SIGNATURE);

    /* tampered signature */
    CHECK(qsc_ecdsa_p256_sign(priv, (qsc_slice_t){ (const qs_u8*)m, ml }, sig) == QSC_OK);
    sig[40] ^= 0x01;
    CHECK(qsc_ecdsa_p256_verify(pub, (qsc_slice_t){ (const qs_u8*)m, ml }, sig)
          == QSC_ERROR_INVALID_SIGNATURE);
    sig[40] ^= 0x01;

    /* zero r and out-of-range s are rejected */
    uint8_t zero_r[64];
    memcpy(zero_r, sig, 64);
    memset(zero_r, 0, 32);
    CHECK(qsc_ecdsa_p256_verify(pub, (qsc_slice_t){ (const qs_u8*)m, ml }, zero_r)
          == QSC_ERROR_INVALID_SIGNATURE);
    uint8_t big_s[64];
    memcpy(big_s, sig, 64);
    memset(big_s + 32, 0xff, 32);
    CHECK(qsc_ecdsa_p256_verify(pub, (qsc_slice_t){ (const qs_u8*)m, ml }, big_s)
          == QSC_ERROR_INVALID_SIGNATURE);

    /* off-curve public key */
    uint8_t bad[65];
    memcpy(bad, pub, 65);
    bad[64] ^= 0x01;
    CHECK(qsc_ecdsa_p256_verify(bad, (qsc_slice_t){ (const qs_u8*)m, ml }, sig) == QSC_ERROR_INVALID_KEY);

    /* zero private key rejected */
    uint8_t zero[32] = { 0 };
    CHECK(qsc_ecdsa_p256_sign(zero, (qsc_slice_t){ (const qs_u8*)m, ml }, sig) == QSC_ERROR_INVALID_KEY);
}

void run_ecdsa_tests(void) {
    ecdsa_known_point();
    kat_ecdsa_run();
    ecdsa_roundtrip();
}
