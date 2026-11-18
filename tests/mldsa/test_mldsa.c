/* ML-DSA-65 tests: Wycheproof verify known-answer vectors, sign/verify round trips, tamper and
 * context rejection, length checks, seed determinism. */
#include "test_common.h"
#include "qs_crypt/qs_crypt.h"
#include "../vectors/kat_mldsa.h"
#include <string.h>

static void kat_mldsa_run(void) {
    size_t count = sizeof kat_mldsa / sizeof kat_mldsa[0];
    int checked = 0;
    for (size_t i = 0; i < count; i++) {
        uint8_t pk[QSC_MLDSA65_PK_BYTES];
        uint8_t msg[256];
        uint8_t ctx[256];
        uint8_t sig[4096];
        char sighex[7000];
        int ok = 0;

        /* A public key whose hex length is not 2 * 1952 is malformed and must be rejected.
         * Check before decoding: hex_decode caps at the buffer size and would silently truncate. */
        if (strlen(kat_mldsa[i].pk) != 2 * QSC_MLDSA65_PK_BYTES) {
            if (kat_mldsa[i].valid != 0) {
                g_failures++;
                fprintf(stderr, "  FAIL mldsa tc=%d malformed pk marked valid\n", kat_mldsa[i].tc);
            }
            checked++;
            continue;
        }

        hex_decode(kat_mldsa[i].pk, pk, sizeof pk);
        size_t ml = hex_decode(kat_mldsa[i].msg, msg, sizeof msg);
        size_t cl = hex_decode(kat_mldsa[i].ctx, ctx, sizeof ctx);
        sighex[0] = '\0';
        strcat(sighex, kat_mldsa[i].s0);
        strcat(sighex, kat_mldsa[i].s1);
        strcat(sighex, kat_mldsa[i].s2);
        size_t sl = hex_decode(sighex, sig, sizeof sig);

        qsc_error_t e = qsc_mldsa65_verify(pk, (qsc_slice_t){ msg, ml }, (qsc_slice_t){ ctx, cl },
                                           (qsc_slice_t){ sig, sl });
        ok = (e == QSC_OK);
        if (kat_mldsa[i].valid == 1 && !ok) {
            g_failures++;
            fprintf(stderr, "  FAIL mldsa tc=%d should verify\n", kat_mldsa[i].tc);
        } else if (kat_mldsa[i].valid == 0 && ok) {
            g_failures++;
            fprintf(stderr, "  FAIL mldsa tc=%d should reject\n", kat_mldsa[i].tc);
        }
        checked++;
    }
    CHECK(checked == 210);
}


static void mldsa_roundtrip(void) {
    uint8_t pk[QSC_MLDSA65_PK_BYTES], sk[QSC_MLDSA65_SK_BYTES], sig[QSC_MLDSA65_SIG_BYTES];
    CHECK(qsc_mldsa65_keygen(pk, sk) == QSC_OK);

    const char* m = "quantum suite ml-dsa test";
    const char* c = "ctx";
    size_t ml = strlen(m), cl = strlen(c);

    /* hedged sign, then verify */
    CHECK(qsc_mldsa65_sign(sk, (qsc_slice_t){ (const qs_u8*)m, ml }, (qsc_slice_t){ (const qs_u8*)c, cl }, sig) == QSC_OK);
    CHECK(qsc_mldsa65_verify(pk, (qsc_slice_t){ (const qs_u8*)m, ml }, (qsc_slice_t){ (const qs_u8*)c, cl },
                             (qsc_slice_t){ sig, QSC_MLDSA65_SIG_BYTES }) == QSC_OK);

    /* deterministic sign is reproducible */
    uint8_t s1[QSC_MLDSA65_SIG_BYTES], s2[QSC_MLDSA65_SIG_BYTES];
    CHECK(qsc_mldsa65_sign_deterministic(sk, (qsc_slice_t){ (const qs_u8*)m, ml }, (qsc_slice_t){ NULL, 0 }, s1) == QSC_OK);
    CHECK(qsc_mldsa65_sign_deterministic(sk, (qsc_slice_t){ (const qs_u8*)m, ml }, (qsc_slice_t){ NULL, 0 }, s2) == QSC_OK);
    CHECK(memcmp(s1, s2, QSC_MLDSA65_SIG_BYTES) == 0);
    CHECK(qsc_mldsa65_verify(pk, (qsc_slice_t){ (const qs_u8*)m, ml }, (qsc_slice_t){ NULL, 0 },
                             (qsc_slice_t){ s1, QSC_MLDSA65_SIG_BYTES }) == QSC_OK);

    /* wrong message, wrong context, tampered signature, wrong length */
    CHECK(qsc_mldsa65_verify(pk, (qsc_slice_t){ (const qs_u8*)"other", 5 }, (qsc_slice_t){ NULL, 0 },
                             (qsc_slice_t){ s1, QSC_MLDSA65_SIG_BYTES }) == QSC_ERROR_INVALID_SIGNATURE);
    CHECK(qsc_mldsa65_verify(pk, (qsc_slice_t){ (const qs_u8*)m, ml }, (qsc_slice_t){ (const qs_u8*)"x", 1 },
                             (qsc_slice_t){ s1, QSC_MLDSA65_SIG_BYTES }) == QSC_ERROR_INVALID_SIGNATURE);
    s1[100] ^= 0x01;
    CHECK(qsc_mldsa65_verify(pk, (qsc_slice_t){ (const qs_u8*)m, ml }, (qsc_slice_t){ NULL, 0 },
                             (qsc_slice_t){ s1, QSC_MLDSA65_SIG_BYTES }) == QSC_ERROR_INVALID_SIGNATURE);
    s1[100] ^= 0x01;
    CHECK(qsc_mldsa65_verify(pk, (qsc_slice_t){ (const qs_u8*)m, ml }, (qsc_slice_t){ NULL, 0 },
                             (qsc_slice_t){ s1, QSC_MLDSA65_SIG_BYTES - 1 }) == QSC_ERROR_INVALID_SIGNATURE);

    /* context longer than 255 bytes is rejected at sign time */
    uint8_t longctx[256];
    memset(longctx, 'a', sizeof longctx);
    CHECK(qsc_mldsa65_sign(sk, (qsc_slice_t){ (const qs_u8*)m, ml }, (qsc_slice_t){ longctx, 256 }, sig)
          == QSC_ERROR_INVALID_PARAMETERS);

    /* seed determinism */
    uint8_t xi[32] = { 7 };
    uint8_t pa[QSC_MLDSA65_PK_BYTES], pb[QSC_MLDSA65_PK_BYTES];
    uint8_t ska[QSC_MLDSA65_SK_BYTES], skb[QSC_MLDSA65_SK_BYTES];
    CHECK(qsc_mldsa65_keygen_seed(xi, pa, ska) == QSC_OK);
    CHECK(qsc_mldsa65_keygen_seed(xi, pb, skb) == QSC_OK);
    CHECK(memcmp(pa, pb, sizeof pa) == 0);
    CHECK(memcmp(ska, skb, sizeof ska) == 0);

    CHECK(qsc_mldsa65_sign(NULL, (qsc_slice_t){ (const qs_u8*)m, ml }, (qsc_slice_t){ NULL, 0 }, sig)
          == QSC_ERROR_INVALID_ARGUMENT);
}

void run_mldsa_tests(void) {
    kat_mldsa_run();
    mldsa_roundtrip();
}
