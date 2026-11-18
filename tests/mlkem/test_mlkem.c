/* ML-KEM-768 tests: Wycheproof known-answer vectors plus round trips and implicit rejection. */
#include "test_common.h"
#include "qs_crypt/qs_crypt.h"
#include "../vectors/kat_mlkem.h"
#include <string.h>

static void kat_mlkem_run(void) {
    size_t count = sizeof kat_mlkem / sizeof kat_mlkem[0];
    int checked = 0;
    for (size_t i = 0; i < count; i++) {
        uint8_t seed[64], ek_exp[1184], c[1088], K_exp[32];
        uint8_t ek[1184], dk[2400], K[32];
        size_t sl = hex_decode(kat_mlkem[i].seed, seed, sizeof seed);
        size_t el = hex_decode(kat_mlkem[i].ek, ek_exp, sizeof ek_exp);
        size_t cl = hex_decode(kat_mlkem[i].c, c, sizeof c);
        size_t kl = hex_decode(kat_mlkem[i].K, K_exp, sizeof K_exp);
        if (sl != 64 || el != 1184 || cl != 1088 || kl != 32) {
            /* malformed-length input: correct behaviour is rejection */
            if (kat_mlkem[i].valid == 1) {
                g_failures++;
                fprintf(stderr, "  FAIL mlkem tc=%d valid but wrong length\n", kat_mlkem[i].tc);
            }
            checked++;
            continue;
        }
        qsc_error_t e1 = qsc_mlkem768_keygen_seed(seed, ek, dk);
        qsc_error_t e2 = qsc_mlkem768_decaps(dk, c, K);
        int eq_ek = (e1 == QSC_OK) && memcmp(ek, ek_exp, 1184) == 0;
        int eq_K  = (e2 == QSC_OK) && memcmp(K, K_exp, 32) == 0;
        if (kat_mlkem[i].valid == 1) {
            if (!(eq_ek && eq_K)) {
                g_failures++;
                fprintf(stderr, "  FAIL mlkem tc=%d (ek %d, K %d)\n", kat_mlkem[i].tc, eq_ek, eq_K);
            }
        } else {
            if (eq_ek && eq_K) {
                g_failures++;
                fprintf(stderr, "  FAIL mlkem tc=%d should not match\n", kat_mlkem[i].tc);
            }
        }
        checked++;
    }
    CHECK(checked == 201);
}

static void mlkem_roundtrip(void) {
    uint8_t ek[1184], dk[2400], ct[1088], K1[32], K2[32], K3[32];
    CHECK(qsc_mlkem768_keygen(ek, dk) == QSC_OK);
    CHECK(qsc_mlkem768_encaps(ek, ct, K1) == QSC_OK);
    CHECK(qsc_mlkem768_decaps(dk, ct, K2) == QSC_OK);
    CHECK(memcmp(K1, K2, 32) == 0);

    /* implicit rejection: a tampered ciphertext decapsulates to a different key, no error */
    ct[7] ^= 0x10;
    CHECK(qsc_mlkem768_decaps(dk, ct, K3) == QSC_OK);
    CHECK(memcmp(K1, K3, 32) != 0);
    ct[7] ^= 0x10;

    /* a key with a coefficient >= q fails the encapsulation modulus check */
    uint8_t bad_ek[1184];
    memcpy(bad_ek, ek, sizeof bad_ek);
    bad_ek[0] = 0xFF;
    bad_ek[1] = 0xFF;
    CHECK(qsc_mlkem768_encaps(bad_ek, ct, K1) == QSC_ERROR_INVALID_KEY);

    CHECK(qsc_mlkem768_encaps(NULL, ct, K1) == QSC_ERROR_INVALID_ARGUMENT);
    CHECK(qsc_mlkem768_decaps(NULL, ct, K1) == QSC_ERROR_INVALID_ARGUMENT);
}

void run_mlkem_tests(void) {
    kat_mlkem_run();
    mlkem_roundtrip();
}
