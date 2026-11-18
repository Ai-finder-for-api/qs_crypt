#include "test_common.h"
#include "qs_crypt/qs_crypt.h"
#include "../src/core/qs_crypt_internal.h"
#include <string.h>

int g_checks = 0;
int g_failures = 0;

size_t hex_decode(const char* hex, uint8_t* out, size_t cap) {
    size_t n = 0;
    while (hex[0] && hex[1]) {
        unsigned v;
        if (sscanf(hex, "%2x", &v) != 1) break;
        if (n >= cap) break;
        out[n++] = (uint8_t)v;
        hex += 2;
    }
    return n;
}

int bytes_match_hex(const uint8_t* b, size_t n, const char* hex) {
    uint8_t exp[1024];
    size_t m = hex_decode(hex, exp, sizeof exp);
    return m == n && memcmp(b, exp, n) == 0;
}

int main(void) {
    if (qsc_init() != QSC_OK) { fprintf(stderr, "qsc_init failed\n"); return 2; }
    run_kat_tests();
    run_kat2_tests();
    run_ed25519_tests();
    run_fhe_tests();
    run_rsa_tests();
    run_ecdsa_tests();
    run_mlkem_tests();
    run_mldsa_tests();
    run_api_tests();
    run_negative_tests();
    run_container_tests();
    run_property_tests();
    {
        size_t live = 0, bytes = 0, bad = 0;
        qsc_alloc_stats(&live, &bytes, &bad);
        if (live != 0 || bad != 0) {
            g_failures++;
            fprintf(stderr, "  FAIL allocator: %zu live blocks (%zu bytes), %zu invalid frees\n",
                    live, bytes, bad);
        }
        g_checks++;
    }
    qsc_shutdown();
    printf("qs_crypt tests: %d checks, %d failures\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
