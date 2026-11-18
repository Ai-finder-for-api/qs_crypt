/* Minimal dependency-free test harness. */
#ifndef QSC_TEST_COMMON_H
#define QSC_TEST_COMMON_H
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

extern int g_checks;
extern int g_failures;

#define CHECK(cond) do { \
    g_checks++; \
    if (!(cond)) { g_failures++; \
        fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } \
} while (0)

size_t hex_decode(const char* hex, uint8_t* out, size_t cap);
int    bytes_match_hex(const uint8_t* b, size_t n, const char* hex);

void run_kat_tests(void);
void run_kat2_tests(void);
void run_ed25519_tests(void);
void run_fhe_tests(void);
void run_rsa_tests(void);
void run_ecdsa_tests(void);
void run_mlkem_tests(void);
void run_mldsa_tests(void);
void run_api_tests(void);
void run_negative_tests(void);
void run_container_tests(void);
void run_property_tests(void);

#endif
