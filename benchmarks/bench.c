/* Reproducible throughput/latency measurements. Reports what it measures; no tuning
 * for a particular result. Run: make bench */
#define _POSIX_C_SOURCE 199309L
#include "qs_crypt/qs_crypt.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double now_s(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

#define MB (1024.0 * 1024.0)

int main(void) {
    const size_t N = 1 << 20;     /* 1 MiB payload */
    const int REPS = 64;
    qs_u8* buf = malloc(N), *ct = malloc(N), *pt = malloc(N);
    qsc_key_t* key = NULL;
    qsc_digest_t d;
    qsc_tag_t tag;
    uint8_t nonce[12] = {0};
    double t0, t1;

    if (!buf || !ct || !pt || qsc_init() != QSC_OK) return 1;
    qsc_random_bytes(buf, N);
    qsc_key_generate(QSC_ALG_CHACHA20_POLY1305, &key);
    qsc_buffer_t kb = { NULL, 0 };
    qsc_key_export(key, &kb);

    printf("qs_crypt benchmark (%d x 1 MiB, -O2, single thread)\n", REPS);

    t0 = now_s();
    for (int r = 0; r < REPS; r++) qsc_hash(QSC_ALG_SHA2_256, (qsc_slice_t){ buf, N }, &d);
    t1 = now_s();
    printf("  SHA-256 hash          : %8.1f MiB/s\n", REPS * (N / MB) / (t1 - t0));

    t0 = now_s();
    for (int r = 0; r < REPS; r++) qsc_mac(QSC_ALG_HMAC_SHA2_256, (qsc_slice_t){ kb.data, 32 }, (qsc_slice_t){ buf, N }, &tag);
    t1 = now_s();
    printf("  HMAC-SHA-256          : %8.1f MiB/s\n", REPS * (N / MB) / (t1 - t0));

    t0 = now_s();
    for (int r = 0; r < REPS; r++) qsc_chacha20_xor((qsc_slice_t){ kb.data, 32 }, (qsc_slice_t){ nonce, 12 }, 0, (qsc_slice_t){ buf, N }, ct);
    t1 = now_s();
    printf("  ChaCha20 (no auth)    : %8.1f MiB/s\n", REPS * (N / MB) / (t1 - t0));

    t0 = now_s();
    for (int r = 0; r < REPS; r++) qsc_aead_encrypt(QSC_ALG_CHACHA20_POLY1305, (qsc_slice_t){ kb.data, 32 }, (qsc_slice_t){ nonce, 12 }, (qsc_slice_t){ NULL, 0 }, (qsc_slice_t){ buf, N }, ct, &tag);
    t1 = now_s();
    printf("  ChaCha20-Poly1305 enc : %8.1f MiB/s\n", REPS * (N / MB) / (t1 - t0));

    t0 = now_s();
    for (int r = 0; r < REPS; r++) qsc_aead_decrypt(QSC_ALG_CHACHA20_POLY1305, (qsc_slice_t){ kb.data, 32 }, (qsc_slice_t){ nonce, 12 }, (qsc_slice_t){ NULL, 0 }, (qsc_slice_t){ ct, N }, (qsc_slice_t){ tag.data, 16 }, pt);
    t1 = now_s();
    printf("  ChaCha20-Poly1305 dec : %8.1f MiB/s\n", REPS * (N / MB) / (t1 - t0));

    t0 = now_s();
    for (int r = 0; r < 10000; r++) { qsc_key_t* k = NULL; qsc_key_generate(QSC_ALG_CHACHA20_POLY1305, &k); qsc_key_destroy(k); }
    t1 = now_s();
    printf("  key generate          : %8.2f us/op\n", (t1 - t0) / 10000 * 1e6);

    t0 = now_s();
    for (int r = 0; r < 10000; r++) { qsc_buffer_t c = {NULL,0}; qsc_seal(key, (qsc_slice_t){NULL,0}, (qsc_slice_t){ buf, 1024 }, &c); qsc_buffer_free(&c); }
    t1 = now_s();
    printf("  seal 1 KiB            : %8.2f us/op\n", (t1 - t0) / 10000 * 1e6);

    t0 = now_s();
    for (int r = 0; r < 10000; r++) { qsc_buffer_t okm = {NULL, 32}; qsc_derive_key(QSC_ALG_HKDF_SHA2_256, (qsc_slice_t){NULL,0}, (qsc_slice_t){ kb.data, 32 }, (qsc_slice_t){ (const qs_u8*)"bench", 5 }, &okm); qsc_buffer_free(&okm); }
    t1 = now_s();
    printf("  HKDF derive (32 B)    : %8.2f us/op\n", (t1 - t0) / 10000 * 1e6);

    qsc_buffer_free(&kb);
    qsc_key_destroy(key);
    free(buf); free(ct); free(pt);
    qsc_shutdown();
    return 0;
}
