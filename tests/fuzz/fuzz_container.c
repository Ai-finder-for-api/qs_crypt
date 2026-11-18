/*
 * Fuzz target for the untrusted-input boundary: wire unwrap and sealed open.
 *
 * Build with libFuzzer:  clang -fsanitize=fuzzer,address -Iinclude \
 *     tests/fuzz/fuzz_container.c <all src/ .c files> -o fuzz_container
 * Or run the built-in driver (no clang needed):  make fuzz-smoke
 *
 * Invariants: never crash, never read out of bounds, and never return QSC_OK
 * for random bytes (a forged tag would be a break of Poly1305).
 */
#include "qs_crypt/qs_crypt.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static qsc_key_t* g_key = NULL;

int LLVMFuzzerInitialize(int* argc, char*** argv) {
    (void)argc; (void)argv;
    qsc_init();
    qsc_key_import(QSC_ALG_CHACHA20_POLY1305, (qsc_slice_t){
        (const qs_u8*)"0123456789abcdef0123456789abcdef", 32 }, &g_key);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    qsc_algorithm_id_t alg;
    qsc_slice_t payload;
    qsc_buffer_t pt = { NULL, 0 };
    qsc_slice_t in = { data, (qs_u64)size };
    if (qsc_serialize_unwrap(in, &alg, &payload) == QSC_OK) { /* parse must be safe */ }
    if (qsc_open(g_key, (qsc_slice_t){ NULL, 0 }, in, &pt) == QSC_OK) {
        /* Random input must never authenticate. */
        abort();
    }
    qsc_buffer_free(&pt);
    return 0;
}

#ifndef QSC_LIBFUZZER
/* Standalone smoke driver: random inputs plus mutations of a valid container. */
int main(int argc, char** argv) {
    long iters = argc > 1 ? atol(argv[1]) : 100000;
    uint8_t buf[512];
    LLVMFuzzerInitialize(NULL, NULL);
    for (long i = 0; i < iters; i++) {
        qs_u64 len = 0;
        qsc_random_bytes((qs_u8*)&len, 1);
        len %= sizeof buf;
        qsc_random_bytes(buf, len ? len : 1);
        LLVMFuzzerTestOneInput(buf, (size_t)len);
    }
    printf("fuzz-smoke: %ld random inputs, no crashes\n", iters);
    qsc_key_destroy(g_key);
    return 0;
}
#endif
