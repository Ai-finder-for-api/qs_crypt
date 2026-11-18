/* Minimal use of the public API: generate a key, seal, open, and reject tampering. */
#include "qs_crypt/qs_crypt.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    if (qsc_init() != QSC_OK) { fprintf(stderr, "entropy unavailable\n"); return 1; }

    qsc_key_t* key = NULL;
    if (qsc_key_generate(QSC_ALG_CHACHA20_POLY1305, &key) != QSC_OK) return 1;

    const char* msg = "attack at dawn";
    qsc_slice_t aad = { (const qs_u8*)"transfer-v1", 11 };
    qsc_buffer_t box = { NULL, 0 }, out = { NULL, 0 };

    if (qsc_seal(key, aad, (qsc_slice_t){ (const qs_u8*)msg, strlen(msg) }, &box) != QSC_OK) return 1;
    if (qsc_open(key, aad, (qsc_slice_t){ box.data, box.length }, &out) != QSC_OK) return 1;
    printf("opened: %.*s\n", (int)out.length, (const char*)out.data);
    qsc_buffer_free(&out);          /* qsc_open requires an unset output buffer */

    box.data[box.length - 1] ^= 1;   /* tamper */
    qsc_error_t e = qsc_open(key, aad, (qsc_slice_t){ box.data, box.length }, &out);
    printf("tampered open rejected: %s\n", e == QSC_ERROR_AUTH_FAILED ? "yes" : "NO");

    qsc_buffer_free(&box);
    qsc_buffer_free(&out);
    qsc_key_destroy(key);
    qsc_shutdown();
    return e == QSC_ERROR_AUTH_FAILED ? 0 : 1;
}
