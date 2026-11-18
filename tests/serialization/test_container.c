/* Wire-format and sealed-container tests. */
#include "test_common.h"
#include "qs_crypt/qs_crypt.h"
#include <string.h>
#include <stdlib.h>

static void wire_roundtrip_and_rejections(void) {
    const uint8_t payload[5] = { 'q','s','c','!', 0 };
    qsc_buffer_t w = { NULL, 0 };
    CHECK(qsc_serialize_wrap(QSC_ALG_CHACHA20_POLY1305, (qsc_slice_t){ payload, 5 }, &w) == QSC_OK);
    CHECK(w.length == QSC_WIRE_HEADER_SIZE + 5);

    qsc_algorithm_id_t alg; qsc_slice_t p;
    CHECK(qsc_serialize_unwrap((qsc_slice_t){ w.data, w.length }, &alg, &p) == QSC_OK);
    CHECK(alg == QSC_ALG_CHACHA20_POLY1305 && p.length == 5 && memcmp(p.data, payload, 5) == 0);

    /* Bad magic. */
    w.data[0] = 'X';
    CHECK(qsc_serialize_unwrap((qsc_slice_t){ w.data, w.length }, &alg, &p) == QSC_ERROR_MALFORMED_DATA);
    w.data[0] = 'Q';

    /* Unknown version. */
    w.data[4] = 2;
    CHECK(qsc_serialize_unwrap((qsc_slice_t){ w.data, w.length }, &alg, &p) == QSC_ERROR_VERSION_MISMATCH);
    w.data[4] = 1;

    /* Declared length larger than available bytes. */
    w.data[12] = 0xFF;
    CHECK(qsc_serialize_unwrap((qsc_slice_t){ w.data, w.length }, &alg, &p) == QSC_ERROR_TRUNCATED);
    w.data[12] = 5;

    /* Trailing garbage: declared length is smaller than the buffer. */
    qsc_buffer_t extra = { NULL, 0 };
    qs_u8* longer = (qs_u8*)malloc((size_t)w.length + 1);
    memcpy(longer, w.data, (size_t)w.length); longer[w.length] = 0x00;
    CHECK(qsc_serialize_unwrap((qsc_slice_t){ longer, w.length + 1 }, &alg, &p) == QSC_ERROR_MALFORMED_DATA);
    free(longer);
    (void)extra;

    /* Shorter than the header. */
    CHECK(qsc_serialize_unwrap((qsc_slice_t){ w.data, 10 }, &alg, &p) == QSC_ERROR_TRUNCATED);

    /* Reserved identifiers may not be wrapped. */
    qsc_buffer_t bad = { NULL, 0 };
    CHECK(qsc_serialize_wrap(QSC_ALG_NONE, (qsc_slice_t){ payload, 5 }, &bad) == QSC_ERROR_INVALID_PARAMETERS);
    qsc_buffer_free(&w);
}

static void container_seal_open(void) {
    qsc_key_t* k = NULL, *other = NULL;
    CHECK(qsc_key_generate(QSC_ALG_CHACHA20_POLY1305, &k) == QSC_OK);
    CHECK(qsc_key_generate(QSC_ALG_CHACHA20_POLY1305, &other) == QSC_OK);
    const char* msg = "container body";
    qsc_slice_t aad = { (const qs_u8*)"ctx-1", 5 };
    qsc_buffer_t c = { NULL, 0 }, p = { NULL, 0 };
    CHECK(qsc_seal(k, aad, (qsc_slice_t){ (const qs_u8*)msg, 14 }, &c) == QSC_OK);

    /* Right key, right AAD. */
    CHECK(qsc_open(k, aad, (qsc_slice_t){ c.data, c.length }, &p) == QSC_OK);
    CHECK(p.length == 14 && memcmp(p.data, msg, 14) == 0);
    qsc_buffer_free(&p);

    /* Wrong AAD. */
    CHECK(qsc_open(k, (qsc_slice_t){ (const qs_u8*)"ctx-2", 5 },
                   (qsc_slice_t){ c.data, c.length }, &p) == QSC_ERROR_AUTH_FAILED);
    CHECK(p.data == NULL);

    /* Wrong key. */
    CHECK(qsc_open(other, aad, (qsc_slice_t){ c.data, c.length }, &p) == QSC_ERROR_AUTH_FAILED);

    /* Every byte of the container is covered: flipping any byte must fail.
     * Byte 4 (version) and 12..19 (length) would fail earlier at parse time,
     * which is also a rejection. Only success is a failure here. */
    for (qs_u64 i = 0; i < c.length; i++) {
        c.data[i] ^= 0x01;
        qsc_error_t e = qsc_open(k, aad, (qsc_slice_t){ c.data, c.length }, &p);
        CHECK(e != QSC_OK);
        CHECK(p.data == NULL);
        c.data[i] ^= 0x01;
    }

    /* Container re-labelled to a different algorithm id must be refused. */
    c.data[8] = 0x00; c.data[9] = 0x02;    /* alg = 0x0200 (SHA2_256) */
    CHECK(qsc_open(k, aad, (qsc_slice_t){ c.data, c.length }, &p) == QSC_ERROR_CAPABILITY_MISMATCH);
    c.data[8] = 0x10; c.data[9] = 0x01;    /* restore 0x0110 */

    /* A non-AEAD key cannot seal or open. */
    qsc_key_t* chacha = NULL;
    CHECK(qsc_key_generate(QSC_ALG_CHACHA20, &chacha) == QSC_OK);
    qsc_buffer_t bad = { NULL, 0 };
    CHECK(qsc_seal(chacha, aad, (qsc_slice_t){ (const qs_u8*)msg, 3 }, &bad) == QSC_ERROR_CAPABILITY_MISMATCH);

    qsc_buffer_free(&c);
    qsc_key_destroy(k); qsc_key_destroy(other); qsc_key_destroy(chacha);
}

void run_container_tests(void) {
    wire_roundtrip_and_rejections();
    container_seal_open();
}
