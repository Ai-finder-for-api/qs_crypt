/* Unit tests for public API behaviour. */
#include "test_common.h"
#include "qs_crypt/qs_crypt.h"
#include <string.h>

static void lifecycle_and_utils(void) {
    qs_u32 a = 9, b = 9, c = 9;
    qsc_version(&a, &b, &c);
    CHECK(a == QS_CRYPT_VERSION_MAJOR && b == QS_CRYPT_VERSION_MINOR && c == QS_CRYPT_VERSION_PATCH);
    CHECK(qsc_build_info() != NULL);

    uint8_t x[8] = {1,2,3,4,5,6,7,8};
    uint8_t y[8] = {1,2,3,4,5,6,7,8};
    CHECK(qsc_constant_time_equal(x, y, 8) == QS_TRUE);
    y[7] ^= 0x80;
    CHECK(qsc_constant_time_equal(x, y, 8) == QS_FALSE);
    CHECK(qsc_constant_time_equal(x, y, 7) == QS_TRUE);

    qsc_secure_zero(x, sizeof x);
    int all_zero = 1;
    for (int i = 0; i < 8; i++) if (x[i]) all_zero = 0;
    CHECK(all_zero);
}

static void registry(void) {
    qsc_algorithm_info_t info;
    CHECK(qsc_algorithm_info(QSC_ALG_CHACHA20_POLY1305, &info) == QSC_OK);
    CHECK(info.key_size_bytes == 32);
    CHECK(info.nonce_size_bytes == 12);
    CHECK(info.tag_size_bytes == 16);
    CHECK(info.experimental == QS_FALSE);

    CHECK(qsc_algorithm_supported(QSC_ALG_SHA2_256) == QS_TRUE);
    CHECK(qsc_algorithm_supported(QSC_ALG_SHA2_512) == QS_TRUE);
    CHECK(qsc_algorithm_supported(QSC_ALG_ED25519) == QS_TRUE);
    CHECK(qsc_algorithm_supported(QSC_ALG_ML_KEM_768) == QS_FALSE); /* backend-only */
    CHECK(qsc_algorithm_is_post_quantum(QSC_ALG_ML_KEM_768) == QS_TRUE);
    CHECK(qsc_algorithm_is_post_quantum(QSC_ALG_CHACHA20) == QS_FALSE);
    CHECK(qsc_algorithm_is_experimental(QSC_ALG_CHACHA20) == QS_FALSE);

    CHECK(qsc_algorithm_require_capabilities(QSC_ALG_CHACHA20_POLY1305, QSC_CAP_AEAD) == QSC_OK);
    CHECK(qsc_algorithm_require_capabilities(QSC_ALG_CHACHA20, QSC_CAP_SIGN) == QSC_ERROR_CAPABILITY_MISMATCH);
    CHECK(qsc_algorithm_require_capabilities(QSC_ALG_ED25519, QSC_CAP_SIGN) == QSC_OK);
    CHECK(qsc_algorithm_require_capabilities(QSC_ALG_ED25519, QSC_CAP_ENCRYPT) == QSC_ERROR_CAPABILITY_MISMATCH);

    qsc_algorithm_info_t buf[32];
    qs_u64 count = 0;
    CHECK(qsc_algorithm_enumerate(buf, 32, &count) == QSC_OK);
    CHECK(count > 0 && count <= 32);
    CHECK(qsc_algorithm_info((qsc_algorithm_id_t)0x1234, &info) == QSC_ERROR_UNSUPPORTED);
}

static void rng(void) {
    qs_u8 a[32], b[32];
    CHECK(qsc_random_bytes(a, 32) == QSC_OK);
    CHECK(qsc_random_bytes(b, 32) == QSC_OK);
    CHECK(memcmp(a, b, 32) != 0);

    qsc_rng_t* r = NULL;
    CHECK(qsc_rng_create(&r) == QSC_OK && r != NULL);
    CHECK(qsc_rng_fill(r, a, 32) == QSC_OK);
    qsc_rng_destroy(r);
}

static void keys(void) {
    qsc_key_t* k = NULL;
    CHECK(qsc_key_generate(QSC_ALG_CHACHA20_POLY1305, &k) == QSC_OK && k);
    CHECK(qsc_key_size(k) == 32);
    CHECK(qsc_key_algorithm(k) == QSC_ALG_CHACHA20_POLY1305);

    qsc_buffer_t exp = { NULL, 0 };
    CHECK(qsc_key_export(k, &exp) == QSC_OK);
    CHECK(exp.length == 32);

    qsc_key_t* k2 = NULL;
    CHECK(qsc_key_import(QSC_ALG_CHACHA20_POLY1305, (qsc_slice_t){ exp.data, 32 }, &k2) == QSC_OK);
    qsc_buffer_t exp2 = { NULL, 0 };
    CHECK(qsc_key_export(k2, &exp2) == QSC_OK);
    CHECK(exp.length == exp2.length && memcmp(exp.data, exp2.data, 32) == 0);

    qsc_buffer_free(&exp);
    qsc_buffer_free(&exp2);
    qsc_key_destroy(k);
    qsc_key_destroy(k2);
}

static void hash_api(void) {
    qsc_digest_t one, inc;
    const char* msg = "quantum suite";
    qsc_slice_t s = { (const qs_u8*)msg, strlen(msg) };
    CHECK(qsc_hash(QSC_ALG_SHA2_256, s, &one) == QSC_OK);

    qsc_hash_ctx_t* c = NULL;
    CHECK(qsc_hash_begin(QSC_ALG_SHA2_256, &c) == QSC_OK);
    CHECK(qsc_hash_update(c, (qsc_slice_t){ s.data, 5 }) == QSC_OK);
    qsc_hash_ctx_t* cl = NULL;
    CHECK(qsc_hash_clone(c, &cl) == QSC_OK);
    CHECK(qsc_hash_update(c, (qsc_slice_t){ s.data + 5, s.length - 5 }) == QSC_OK);
    CHECK(qsc_hash_finish(c, &inc) == QSC_OK);
    CHECK(one.length == inc.length && memcmp(one.data, inc.data, 32) == 0);

    /* The clone was taken mid-stream; finishing it with the rest must match too. */
    qsc_digest_t cd;
    CHECK(qsc_hash_update(cl, (qsc_slice_t){ s.data + 5, s.length - 5 }) == QSC_OK);
    CHECK(qsc_hash_finish(cl, &cd) == QSC_OK);
    CHECK(memcmp(one.data, cd.data, 32) == 0);
}

static void mac_and_kdf(void) {
    uint8_t key[32]; memset(key, 0x42, sizeof key);
    qsc_tag_t t;
    CHECK(qsc_mac(QSC_ALG_HMAC_SHA2_256, (qsc_slice_t){ key, 32 },
                  (qsc_slice_t){ (const qs_u8*)"m", 1 }, &t) == QSC_OK);
    CHECK(qsc_mac_verify(QSC_ALG_HMAC_SHA2_256, (qsc_slice_t){ key, 32 },
                         (qsc_slice_t){ (const qs_u8*)"m", 1 },
                         (qsc_slice_t){ t.data, 32 }) == QSC_OK);
    t.data[0] ^= 1;
    CHECK(qsc_mac_verify(QSC_ALG_HMAC_SHA2_256, (qsc_slice_t){ key, 32 },
                         (qsc_slice_t){ (const qs_u8*)"m", 1 },
                         (qsc_slice_t){ t.data, 32 }) == QSC_ERROR_AUTH_FAILED);

    /* Domain separation: same IKM, different labels -> different keys. */
    qsc_buffer_t k1 = { NULL, 32 }, k2 = { NULL, 32 };
    qsc_slice_t ikm = { key, 32 }, salt = { NULL, 0 };
    CHECK(qsc_derive_key(QSC_ALG_HKDF_SHA2_256, salt, ikm,
            (qsc_slice_t){ (const qs_u8*)"qs/app/enc", 10 }, &k1) == QSC_OK);
    CHECK(qsc_derive_key(QSC_ALG_HKDF_SHA2_256, salt, ikm,
            (qsc_slice_t){ (const qs_u8*)"qs/app/mac", 10 }, &k2) == QSC_OK);
    CHECK(memcmp(k1.data, k2.data, 32) != 0);
    qsc_buffer_free(&k1);
    qsc_buffer_free(&k2);
}

static void aead_roundtrip(void) {
    qsc_key_t* k = NULL;
    qsc_buffer_t kb = { NULL, 0 };
    CHECK(qsc_key_generate(QSC_ALG_CHACHA20_POLY1305, &k) == QSC_OK);
    CHECK(qsc_key_export(k, &kb) == QSC_OK && kb.length == 32);
    uint8_t nonce[12] = {0}; nonce[0] = 1;
    const char* pt = "hello";
    uint8_t ct[5], out[5];
    qsc_tag_t tag;
    CHECK(qsc_aead_encrypt(QSC_ALG_CHACHA20_POLY1305,
        (qsc_slice_t){ kb.data, 32 }, (qsc_slice_t){ nonce, 12 },
        (qsc_slice_t){ (const qs_u8*)"ad", 2 }, (qsc_slice_t){ (const qs_u8*)pt, 5 },
        ct, &tag) == QSC_OK);
    CHECK(qsc_aead_decrypt(QSC_ALG_CHACHA20_POLY1305,
        (qsc_slice_t){ kb.data, 32 }, (qsc_slice_t){ nonce, 12 },
        (qsc_slice_t){ (const qs_u8*)"ad", 2 }, (qsc_slice_t){ ct, 5 },
        (qsc_slice_t){ tag.data, 16 }, out) == QSC_OK);
    CHECK(memcmp(out, pt, 5) == 0);

    /* Empty plaintext is valid and still authenticated. */
    qsc_tag_t t0;
    CHECK(qsc_aead_encrypt(QSC_ALG_CHACHA20_POLY1305,
        (qsc_slice_t){ kb.data, 32 }, (qsc_slice_t){ nonce, 12 },
        (qsc_slice_t){ NULL, 0 }, (qsc_slice_t){ NULL, 0 }, NULL, &t0) == QSC_OK);
    CHECK(t0.length == 16);
    qsc_buffer_free(&kb);
    qsc_key_destroy(k);
}

static void seal_roundtrip(void) {
    qsc_key_t* k = NULL;
    CHECK(qsc_key_generate(QSC_ALG_CHACHA20_POLY1305, &k) == QSC_OK);
    const char* msg = "sealed payload";
    qsc_buffer_t c1 = { NULL, 0 }, c2 = { NULL, 0 }, p = { NULL, 0 };
    CHECK(qsc_seal(k, (qsc_slice_t){ NULL, 0 }, (qsc_slice_t){ (const qs_u8*)msg, 14 }, &c1) == QSC_OK);
    CHECK(qsc_seal(k, (qsc_slice_t){ NULL, 0 }, (qsc_slice_t){ (const qs_u8*)msg, 14 }, &c2) == QSC_OK);
    /* Fresh random nonce per seal: identical plaintexts must not produce identical containers. */
    CHECK(c1.length == c2.length && memcmp(c1.data, c2.data, (size_t)c1.length) != 0);
    CHECK(qsc_open(k, (qsc_slice_t){ NULL, 0 }, (qsc_slice_t){ c1.data, c1.length }, &p) == QSC_OK);
    CHECK(p.length == 14 && memcmp(p.data, msg, 14) == 0);
    qsc_buffer_free(&p); qsc_buffer_free(&c1); qsc_buffer_free(&c2);
    qsc_key_destroy(k);
}

void run_api_tests(void) {
    lifecycle_and_utils();
    registry();
    rng();
    keys();
    hash_api();
    mac_and_kdf();
    aead_roundtrip();
    seal_roundtrip();
}
