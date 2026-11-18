/* Negative tests: malformed input, wrong sizes, tampering, and misuse. */
#include "test_common.h"
#include "qs_crypt/qs_crypt.h"
#include <string.h>

static void chacha_param_validation(void) {
    uint8_t key[32] = {1}, nonce[12] = {0}, in[8] = {0}, out[8];
    uint8_t key16[16] = {1}, nonce8[8] = {0};
    CHECK(qsc_chacha20_xor((qsc_slice_t){ key16, 16 }, (qsc_slice_t){ nonce, 12 }, 0,
                           (qsc_slice_t){ in, 8 }, out) == QSC_ERROR_KEY_SIZE_MISMATCH);
    CHECK(qsc_chacha20_xor((qsc_slice_t){ key, 32 }, (qsc_slice_t){ nonce8, 8 }, 0,
                           (qsc_slice_t){ in, 8 }, out) == QSC_ERROR_INVALID_NONCE);
    CHECK(qsc_chacha20_xor((qsc_slice_t){ key, 32 }, (qsc_slice_t){ nonce, 12 }, 0,
                           (qsc_slice_t){ NULL, 8 }, out) == QSC_ERROR_INVALID_ARGUMENT);
    /* Counter must not wrap within one call: 2 blocks starting at 0xFFFFFFFF. */
    uint8_t big[128] = {0};
    CHECK(qsc_chacha20_xor((qsc_slice_t){ key, 32 }, (qsc_slice_t){ nonce, 12 }, 0xFFFFFFFFu,
                           (qsc_slice_t){ big, 128 }, big) == QSC_ERROR_INVALID_PARAMETERS);
}

static void aead_param_validation(void) {
    uint8_t key[32] = {1}, nonce[12] = {0}, ct[4], pt[4], tag[16] = {0};
    qsc_tag_t t;
    CHECK(qsc_aead_encrypt(QSC_ALG_ED25519, (qsc_slice_t){ key, 32 },
          (qsc_slice_t){ nonce, 12 }, (qsc_slice_t){ NULL, 0 },
          (qsc_slice_t){ pt, 4 }, ct, &t) == QSC_ERROR_UNSUPPORTED);
    CHECK(qsc_aead_encrypt(QSC_ALG_AES_256_GCM, (qsc_slice_t){ key, 16 },
          (qsc_slice_t){ nonce, 12 }, (qsc_slice_t){ NULL, 0 },
          (qsc_slice_t){ pt, 4 }, ct, &t) == QSC_ERROR_KEY_SIZE_MISMATCH);
    CHECK(qsc_aead_encrypt(QSC_ALG_AES_128_GCM, (qsc_slice_t){ key, 32 },
          (qsc_slice_t){ nonce, 12 }, (qsc_slice_t){ NULL, 0 },
          (qsc_slice_t){ pt, 4 }, ct, &t) == QSC_ERROR_KEY_SIZE_MISMATCH);
    CHECK(qsc_aead_encrypt(QSC_ALG_CHACHA20_POLY1305, (qsc_slice_t){ key, 16 },
          (qsc_slice_t){ nonce, 12 }, (qsc_slice_t){ NULL, 0 },
          (qsc_slice_t){ pt, 4 }, ct, &t) == QSC_ERROR_KEY_SIZE_MISMATCH);
    CHECK(qsc_aead_encrypt(QSC_ALG_CHACHA20_POLY1305, (qsc_slice_t){ key, 32 },
          (qsc_slice_t){ nonce, 8 }, (qsc_slice_t){ NULL, 0 },
          (qsc_slice_t){ pt, 4 }, ct, &t) == QSC_ERROR_INVALID_NONCE);
    CHECK(qsc_aead_decrypt(QSC_ALG_CHACHA20_POLY1305, (qsc_slice_t){ key, 32 },
          (qsc_slice_t){ nonce, 12 }, (qsc_slice_t){ NULL, 0 },
          (qsc_slice_t){ ct, 4 }, (qsc_slice_t){ tag, 15 }, pt) == QSC_ERROR_INVALID_TAG);
    CHECK(qsc_aead_encrypt(QSC_ALG_CHACHA20_POLY1305, (qsc_slice_t){ key, 32 },
          (qsc_slice_t){ nonce, 12 }, (qsc_slice_t){ NULL, 0 },
          (qsc_slice_t){ pt, 4 }, ct, NULL) == QSC_ERROR_INVALID_ARGUMENT);
}

static void aead_tamper_detection(void) {
    uint8_t key[32]; for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 7 + 3);
    uint8_t nonce[12] = {9}, aad[6] = {1,2,3,4,5,6};
    uint8_t pt[40]; for (int i = 0; i < 40; i++) pt[i] = (uint8_t)i;
    uint8_t ct[40], dec[40];
    qsc_tag_t tag;
    CHECK(qsc_aead_encrypt(QSC_ALG_CHACHA20_POLY1305, (qsc_slice_t){ key, 32 },
          (qsc_slice_t){ nonce, 12 }, (qsc_slice_t){ aad, 6 },
          (qsc_slice_t){ pt, 40 }, ct, &tag) == QSC_OK);

    /* Flip each tag byte: every single-bit change must be rejected. */
    for (int i = 0; i < 16; i++) {
        qs_u8 bad[16]; memcpy(bad, tag.data, 16); bad[i] ^= 0x01;
        CHECK(qsc_aead_decrypt(QSC_ALG_CHACHA20_POLY1305, (qsc_slice_t){ key, 32 },
              (qsc_slice_t){ nonce, 12 }, (qsc_slice_t){ aad, 6 },
              (qsc_slice_t){ ct, 40 }, (qsc_slice_t){ bad, 16 }, dec) == QSC_ERROR_AUTH_FAILED);
    }
    /* Flip a ciphertext byte. */
    ct[17] ^= 0x10;
    CHECK(qsc_aead_decrypt(QSC_ALG_CHACHA20_POLY1305, (qsc_slice_t){ key, 32 },
          (qsc_slice_t){ nonce, 12 }, (qsc_slice_t){ aad, 6 },
          (qsc_slice_t){ ct, 40 }, (qsc_slice_t){ tag.data, 16 }, dec) == QSC_ERROR_AUTH_FAILED);
    ct[17] ^= 0x10;
    /* Wrong AAD. */
    aad[0] ^= 1;
    CHECK(qsc_aead_decrypt(QSC_ALG_CHACHA20_POLY1305, (qsc_slice_t){ key, 32 },
          (qsc_slice_t){ nonce, 12 }, (qsc_slice_t){ aad, 6 },
          (qsc_slice_t){ ct, 40 }, (qsc_slice_t){ tag.data, 16 }, dec) == QSC_ERROR_AUTH_FAILED);
    aad[0] ^= 1;
    /* Wrong nonce. */
    nonce[0] ^= 1;
    CHECK(qsc_aead_decrypt(QSC_ALG_CHACHA20_POLY1305, (qsc_slice_t){ key, 32 },
          (qsc_slice_t){ nonce, 12 }, (qsc_slice_t){ aad, 6 },
          (qsc_slice_t){ ct, 40 }, (qsc_slice_t){ tag.data, 16 }, dec) == QSC_ERROR_AUTH_FAILED);
    nonce[0] ^= 1;
    /* Wrong key. */
    key[0] ^= 1;
    CHECK(qsc_aead_decrypt(QSC_ALG_CHACHA20_POLY1305, (qsc_slice_t){ key, 32 },
          (qsc_slice_t){ nonce, 12 }, (qsc_slice_t){ aad, 6 },
          (qsc_slice_t){ ct, 40 }, (qsc_slice_t){ tag.data, 16 }, dec) == QSC_ERROR_AUTH_FAILED);
    key[0] ^= 1;

    /* Failure must not write plaintext: sentinel survives. */
    memset(dec, 0xEE, sizeof dec);
    ct[0] ^= 0xFF;
    (void)qsc_aead_decrypt(QSC_ALG_CHACHA20_POLY1305, (qsc_slice_t){ key, 32 },
          (qsc_slice_t){ nonce, 12 }, (qsc_slice_t){ aad, 6 },
          (qsc_slice_t){ ct, 40 }, (qsc_slice_t){ tag.data, 16 }, dec);
    int untouched = 1;
    for (int i = 0; i < 40; i++) if (dec[i] != 0xEE) untouched = 0;
    CHECK(untouched);
}

static void kdf_and_mac_validation(void) {
    qsc_digest_t prk; uint8_t ikm[4] = {1,2,3,4};
    CHECK(qsc_hkdf_extract(QSC_ALG_HKDF_SHA2_256, (qsc_slice_t){ NULL, 0 },
          (qsc_slice_t){ ikm, 4 }, &prk) == QSC_OK);
    qsc_buffer_t out = { NULL, 0 };
    CHECK(qsc_hkdf_expand(QSC_ALG_HKDF_SHA2_256, (qsc_slice_t){ prk.data, 32 },
          (qsc_slice_t){ NULL, 0 }, &out) == QSC_ERROR_INVALID_PARAMETERS); /* length 0 */

    out.length = QSC_HKDF_SHA256_MAX_OUTPUT + 1;
    CHECK(qsc_hkdf_expand(QSC_ALG_HKDF_SHA2_256, (qsc_slice_t){ prk.data, 32 },
          (qsc_slice_t){ NULL, 0 }, &out) == QSC_ERROR_INVALID_PARAMETERS); /* over RFC limit */

    out.length = 16;
    CHECK(qsc_hkdf_expand(QSC_ALG_HKDF_SHA2_256, (qsc_slice_t){ prk.data, 31 },
          (qsc_slice_t){ NULL, 0 }, &out) == QSC_ERROR_INVALID_KEY);

    out.data = (qs_u8*)&prk;   /* pre-set output must be rejected */
    CHECK(qsc_hkdf_expand(QSC_ALG_HKDF_SHA2_256, (qsc_slice_t){ prk.data, 32 },
          (qsc_slice_t){ NULL, 0 }, &out) == QSC_ERROR_INVALID_ARGUMENT);
    out.data = NULL;

    /* Derivation requires a non-empty domain label. */
    qsc_buffer_t d = { NULL, 16 };
    CHECK(qsc_derive_key(QSC_ALG_HKDF_SHA2_256, (qsc_slice_t){ NULL, 0 },
          (qsc_slice_t){ ikm, 4 }, (qsc_slice_t){ NULL, 0 }, &d) == QSC_ERROR_INVALID_PARAMETERS);

    qsc_tag_t t;
    CHECK(qsc_mac(QSC_ALG_HMAC_SHA2_256, (qsc_slice_t){ NULL, 0 },
          (qsc_slice_t){ ikm, 4 }, &t) == QSC_ERROR_INVALID_KEY);
    CHECK(qsc_mac(QSC_ALG_SHA2_256, (qsc_slice_t){ ikm, 4 },
          (qsc_slice_t){ ikm, 4 }, &t) == QSC_ERROR_UNSUPPORTED);
    CHECK(qsc_mac_verify(QSC_ALG_HMAC_SHA2_256, (qsc_slice_t){ ikm, 4 },
          (qsc_slice_t){ ikm, 4 }, (qsc_slice_t){ ikm, 7 }) == QSC_ERROR_INVALID_TAG);
}

static void key_and_hash_validation(void) {
    uint8_t zero[32] = {0}, bad[31] = {1};
    qsc_key_t* k = NULL;
    CHECK(qsc_key_import(QSC_ALG_CHACHA20_POLY1305, (qsc_slice_t){ zero, 32 }, &k) == QSC_ERROR_WEAK_KEY);
    CHECK(k == NULL);
    CHECK(qsc_key_import(QSC_ALG_CHACHA20_POLY1305, (qsc_slice_t){ bad, 31 }, &k) == QSC_ERROR_KEY_SIZE_MISMATCH);
    CHECK(qsc_key_generate(QSC_ALG_ED25519, &k) == QSC_ERROR_UNSUPPORTED);
    CHECK(qsc_key_generate(QSC_ALG_CHACHA20_POLY1305, NULL) == QSC_ERROR_INVALID_ARGUMENT);

    qsc_digest_t d;
    CHECK(qsc_hash(QSC_ALG_ED25519, (qsc_slice_t){ NULL, 0 }, &d) == QSC_ERROR_UNSUPPORTED);
    CHECK(qsc_hash(QSC_ALG_SHAKE256, (qsc_slice_t){ NULL, 0 }, &d) == QSC_ERROR_UNSUPPORTED); /* XOF: use qsc_shake256 */
    CHECK(qsc_hash(QSC_ALG_SHA2_256, (qsc_slice_t){ NULL, 5 }, &d) == QSC_ERROR_INVALID_ARGUMENT);
    CHECK(qsc_hash_update(NULL, (qsc_slice_t){ NULL, 0 }) == QSC_ERROR_INVALID_ARGUMENT);
    CHECK(qsc_random_bytes(NULL, 4) == QSC_ERROR_INVALID_ARGUMENT);
}

void run_negative_tests(void) {
    chacha_param_validation();
    aead_param_validation();
    aead_tamper_detection();
    kdf_and_mac_validation();
    key_and_hash_validation();
}
