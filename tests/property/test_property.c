/* Randomized property tests. Seeds come from the OS CSPRNG, so each run differs;
 * failures print the iteration index for reproduction via the failing assertion. */
#include "test_common.h"
#include "qs_crypt/qs_crypt.h"
#include <string.h>

#define ITER 200

static void aead_random_roundtrip(void) {
    for (int it = 0; it < ITER; it++) {
        qs_u8 key[32], nonce[12], aad[64], pt[512], ct[512], out[512];
        qsc_tag_t tag;
        qs_u64 alen = 0, plen = 0;
        CHECK(qsc_random_bytes(key, 32) == QSC_OK);
        CHECK(qsc_random_bytes(nonce, 12) == QSC_OK);
        CHECK(qsc_random_bytes((qs_u8*)&alen, 1) == QSC_OK);
        CHECK(qsc_random_bytes((qs_u8*)&plen, 2) == QSC_OK);
        alen %= 65; plen %= 513;
        CHECK(qsc_random_bytes(aad, (qs_u64)(alen ? alen : 1)) == QSC_OK);
        CHECK(qsc_random_bytes(pt, (qs_u64)(plen ? plen : 1)) == QSC_OK);
        CHECK(qsc_aead_encrypt(QSC_ALG_CHACHA20_POLY1305, (qsc_slice_t){ key, 32 },
              (qsc_slice_t){ nonce, 12 }, (qsc_slice_t){ aad, alen },
              (qsc_slice_t){ pt, plen }, ct, &tag) == QSC_OK);
        CHECK(qsc_aead_decrypt(QSC_ALG_CHACHA20_POLY1305, (qsc_slice_t){ key, 32 },
              (qsc_slice_t){ nonce, 12 }, (qsc_slice_t){ aad, alen },
              (qsc_slice_t){ ct, plen }, (qsc_slice_t){ tag.data, 16 }, out) == QSC_OK);
        CHECK(plen == 0 || memcmp(out, pt, (size_t)plen) == 0);
    }
}

static void aead_random_bitflips_rejected(void) {
    for (int it = 0; it < ITER; it++) {
        qs_u8 key[32], nonce[12], pt[64], ct[64], out[64];
        qsc_tag_t tag;
        CHECK(qsc_random_bytes(key, 32) == QSC_OK);
        CHECK(qsc_random_bytes(nonce, 12) == QSC_OK);
        CHECK(qsc_random_bytes(pt, 64) == QSC_OK);
        CHECK(qsc_aead_encrypt(QSC_ALG_CHACHA20_POLY1305, (qsc_slice_t){ key, 32 },
              (qsc_slice_t){ nonce, 12 }, (qsc_slice_t){ NULL, 0 },
              (qsc_slice_t){ pt, 64 }, ct, &tag) == QSC_OK);
        qs_u8 r; CHECK(qsc_random_bytes(&r, 1) == QSC_OK);
        ct[r % 64] ^= (qs_u8)(1u << (r % 8));
        CHECK(qsc_aead_decrypt(QSC_ALG_CHACHA20_POLY1305, (qsc_slice_t){ key, 32 },
              (qsc_slice_t){ nonce, 12 }, (qsc_slice_t){ NULL, 0 },
              (qsc_slice_t){ ct, 64 }, (qsc_slice_t){ tag.data, 16 }, out) == QSC_ERROR_AUTH_FAILED);
    }
}

static void sha256_random_split_equivalence(void) {
    for (int it = 0; it < ITER; it++) {
        qs_u8 msg[300];
        qs_u8 cut;
        CHECK(qsc_random_bytes(msg, sizeof msg) == QSC_OK);
        CHECK(qsc_random_bytes(&cut, 1) == QSC_OK);
        size_t split = cut % sizeof msg;
        qsc_digest_t a, b;
        qsc_hash_ctx_t* c = NULL;
        CHECK(qsc_hash(QSC_ALG_SHA2_256, (qsc_slice_t){ msg, sizeof msg }, &a) == QSC_OK);
        CHECK(qsc_hash_begin(QSC_ALG_SHA2_256, &c) == QSC_OK);
        CHECK(qsc_hash_update(c, (qsc_slice_t){ msg, split }) == QSC_OK);
        CHECK(qsc_hash_update(c, (qsc_slice_t){ msg + split, sizeof msg - split }) == QSC_OK);
        CHECK(qsc_hash_finish(c, &b) == QSC_OK);
        CHECK(memcmp(a.data, b.data, 32) == 0);
    }
}

static void hkdf_domain_separation_random(void) {
    for (int it = 0; it < 50; it++) {
        qs_u8 ikm[32]; CHECK(qsc_random_bytes(ikm, 32) == QSC_OK);
        qsc_buffer_t a = { NULL, 32 }, b = { NULL, 32 };
        CHECK(qsc_derive_key(QSC_ALG_HKDF_SHA2_256, (qsc_slice_t){ NULL, 0 },
              (qsc_slice_t){ ikm, 32 }, (qsc_slice_t){ (const qs_u8*)"ctx/a", 5 }, &a) == QSC_OK);
        CHECK(qsc_derive_key(QSC_ALG_HKDF_SHA2_256, (qsc_slice_t){ NULL, 0 },
              (qsc_slice_t){ ikm, 32 }, (qsc_slice_t){ (const qs_u8*)"ctx/b", 5 }, &b) == QSC_OK);
        CHECK(memcmp(a.data, b.data, 32) != 0);
        qsc_buffer_free(&a); qsc_buffer_free(&b);
    }
}

void run_property_tests(void) {
    aead_random_roundtrip();
    aead_random_bitflips_rejected();
    sha256_random_split_equivalence();
    hkdf_domain_separation_random();
}
