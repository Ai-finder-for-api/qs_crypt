/* Known-answer tests for SHA-2/SHA-3/SHAKE, HMAC-SHA-512, AES, AES-GCM, X25519, and the XOF. */
#include "test_common.h"
#include "qs_crypt/qs_crypt.h"
#include "qs_crypt/qs_crypt_experimental.h"
#include <string.h>

static void sha512_kat(void) {
    qsc_digest_t d;
    qsc_slice_t in = { (const qs_u8*)"abc", 3 };
    CHECK(qsc_hash(QSC_ALG_SHA2_512, in, &d) == QSC_OK && d.length == 64);
    CHECK(bytes_match_hex(d.data, 64,
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"));
    in = (qsc_slice_t){ NULL, 0 };
    CHECK(qsc_hash(QSC_ALG_SHA2_512, in, &d) == QSC_OK);
    CHECK(bytes_match_hex(d.data, 64,
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
        "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"));
}

static void sha3_kat(void) {
    qsc_digest_t d;
    qsc_slice_t empty = { NULL, 0 };
    CHECK(qsc_hash(QSC_ALG_SHA3_256, empty, &d) == QSC_OK && d.length == 32);
    CHECK(bytes_match_hex(d.data, 32,
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"));
    qsc_slice_t abc = { (const qs_u8*)"abc", 3 };
    CHECK(qsc_hash(QSC_ALG_SHA3_256, abc, &d) == QSC_OK);
    CHECK(bytes_match_hex(d.data, 32,
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"));
    CHECK(qsc_hash(QSC_ALG_SHA3_512, empty, &d) == QSC_OK && d.length == 64);
    CHECK(bytes_match_hex(d.data, 64,
        "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
        "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"));
    /* Incremental absorption across the rate boundary (136 bytes). */
    uint8_t big[300];
    for (int i = 0; i < 300; i++) big[i] = (uint8_t)i;
    qsc_digest_t one, inc;
    CHECK(qsc_hash(QSC_ALG_SHA3_256, (qsc_slice_t){ big, 300 }, &one) == QSC_OK);
    qsc_hash_ctx_t* c = NULL;
    CHECK(qsc_hash_begin(QSC_ALG_SHA3_256, &c) == QSC_OK);
    CHECK(qsc_hash_update(c, (qsc_slice_t){ big, 135 }) == QSC_OK);
    CHECK(qsc_hash_update(c, (qsc_slice_t){ big + 135, 165 }) == QSC_OK);
    CHECK(qsc_hash_finish(c, &inc) == QSC_OK);
    CHECK(memcmp(one.data, inc.data, 32) == 0);
}

static void shake_kat(void) {
    qsc_buffer_t out = { NULL, 32 };
    CHECK(qsc_shake256((qsc_slice_t){ NULL, 0 }, &out) == QSC_OK);
    CHECK(bytes_match_hex(out.data, 32,
        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"));
    qsc_buffer_free(&out);
}

static void hmac512_kat(void) {
    uint8_t key[20]; memset(key, 0x0b, sizeof key);
    qsc_tag_t t;
    CHECK(qsc_mac(QSC_ALG_HMAC_SHA2_512, (qsc_slice_t){ key, 20 },
                  (qsc_slice_t){ (const qs_u8*)"Hi There", 8 }, &t) == QSC_OK);
    CHECK(t.length == 64);
    CHECK(bytes_match_hex(t.data, 64,
        "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde"
        "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"));
}

static void aes_block_kat(void) {
    /* FIPS-197 C.1 (AES-128) and C.3 (AES-256) via GCM with empty AAD is not a block test,
     * so the block cipher is checked through the GCM tag of a single-block message below.
     * Here: GCM test case 2 (AES-128) exercises one block of CTR plus GHASH. */
    uint8_t key[16] = {0}, nonce[12] = {0}, pt[16] = {0}, ct[16];
    qsc_tag_t t;
    CHECK(qsc_aead_encrypt(QSC_ALG_AES_128_GCM, (qsc_slice_t){ key, 16 },
          (qsc_slice_t){ nonce, 12 }, (qsc_slice_t){ NULL, 0 },
          (qsc_slice_t){ pt, 16 }, ct, &t) == QSC_OK);
    CHECK(bytes_match_hex(ct, 16, "0388dace60b6a392f328c2b971b2fe78"));
    CHECK(bytes_match_hex(t.data, 16, "ab6e47d42cec13bdf53a67b21257bddf"));
}

static void aes256_gcm_kat(void) {
    uint8_t key[32], iv[12], pt[60], aad[20], ct[60];
    qsc_tag_t t;
    const char* keyhex = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308";
    const char* ptx = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                      "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39";
    hex_decode(keyhex, key, 32);
    hex_decode("cafebabefacedbaddecaf888", iv, 12);
    hex_decode(ptx, pt, 60);
    hex_decode("feedfacedeadbeeffeedfacedeadbeefabaddad2", aad, 20);
    CHECK(qsc_aead_encrypt(QSC_ALG_AES_256_GCM, (qsc_slice_t){ key, 32 },
          (qsc_slice_t){ iv, 12 }, (qsc_slice_t){ aad, 20 },
          (qsc_slice_t){ pt, 60 }, ct, &t) == QSC_OK);
    CHECK(bytes_match_hex(ct, 16, "522dc1f099567d07f47f37a32a84427d"));
    CHECK(bytes_match_hex(t.data, 16, "76fc6ece0f4e1768cddf8853bb2d551b"));
    uint8_t back[60];
    CHECK(qsc_aead_decrypt(QSC_ALG_AES_256_GCM, (qsc_slice_t){ key, 32 },
          (qsc_slice_t){ iv, 12 }, (qsc_slice_t){ aad, 20 },
          (qsc_slice_t){ ct, 60 }, (qsc_slice_t){ t.data, 16 }, back) == QSC_OK);
    CHECK(memcmp(back, pt, 60) == 0);
}

static void x25519_kat(void) {
    uint8_t a_priv[32], b_priv[32], a_pub[32], b_pub[32], s1[32], s2[32];
    hex_decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", a_priv, 32);
    hex_decode("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", b_priv, 32);
    CHECK(qsc_x25519_public(a_priv, a_pub) == QSC_OK);
    CHECK(bytes_match_hex(a_pub, 32, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"));
    CHECK(qsc_x25519_public(b_priv, b_pub) == QSC_OK);
    CHECK(bytes_match_hex(b_pub, 32, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"));
    CHECK(qsc_x25519_shared(a_priv, b_pub, s1) == QSC_OK);
    CHECK(qsc_x25519_shared(b_priv, a_pub, s2) == QSC_OK);
    CHECK(bytes_match_hex(s1, 32, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"));
    CHECK(memcmp(s1, s2, 32) == 0);
    /* All-zero output from low-order point u=0 must be rejected. */
    uint8_t zero_u[32] = {0};
    CHECK(qsc_x25519_shared(a_priv, zero_u, s1) == QSC_ERROR_INVALID_KEY);
}

static void xof_experimental(void) {
    qsc_buffer_t a = { NULL, QSC_EXPERIMENTAL_XOF_4096_BYTES };
    qsc_buffer_t b = { NULL, QSC_EXPERIMENTAL_XOF_4096_BYTES };
    qsc_buffer_t c = { NULL, QSC_EXPERIMENTAL_XOF_4096_BYTES };
    qsc_slice_t dom1 = { (const qs_u8*)"app/a", 5 };
    qsc_slice_t dom2 = { (const qs_u8*)"app/b", 5 };
    qsc_slice_t in   = { (const qs_u8*)"input", 5 };
    CHECK(qsc_experimental_xof(dom1, in, &a) == QSC_OK);
    CHECK(qsc_experimental_xof(dom1, in, &b) == QSC_OK);
    CHECK(a.length == 512 && memcmp(a.data, b.data, 512) == 0);       /* deterministic */
    CHECK(qsc_experimental_xof(dom2, in, &c) == QSC_OK);
    CHECK(memcmp(a.data, c.data, 512) != 0);                           /* domain separated */
    /* Prefix property of a XOF: a shorter output is a prefix of a longer one. */
    qsc_buffer_t s = { NULL, 64 };
    CHECK(qsc_experimental_xof(dom1, in, &s) == QSC_OK);
    CHECK(memcmp(s.data, a.data, 64) == 0);
    qsc_buffer_free(&a); qsc_buffer_free(&b); qsc_buffer_free(&c); qsc_buffer_free(&s);
    /* Empty domain is refused. */
    qsc_buffer_t bad = { NULL, 32 };
    CHECK(qsc_experimental_xof((qsc_slice_t){ NULL, 0 }, in, &bad) == QSC_ERROR_INVALID_PARAMETERS);
}

void run_kat2_tests(void) {
    sha512_kat();
    sha3_kat();
    shake_kat();
    hmac512_kat();
    aes_block_kat();
    aes256_gcm_kat();
    x25519_kat();
    xof_experimental();
}
