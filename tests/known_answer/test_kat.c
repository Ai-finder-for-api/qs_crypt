/* Known-answer tests from published specifications. */
#include "test_common.h"
#include "qs_crypt/qs_crypt.h"
#include <string.h>

static void sha256_kat(void) {
    qsc_digest_t d;
    qsc_slice_t in;

    in = (qsc_slice_t){ (const qs_u8*)"", 0 };
    CHECK(qsc_hash(QSC_ALG_SHA2_256, in, &d) == QSC_OK);
    CHECK(bytes_match_hex(d.data, 32,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));

    in = (qsc_slice_t){ (const qs_u8*)"abc", 3 };
    CHECK(qsc_hash(QSC_ALG_SHA2_256, in, &d) == QSC_OK);
    CHECK(bytes_match_hex(d.data, 32,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));

    const char* m448 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    in = (qsc_slice_t){ (const qs_u8*)m448, strlen(m448) };
    CHECK(qsc_hash(QSC_ALG_SHA2_256, in, &d) == QSC_OK);
    CHECK(bytes_match_hex(d.data, 32,
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
}

static void sha256_million_a(void) {
    static uint8_t a[1000000];
    qsc_digest_t d;
    qsc_hash_ctx_t* ctx = NULL;
    memset(a, 'a', sizeof a);
    CHECK(qsc_hash(QSC_ALG_SHA2_256, (qsc_slice_t){ a, sizeof a }, &d) == QSC_OK);
    CHECK(bytes_match_hex(d.data, 32,
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));

    /* Incremental with awkward chunk sizes must match one-shot. */
    CHECK(qsc_hash_begin(QSC_ALG_SHA2_256, &ctx) == QSC_OK);
    size_t off = 0, step = 7;
    while (off < sizeof a) {
        size_t take = (sizeof a - off) < step ? (sizeof a - off) : step;
        CHECK(qsc_hash_update(ctx, (qsc_slice_t){ a + off, take }) == QSC_OK);
        off += take;
        step = (step * 3 + 1) % 200 + 1;
    }
    qsc_digest_t d2;
    CHECK(qsc_hash_finish(ctx, &d2) == QSC_OK);
    CHECK(d2.length == 32 && memcmp(d.data, d2.data, 32) == 0);
}

static void hmac_kat(void) {
    qsc_tag_t t;
    uint8_t k1[20]; memset(k1, 0x0b, sizeof k1);
    CHECK(qsc_mac(QSC_ALG_HMAC_SHA2_256, (qsc_slice_t){ k1, 20 },
                  (qsc_slice_t){ (const qs_u8*)"Hi There", 8 }, &t) == QSC_OK);
    CHECK(bytes_match_hex(t.data, 32,
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));

    CHECK(qsc_mac(QSC_ALG_HMAC_SHA2_256, (qsc_slice_t){ (const qs_u8*)"Jefe", 4 },
                  (qsc_slice_t){ (const qs_u8*)"what do ya want for nothing?", 28 }, &t) == QSC_OK);
    CHECK(bytes_match_hex(t.data, 32,
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));

    /* RFC 4231 test case 6: key longer than the block size is hashed first. */
    uint8_t k6[131]; memset(k6, 0xaa, sizeof k6);
    const char* m6 = "Test Using Larger Than Block-Size Key - Hash Key First";
    CHECK(qsc_mac(QSC_ALG_HMAC_SHA2_256, (qsc_slice_t){ k6, 131 },
                  (qsc_slice_t){ (const qs_u8*)m6, strlen(m6) }, &t) == QSC_OK);
    CHECK(bytes_match_hex(t.data, 32,
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"));
}

static void hkdf_kat(void) {
    uint8_t ikm[22], salt[13], info[10];
    memset(ikm, 0x0b, sizeof ikm);
    for (int i = 0; i < 13; i++) salt[i] = (uint8_t)i;
    for (int i = 0; i < 10; i++) info[i] = (uint8_t)(0xf0 + i);

    qsc_digest_t prk;
    CHECK(qsc_hkdf_extract(QSC_ALG_HKDF_SHA2_256, (qsc_slice_t){ salt, 13 },
                           (qsc_slice_t){ ikm, 22 }, &prk) == QSC_OK);
    CHECK(bytes_match_hex(prk.data, 32,
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"));

    qsc_buffer_t okm = { NULL, 42 };
    CHECK(qsc_hkdf_expand(QSC_ALG_HKDF_SHA2_256, (qsc_slice_t){ prk.data, 32 },
                          (qsc_slice_t){ info, 10 }, &okm) == QSC_OK);
    CHECK(okm.length == 42);
    CHECK(bytes_match_hex(okm.data, 42,
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"));
    qsc_buffer_free(&okm);
}

static void chacha20_kat(void) {
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;

    /* RFC 8439 2.3.2: first keystream bytes for counter 1. */
    uint8_t nonce_b[12] = { 0,0,0,9, 0,0,0,0x4a, 0,0,0,0 };
    uint8_t zeros[64] = {0}, ks[64];
    CHECK(qsc_chacha20_xor((qsc_slice_t){ key, 32 }, (qsc_slice_t){ nonce_b, 12 }, 1,
                           (qsc_slice_t){ zeros, 64 }, ks) == QSC_OK);
    CHECK(bytes_match_hex(ks, 16, "10f1e7e4d13b5915500fdd1fa32071c4"));

    /* RFC 8439 2.4.2: ciphertext prefix. */
    uint8_t nonce_c[12] = { 0,0,0,0, 0,0,0,0x4a, 0,0,0,0 };
    const char* pt = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    uint8_t ct[256];
    CHECK(qsc_chacha20_xor((qsc_slice_t){ key, 32 }, (qsc_slice_t){ nonce_c, 12 }, 1,
                           (qsc_slice_t){ (const qs_u8*)pt, strlen(pt) }, ct) == QSC_OK);
    CHECK(bytes_match_hex(ct, 16, "6e2e359a2568f98041ba0728dd0d6981"));

    /* XOR is an involution. */
    uint8_t back[256];
    CHECK(qsc_chacha20_xor((qsc_slice_t){ key, 32 }, (qsc_slice_t){ nonce_c, 12 }, 1,
                           (qsc_slice_t){ ct, strlen(pt) }, back) == QSC_OK);
    CHECK(memcmp(back, pt, strlen(pt)) == 0);
}

static void aead_kat(void) {
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(0x80 + i);
    uint8_t nonce[12] = { 0x07,0,0,0, 0x40,0x41,0x42,0x43, 0x44,0x45,0x46,0x47 };
    uint8_t aad[12] = { 0x50,0x51,0x52,0x53, 0xc0,0xc1,0xc2,0xc3, 0xc4,0xc5,0xc6,0xc7 };
    const char* pt = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    size_t n = strlen(pt);
    uint8_t ct[256]; qsc_tag_t tag;

    CHECK(qsc_aead_encrypt(QSC_ALG_CHACHA20_POLY1305,
            (qsc_slice_t){ key, 32 }, (qsc_slice_t){ nonce, 12 },
            (qsc_slice_t){ aad, 12 }, (qsc_slice_t){ (const qs_u8*)pt, n },
            ct, &tag) == QSC_OK);
    /* RFC 8439 2.8.2 */
    CHECK(tag.length == 16);
    CHECK(bytes_match_hex(tag.data, 16, "1ae10b594f09e26a7e902ecbd0600691"));
    CHECK(bytes_match_hex(ct, 16, "d31a8d34648e60db7b86afbc53ef7ec2"));

    uint8_t dec[256];
    CHECK(qsc_aead_decrypt(QSC_ALG_CHACHA20_POLY1305,
            (qsc_slice_t){ key, 32 }, (qsc_slice_t){ nonce, 12 },
            (qsc_slice_t){ aad, 12 }, (qsc_slice_t){ ct, n },
            (qsc_slice_t){ tag.data, 16 }, dec) == QSC_OK);
    CHECK(memcmp(dec, pt, n) == 0);
}

void run_kat_tests(void) {
    sha256_kat();
    sha256_million_a();
    hmac_kat();
    hkdf_kat();
    chacha20_kat();
    aead_kat();
}
