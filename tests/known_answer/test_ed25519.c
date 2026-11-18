/* Ed25519 tests: RFC 8032 section 7.1 vectors, forgery and tamper rejection, round trip. */
#include "test_common.h"
#include "qs_crypt/qs_crypt.h"
#include <string.h>

static void rfc8032_vector(const char* sk_hex, const char* pk_hex, const uint8_t* msg,
                           size_t mlen, const char* sig_hex) {
    uint8_t sk[32], pk[32], pk2[32], sig[64], sig2[64];
    CHECK(hex_decode(sk_hex, sk, 32) == 32);
    CHECK(hex_decode(pk_hex, pk, 32) == 32);
    CHECK(qsc_ed25519_public(sk, pk2) == QSC_OK);
    CHECK(memcmp(pk, pk2, 32) == 0);
    CHECK(qsc_ed25519_sign(sk, msg, mlen, sig) == QSC_OK);
    CHECK(bytes_match_hex(sig, 64, sig_hex));
    CHECK(qsc_ed25519_verify(pk, msg, mlen, sig) == QSC_OK);
    (void)sig2;
}

static void add_L(uint8_t s[32]) {
    static const uint8_t L[32] = {
        0xed,0xd3,0xf5,0x5c,0x1a,0x63,0x12,0x58,0xd6,0x9c,0xf7,0xa2,0xde,0xf9,0xde,0x14,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x10
    };
    unsigned carry = 0;
    for (int i = 0; i < 32; i++) {
        unsigned t = (unsigned)s[i] + L[i] + carry;
        s[i] = (uint8_t)t;
        carry = t >> 8;
    }
}

static void ed25519_kat(void) {
    /* RFC 8032 7.1 TEST 1: empty message. */
    rfc8032_vector(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        (const uint8_t*)"", 0,
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");

    /* RFC 8032 7.1 TEST 2: one-byte message 0x72. */
    uint8_t m72[1] = { 0x72 };
    rfc8032_vector(
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        m72, 1,
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");
}

static void ed25519_rejections(void) {
    uint8_t sk[32], pk[32], sig[64], bad[64], s2[32];
    static const uint8_t msg[] = "quantum suite";
    hex_decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", sk, 32);
    hex_decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", pk, 32);
    CHECK(qsc_ed25519_sign(sk, msg, sizeof msg - 1, sig) == QSC_OK);
    CHECK(qsc_ed25519_verify(pk, msg, sizeof msg - 1, sig) == QSC_OK);

    /* Wrong message. */
    CHECK(qsc_ed25519_verify(pk, msg, sizeof msg - 2, sig) == QSC_ERROR_INVALID_SIGNATURE);

    /* Every single-bit flip in R or S must be rejected. */
    for (int i = 0; i < 64; i++) {
        memcpy(bad, sig, 64);
        bad[i] ^= 0x04;
        CHECK(qsc_ed25519_verify(pk, msg, sizeof msg - 1, bad) != QSC_OK);
    }

    /* Non-canonical S (S + L) must be rejected even though it is congruent. */
    memcpy(bad, sig, 64);
    memcpy(s2, sig + 32, 32);
    add_L(s2);
    memcpy(bad + 32, s2, 32);
    CHECK(qsc_ed25519_verify(pk, msg, sizeof msg - 1, bad) == QSC_ERROR_INVALID_SIGNATURE);

    /* Wrong public key (RFC 8032 test 2's key). */
    uint8_t pk2[32];
    hex_decode("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", pk2, 32);
    CHECK(qsc_ed25519_verify(pk2, msg, sizeof msg - 1, sig) == QSC_ERROR_INVALID_SIGNATURE);

    /* Invalid public-key encoding (y >= p) is rejected. */
    uint8_t badpk[32];
    memset(badpk, 0xFF, 32);
    CHECK(qsc_ed25519_verify(badpk, msg, sizeof msg - 1, sig) == QSC_ERROR_INVALID_SIGNATURE);
}

static void ed25519_roundtrip(void) {
    for (int i = 0; i < 20; i++) {
        uint8_t seed[32], pk[32], sig[64], msg[100];
        qs_u8 len = 0;
        CHECK(qsc_ed25519_keygen(seed, pk) == QSC_OK);
        CHECK(qsc_random_bytes(msg, sizeof msg) == QSC_OK);
        CHECK(qsc_random_bytes(&len, 1) == QSC_OK);
        CHECK(qsc_ed25519_sign(seed, msg, len % 100, sig) == QSC_OK);
        CHECK(qsc_ed25519_verify(pk, msg, len % 100, sig) == QSC_OK);
        if (len % 100) {
            msg[0] ^= 1;
            CHECK(qsc_ed25519_verify(pk, msg, len % 100, sig) == QSC_ERROR_INVALID_SIGNATURE);
        }
    }
}

void run_ed25519_tests(void) {
    ed25519_kat();
    ed25519_rejections();
    ed25519_roundtrip();
}
