/* Consumer test: links against qs_crypt.lib and loads qs_crypt.dll at run time. */
#include "qs_crypt/qs_crypt.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    int fail = 0;
    if (qsc_init() != QSC_OK) { printf("qsc_init failed\n"); return 1; }

    /* SHA-256("abc") */
    static const qs_u8 sha_abc[32] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad };
    qsc_digest_t dg;
    qsc_hash(QSC_ALG_SHA2_256, (qsc_slice_t){ (const qs_u8*)"abc", 3 }, &dg);
    if (memcmp(dg.data, sha_abc, 32) != 0) { printf("sha256 mismatch\n"); fail++; }

    /* ECDSA P-256 sign and verify */
    qs_u8 priv[32], pub[65], sig[64];
    const char* msg = "dll test";
    if (qsc_ecdsa_p256_keygen(priv, pub) != QSC_OK) { printf("ecdsa keygen failed\n"); fail++; }
    else {
        if (qsc_ecdsa_p256_sign(priv, (qsc_slice_t){ (const qs_u8*)msg, strlen(msg) }, sig) != QSC_OK ||
            qsc_ecdsa_p256_verify(pub, (qsc_slice_t){ (const qs_u8*)msg, strlen(msg) }, sig) != QSC_OK) {
            printf("ecdsa sign/verify failed\n"); fail++;
        }
    }

    /* ML-KEM-768 encapsulate and decapsulate */
    static qs_u8 ek[1184], dk[2400], ct[1088], k1[32], k2[32];
    if (qsc_mlkem768_keygen(ek, dk) != QSC_OK ||
        qsc_mlkem768_encaps(ek, ct, k1) != QSC_OK ||
        qsc_mlkem768_decaps(dk, ct, k2) != QSC_OK ||
        memcmp(k1, k2, 32) != 0) {
        printf("mlkem round trip failed\n"); fail++;
    }

    /* RSA-2048 OAEP round trip */
    qsc_rsa_public_t* rpub = NULL;
    qsc_rsa_private_t* rpriv = NULL;
    static qs_u8 rct[512], rout[512];
    if (qsc_rsa_keygen(2048, &rpub, &rpriv) != QSC_OK) { printf("rsa keygen failed\n"); fail++; }
    else {
        qsc_buffer_t c = { rct, sizeof rct };
        qsc_buffer_t o = { rout, sizeof rout };
        if (qsc_rsa_oaep_encrypt(rpub, (qsc_slice_t){ (const qs_u8*)msg, strlen(msg) }, &c) != QSC_OK ||
            qsc_rsa_oaep_decrypt(rpriv, (qsc_slice_t){ rct, c.length }, &o) != QSC_OK ||
            o.length != strlen(msg) || memcmp(rout, msg, strlen(msg)) != 0) {
            printf("rsa oaep round trip failed\n"); fail++;
        }
    }
    qsc_rsa_public_destroy(rpub);
    qsc_rsa_private_destroy(rpriv);

    printf(fail ? "DLL test FAILED (%d)\n" : "DLL test OK\n", fail);
    qsc_shutdown();
    return fail ? 1 : 0;
}
