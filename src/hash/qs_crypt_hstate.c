/**
 * @file qs_crypt_hstate.c
 * @brief Unified streaming state over SHA-2 and SHA-3/SHAKE implementations.
 */
#include "qs_crypt/qs_crypt.h"
#include "qs_crypt_hash_internal.h"
#include <string.h>

qsc_error_t qsc_hstate_init(qsc_hstate* h, qsc_algorithm_id_t alg) {
    h->alg = alg;
    switch (alg) {
        case QSC_ALG_SHA2_256: qsc_sha256_init(&h->u.s256); return QSC_OK;
        case QSC_ALG_SHA2_384: qsc_sha384_init(&h->u.s512); return QSC_OK;
        case QSC_ALG_SHA2_512: qsc_sha512_init(&h->u.s512); return QSC_OK;
        case QSC_ALG_SHA3_256: qsc_keccak_init(&h->u.kk, 136, 0x06); return QSC_OK;
        case QSC_ALG_SHA3_512: qsc_keccak_init(&h->u.kk, 72, 0x06);  return QSC_OK;
        default: return QSC_ERROR_UNSUPPORTED;
    }
}

void qsc_hstate_update(qsc_hstate* h, const uint8_t* d, size_t n) {
    if (!n) return;
    switch (h->alg) {
        case QSC_ALG_SHA2_256: qsc_sha256_update(&h->u.s256, d, n); break;
        case QSC_ALG_SHA2_384:
        case QSC_ALG_SHA2_512: qsc_sha512_update(&h->u.s512, d, n); break;
        case QSC_ALG_SHA3_256:
        case QSC_ALG_SHA3_512: qsc_keccak_absorb(&h->u.kk, d, n); break;
        default: break;
    }
}

void qsc_hstate_final(qsc_hstate* h, uint8_t* out) {
    switch (h->alg) {
        case QSC_ALG_SHA2_256: qsc_sha256_final(&h->u.s256, out); break;
        case QSC_ALG_SHA2_384: qsc_sha384_final(&h->u.s512, out); break;
        case QSC_ALG_SHA2_512: qsc_sha512_final(&h->u.s512, out); break;
        case QSC_ALG_SHA3_256:
        case QSC_ALG_SHA3_512:
            qsc_keccak_squeeze(&h->u.kk, out, qsc_hstate_outlen(h->alg));
            qsc_secure_zero(&h->u.kk, sizeof h->u.kk);
            break;
        default: break;
    }
}

size_t qsc_hstate_outlen(qsc_algorithm_id_t alg) {
    switch (alg) {
        case QSC_ALG_SHA2_256: case QSC_ALG_SHA3_256: return 32;
        case QSC_ALG_SHA2_384: return 48;
        case QSC_ALG_SHA2_512: case QSC_ALG_SHA3_512: return 64;
        default: return 0;
    }
}

size_t qsc_hstate_block(qsc_algorithm_id_t alg) {
    switch (alg) {
        case QSC_ALG_SHA2_256: return 64;
        case QSC_ALG_SHA2_384:
        case QSC_ALG_SHA2_512: return 128;
        default: return 0;
    }
}
