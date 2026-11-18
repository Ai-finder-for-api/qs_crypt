/**
 * @file qs_crypt_xof_experimental.c
 * @brief EXPERIMENTAL / NOT FOR PRODUCTION: domain-separated SHAKE256 XOF.
 *
 * Construction (v0): SHAKE256( "QSCRYPT-XOF-EXP-V0" || u64le(|domain|) || domain
 *                              || u64le(|input|) || input ).
 * Output length is caller-chosen up to QSC_EXPERIMENTAL_XOF_MAX_OUTPUT.
 *
 * Security: this wrapper adds no new cipher or permutation. Its security rests on
 * SHAKE256 (Keccak-f[1600], capacity 512 bits). Collision and preimage resistance are
 * capped near 2^128 and 2^256 respectively, no matter how long the output is. A 512-byte
 * (4096-bit) output does NOT make the construction harder to break than SHAKE256 itself.
 * It has had no independent cryptanalysis. Use SHA3-256 / SHAKE256 for production.
 */
#include "qs_crypt/qs_crypt.h"
#include "qs_crypt/qs_crypt_experimental.h"
#include "../core/qs_crypt_internal.h"
#include "../hash/qs_crypt_hash_internal.h"
#include <string.h>

static const char XOF_TAG[] = "QSCRYPT-XOF-EXP-V0";

qsc_error_t qsc_experimental_xof(qsc_slice_t domain, qsc_slice_t input, qsc_buffer_t* out) {
    qsc_keccak_state s;
    uint8_t len8[8];
    if (!out || out->data != NULL) return QSC_ERROR_INVALID_ARGUMENT;
    if (out->length == 0 || out->length > QSC_EXPERIMENTAL_XOF_MAX_OUTPUT)
        return QSC_ERROR_INVALID_PARAMETERS;
    if ((domain.length && !domain.data) || (input.length && !input.data))
        return QSC_ERROR_INVALID_ARGUMENT;
    if (domain.length == 0) return QSC_ERROR_INVALID_PARAMETERS;  /* domain separation is mandatory */

    out->data = (qs_u8*)qsc_alloc((size_t)out->length);
    if (!out->data) return QSC_ERROR_OOM;

    qsc_keccak_init(&s, 136, 0x1F);
    qsc_keccak_absorb(&s, (const uint8_t*)XOF_TAG, sizeof XOF_TAG - 1);
    qsc_st64le(len8, domain.length);
    qsc_keccak_absorb(&s, len8, 8);
    qsc_keccak_absorb(&s, domain.data, (size_t)domain.length);
    qsc_st64le(len8, input.length);
    qsc_keccak_absorb(&s, len8, 8);
    qsc_keccak_absorb(&s, input.data, (size_t)input.length);
    qsc_keccak_squeeze(&s, out->data, (size_t)out->length);
    qsc_secure_zero(&s, sizeof s);
    return QSC_OK;
}
