/**
 * @file qs_crypt_wire.c
 * @brief Versioned wire envelope: magic | version | alg | payload_len | payload.
 * Parsing is strict: wrong magic, wrong version, length mismatch, or trailing
 * bytes are all rejected.
 */
#include "qs_crypt/qs_crypt.h"
#include "../core/qs_crypt_internal.h"
#include <string.h>

qsc_error_t qsc_serialize_wrap(qsc_algorithm_id_t alg, qsc_slice_t payload, qsc_buffer_t* out) {
    uint8_t* p;
    if (!out || out->data != NULL) return QSC_ERROR_INVALID_ARGUMENT;
    if (payload.length && !payload.data) return QSC_ERROR_INVALID_ARGUMENT;
    if (alg == QSC_ALG_NONE || alg == QSC_ALG_UNKNOWN) return QSC_ERROR_INVALID_PARAMETERS;
    if (payload.length > ((uint64_t)1 << 40)) return QSC_ERROR_INVALID_PARAMETERS;
    p = (uint8_t*)qsc_alloc((size_t)(QSC_WIRE_HEADER_SIZE + payload.length));
    if (!p) return QSC_ERROR_OOM;
    memcpy(p, QSC_WIRE_MAGIC, 4);
    qsc_st32le(p + 4, QSC_WIRE_VERSION);
    qsc_st32le(p + 8, (uint32_t)alg);
    qsc_st64le(p + 12, payload.length);
    if (payload.length) memcpy(p + QSC_WIRE_HEADER_SIZE, payload.data, (size_t)payload.length);
    out->data = p;
    out->length = QSC_WIRE_HEADER_SIZE + payload.length;
    return QSC_OK;
}

qsc_error_t qsc_serialize_unwrap(qsc_slice_t input, qsc_algorithm_id_t* alg,
                                 qsc_slice_t* payload) {
    uint64_t plen;
    if (!alg || !payload || !input.data) return QSC_ERROR_INVALID_ARGUMENT;
    if (input.length < QSC_WIRE_HEADER_SIZE) return QSC_ERROR_TRUNCATED;
    if (memcmp(input.data, QSC_WIRE_MAGIC, 4) != 0) return QSC_ERROR_MALFORMED_DATA;
    if (qsc_ld32le(input.data + 4) != QSC_WIRE_VERSION) return QSC_ERROR_VERSION_MISMATCH;
    plen = 0;
    for (int i = 7; i >= 0; i--) plen = (plen << 8) | input.data[12 + i];
    if (plen > input.length - QSC_WIRE_HEADER_SIZE) return QSC_ERROR_TRUNCATED;
    if (plen != input.length - QSC_WIRE_HEADER_SIZE) return QSC_ERROR_MALFORMED_DATA;
    *alg = (qsc_algorithm_id_t)qsc_ld32le(input.data + 8);
    payload->data = input.data + QSC_WIRE_HEADER_SIZE;
    payload->length = plen;
    return QSC_OK;
}
