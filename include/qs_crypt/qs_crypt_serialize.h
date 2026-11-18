/**
 * @file qs_crypt_serialize.h
 * @brief Versioned, length-prefixed serialization for keys and containers.
 *
 * Wire format (all integers little-endian, 64-bit length fields):
 *   magic[4] = "QSC1" | version u32 | alg_id u32 | payload_len u64 | payload | crc? (none)
 * Parsers reject: bad magic, unknown version, length beyond input, trailing bytes.
 */
#ifndef QS_CRYPT_SERIALIZE_H
#define QS_CRYPT_SERIALIZE_H
#include "qs_crypt_types.h"
#ifdef __cplusplus
extern "C" {
#endif

#define QSC_WIRE_MAGIC "QSC1"
#define QSC_WIRE_VERSION 1u
#define QSC_WIRE_HEADER_SIZE 20u

qsc_error_t qsc_serialize_wrap(qsc_algorithm_id_t alg, qsc_slice_t payload,
                               qsc_buffer_t* out);
qsc_error_t qsc_serialize_unwrap(qsc_slice_t input, qsc_algorithm_id_t* alg,
                                 qsc_slice_t* payload);

#ifdef __cplusplus
}
#endif
#endif
