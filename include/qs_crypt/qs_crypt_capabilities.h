/**
 * @file qs_crypt_capabilities.h
 * @brief Algorithm capability discovery.
 */
#ifndef QS_CRYPT_CAPABILITIES_H
#define QS_CRYPT_CAPABILITIES_H
#include "qs_crypt_types.h"
#ifdef __cplusplus
extern "C" {
#endif

qsc_error_t qsc_algorithm_info(qsc_algorithm_id_t id, qsc_algorithm_info_t* info);
qsc_error_t qsc_algorithm_enumerate(qsc_algorithm_info_t* out_buf, qs_u64 capacity, qs_u64* count);
qs_bool_t   qsc_algorithm_supported(qsc_algorithm_id_t id);
qs_bool_t   qsc_algorithm_is_experimental(qsc_algorithm_id_t id);
qs_bool_t   qsc_algorithm_is_post_quantum(qsc_algorithm_id_t id);
qsc_error_t qsc_algorithm_require_capabilities(qsc_algorithm_id_t id,
                                               qsc_capabilities_t required);

#ifdef __cplusplus
}
#endif
#endif
