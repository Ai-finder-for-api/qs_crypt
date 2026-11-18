/**
 * @file qs_crypt_experimental.h
 * @brief EXPERIMENTAL / NOT FOR PRODUCTION. Opt-in only.
 *
 * This header is deliberately NOT included by qs_crypt.h. Code must include it
 * explicitly, so experimental use is visible in review.
 *
 * Read docs/EXPERIMENTAL.md before use. Nothing here has independent cryptanalysis.
 */
#ifndef QS_CRYPT_EXPERIMENTAL_H
#define QS_CRYPT_EXPERIMENTAL_H
#include "qs_crypt_types.h"
#ifdef __cplusplus
extern "C" {
#endif

/* 4096 bits. The length is a size choice, not a security level: see the .c file. */
#define QSC_EXPERIMENTAL_XOF_4096_BYTES 512u
#define QSC_EXPERIMENTAL_XOF_MAX_OUTPUT (1u << 20)

/* Domain-separated XOF. domain must be non-empty. out->data must be NULL on entry.
 * Release the result with qsc_buffer_free(). */
qsc_error_t qsc_experimental_xof(qsc_slice_t domain, qsc_slice_t input, qsc_buffer_t* out);

#ifdef __cplusplus
}
#endif
#endif
