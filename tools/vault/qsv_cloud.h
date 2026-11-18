/**
 * @file qsv_cloud.h
 * @brief Optional cloud validation layer for qsvault.
 *
 * Design: the cloud service NEVER receives key material. The client sends a one-way commitment,
 * SHA-256("QSV1-cloud-commit" || ckey_secret), so the service can check registration and
 * revocation but cannot decrypt anything. Storing the raw keys in a database would turn the
 * database into a single point of decryption; this layer is deliberately not that.
 */
#ifndef QSV_CLOUD_H
#define QSV_CLOUD_H

#include <stdint.h>
#include <stddef.h>
#include "qs_crypt/qs_crypt.h"

/* Transport hook. Performs an HTTPS POST of json_body to url and writes the response body into
 * resp (NUL-terminated, at most resp_cap bytes). Supplied by the host application, because this
 * library carries no HTTP stack. */
typedef qsc_error_t (*qsv_cloud_transport_fn)(const char* url, const char* json_body,
                                              char* resp, size_t resp_cap);

qsc_error_t qsv_cloud_commitment(const uint8_t ckey[32], uint8_t out[32]);
void        qsv_cloud_set_transport(qsv_cloud_transport_fn fn, const char* url);
qsc_error_t qsv_cloud_register(const uint8_t commitment[32]);
qsc_error_t qsv_cloud_validate(const uint8_t commitment[32]);

#endif
