/**
 * @file qsv_cloudstore.h
 * @brief Cloud backup of .qs.ckey files, encrypted before upload.
 *
 * Cloud key file: key-<16 random hex>.cloud.ckey.qs (60 bytes, keep it on a USB drive).
 *   0   "QSCLD002"                8
 *   8   id "key-<16 hex>"        20
 *   28  secret                   32
 *
 * Backup: the 40-byte .qs.ckey is sealed with the password and the cloud key secret, then
 * uploaded with its id. The server stores only that ciphertext.
 * Restore: the server returns the ciphertext and its creation timestamp. The timestamp must match
 * the local index when one exists; the decryption itself needs the password and the cloud key.
 */
#ifndef QSV_CLOUDSTORE_H
#define QSV_CLOUDSTORE_H

#include <stdint.h>
#include <stddef.h>
#include "qs_crypt/qs_crypt.h"

#define QSV_CS_ID_LEN        20u   /* "key-" + 16 hex */
#define QSV_CS_CLOUDKEY_BYTES 60u
#define QSV_CS_TIME_MAX      64u

/* Sends one request. path is "/put" or "/get"; body is JSON; the reply goes into resp. */
typedef qsc_error_t (*qsv_cs_call_fn)(const char* path, const char* json_body,
                                      char* resp, size_t resp_cap);

qsc_error_t qsv_cs_cloudkey_make(uint8_t out[QSV_CS_CLOUDKEY_BYTES]);
qsc_error_t qsv_cs_cloudkey_parse(const uint8_t* in, size_t inl,
                                  char id[QSV_CS_ID_LEN + 1], uint8_t secret[32]);

qsc_error_t qsv_cs_backup(qsv_cs_call_fn call,
                          const uint8_t* cloudkey, size_t cloudkey_len,
                          const uint8_t* password, size_t password_len,
                          const uint8_t ckey[40], uint32_t iterations,
                          char created[QSV_CS_TIME_MAX]);

qsc_error_t qsv_cs_restore(qsv_cs_call_fn call,
                           const uint8_t* cloudkey, size_t cloudkey_len,
                           const uint8_t* password, size_t password_len,
                           uint8_t ckey[40], char created[QSV_CS_TIME_MAX]);

/* Local index: one line per backup, "<id> <created_at>". */
/* Returns 0 if there is no entry or it matches, 1 if the entry differs, -1 on I/O error. */
int         qsv_cs_index_check(const char* path, const char* id, const char* created);
qsc_error_t qsv_cs_index_write(const char* path, const char* id, const char* created);

#endif
