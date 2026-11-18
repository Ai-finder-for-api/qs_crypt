/**
 * @file qsv_core.h
 * @brief qsvault: layered file encryption built on qs_crypt.
 *
 * Layers (see docs in qsvault README):
 *   1. password     (mandatory)  PBKDF2-HMAC-SHA256
 *   2. .qs.ckey     (mandatory)  256-bit random key file
 *   3. signature    (optional)   ML-DSA-65 over the whole file, checked against a trusted key
 *   4. USB key      (optional)   256-bit random key file that must be present on decrypt
 *   5. cloud        (optional)   validation via a one-way commitment; OFF unless QSV_CLOUD_ENABLED
 *
 * File format (version 1, all integers big-endian):
 *   0    "QSV1"                    4
 *   4    flags                     1   bit0 password, bit1 ckey, bit2 usb, bit3 signed, bit4 cloud
 *   5    reserved (zero)           3
 *   8    PBKDF2 iterations         4
 *   12   salt_pw                   16
 *   28   salt_kdf                  32
 *   60   sha256(ckey secret)       32
 *   92   sha256(usb secret)        32   (zero if no usb layer)
 *   124  u32 len(wrapped_fk), wrapped_fk            (sealed under KEK)
 *        u64 len(body),       body                  (sealed under file key)
 *   [signed only] signer public key (1952) || ML-DSA-65 signature (3309)
 *
 * The header is authenticated as AAD by both seal operations. The signature covers every byte
 * before the signer public key, so changing any layer flag or byte breaks verification.
 */
#ifndef QSV_CORE_H
#define QSV_CORE_H

#include <stdint.h>
#include <stddef.h>
#include "qs_crypt/qs_crypt.h"
#include <stddef.h>

#define QSV_FLAG_PASSWORD 0x01u
#define QSV_FLAG_CKEY     0x02u
#define QSV_FLAG_USB      0x04u
#define QSV_FLAG_SIGNED   0x08u
#define QSV_FLAG_CLOUD    0x10u
#define QSV_FLAG_KNOWN    0x1Fu

#define QSV_HEADER_BYTES  124u
#define QSV_KEYFILE_BYTES 40u     /* "QSCKEY01" (8) + secret (32) */
#define QSV_MIN_PASSWORD  12u
#define QSV_DEFAULT_ITER  600000u
#define QSV_MAX_ITER      50000000u

typedef struct {
    const uint8_t* password;   /* required on encrypt and decrypt */
    size_t         password_len;
    const uint8_t* ckey;       /* 32-byte secret from the .qs.ckey file, required */
    const uint8_t* usb;        /* 32-byte secret from the USB key file, or NULL */
    const uint8_t* sign_sk;    /* 4032-byte ML-DSA-65 secret key, or NULL (encrypt only) */
    const uint8_t* sign_pk;    /* 1952-byte matching public key, required with sign_sk */
    uint32_t       iterations; /* 0 = QSV_DEFAULT_ITER */
} qsv_secrets_t;

typedef struct {
    uint8_t  flags;
    uint32_t iterations;
    size_t   total_bytes;
} qsv_info_t;

/* Encrypt. On success *out is malloc'd; release with qsv_free(). */
qsc_error_t qsv_encrypt(const qsv_secrets_t* s, const uint8_t* pt, size_t ptl,
                        uint8_t** out, size_t* outl);

/* Decrypt. trust_pk is required when the file is signed and is compared against the embedded key.
 * On success *pt is malloc'd; release with qsv_free(). Signature and cloud checks run before the
 * password KDF, so an unauthorised file costs no key derivation work. */
qsc_error_t qsv_decrypt(const qsv_secrets_t* s, const uint8_t* trust_pk,
                        const uint8_t* in, size_t inl, uint8_t** pt, size_t* ptl);

/* Header-only inspection. Needs no secrets. */
qsc_error_t qsv_info(const uint8_t* in, size_t inl, qsv_info_t* info);

/* Key files. */
qsc_error_t qsv_keyfile_make(uint8_t out[QSV_KEYFILE_BYTES]);
qsc_error_t qsv_keyfile_parse(const uint8_t* in, size_t inl, uint8_t secret[32]);

/* PBKDF2-HMAC-SHA256 (exposed for known-answer tests). */
qsc_error_t qsv_pbkdf2_sha256(const uint8_t* pw, size_t pwl, const uint8_t* salt, size_t saltl,
                              uint32_t iters, uint8_t out[32]);

void qsv_free(uint8_t* p, size_t n);

#endif
