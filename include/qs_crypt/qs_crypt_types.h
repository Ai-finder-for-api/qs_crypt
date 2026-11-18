/**
 * @file qs_crypt_types.h
 * @brief QScrypt foundational types, error codes, and algorithm identifiers.
 * Stability: STABLE. Language: C (C ABI).
 */
#ifndef QS_CRYPT_TYPES_H
#define QS_CRYPT_TYPES_H

#include "../core/qs_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define QS_CRYPT_VERSION_MAJOR 0
#define QS_CRYPT_VERSION_MINOR 2
#define QS_CRYPT_VERSION_PATCH 0

typedef enum {
    QSC_OK                         = 0,
    QSC_ERROR_INVALID_ARGUMENT     = 1,
    QSC_ERROR_OOM                  = 2,
    QSC_ERROR_UNSUPPORTED          = 3,
    QSC_ERROR_NOT_INITIALIZED      = 4,
    QSC_ERROR_AUTH_FAILED          = 100,
    QSC_ERROR_DECRYPTION_FAILED    = 101,
    QSC_ERROR_INVALID_KEY          = 102,
    QSC_ERROR_INVALID_NONCE        = 103,
    QSC_ERROR_NONCE_REUSE          = 104,
    QSC_ERROR_WEAK_KEY             = 105,
    QSC_ERROR_INVALID_SIGNATURE    = 106,
    QSC_ERROR_INVALID_TAG          = 107,
    QSC_ERROR_ENTROPY_UNAVAILABLE  = 200,
    QSC_ERROR_RNG_NOT_SEEDED       = 201,
    QSC_ERROR_MALFORMED_DATA       = 300,
    QSC_ERROR_VERSION_MISMATCH     = 301,
    QSC_ERROR_TRUNCATED            = 302,
    QSC_ERROR_BUFFER_TOO_SMALL     = 303,
    QSC_ERROR_KEY_SIZE_MISMATCH    = 400,
    QSC_ERROR_OUTPUT_SIZE_MISMATCH = 401,
    QSC_ERROR_INVALID_PARAMETERS   = 402,
    QSC_ERROR_ALGORITHM_DISABLED   = 500,
    QSC_ERROR_CAPABILITY_MISMATCH  = 501
} qsc_error_t;

/* Ranges: 0x0000 symmetric, 0x0100 AEAD, 0x0200 hash, 0x0300 MAC, 0x0400 KDF,
 * 0x0500 PKE/KEM, 0x0600 signatures, 0x0700 post-quantum, 0x0800 experimental. */
typedef enum {
    QSC_ALG_NONE                   = 0x0000,
    QSC_ALG_CHACHA20               = 0x0010,
    QSC_ALG_AES_128_GCM            = 0x0100,
    QSC_ALG_AES_256_GCM            = 0x0101,
    QSC_ALG_CHACHA20_POLY1305      = 0x0110,
    QSC_ALG_SHA2_256               = 0x0200,
    QSC_ALG_SHA2_384               = 0x0201,
    QSC_ALG_SHA2_512               = 0x0202,
    QSC_ALG_SHA3_256               = 0x0210,
    QSC_ALG_SHA3_512               = 0x0212,
    QSC_ALG_SHAKE256               = 0x0220, /* XOF: use qsc_shake256() */
    QSC_ALG_HMAC_SHA2_256          = 0x0300,
    QSC_ALG_HMAC_SHA2_512          = 0x0301,
    QSC_ALG_HMAC_SHA2_384          = 0x0302,
    QSC_ALG_HKDF_SHA2_256          = 0x0400,
    QSC_ALG_HKDF_SHA2_512          = 0x0401,
    QSC_ALG_RSA_OAEP_SHA256        = 0x0510, /* RSA-OAEP, SHA-256, 2048/3072/4096-bit */
    QSC_ALG_X25519                 = 0x0520, /* RFC 7748 key agreement */
    QSC_ALG_RSA_PSS_SHA256         = 0x0610, /* RSASSA-PSS, SHA-256, salt 32, 2048/3072/4096-bit */
    QSC_ALG_ED25519                = 0x0620, /* identifier reserved; backend-only */
    QSC_ALG_ECDSA_P256_SHA256      = 0x0630, /* ECDSA over NIST P-256, SHA-256, raw r||s signatures */
    QSC_ALG_ML_KEM_768             = 0x0700, /* FIPS 203; backend-only */
    QSC_ALG_ML_DSA_65              = 0x0710, /* FIPS 204; backend-only */
    QSC_ALG_EXPERIMENTAL_QS_STREAM = 0x0800, /* reserved, no implementation */
    QSC_ALG_EXPERIMENTAL_QS_XOF    = 0x0801, /* EXPERIMENTAL / NOT FOR PRODUCTION: see qs_crypt_experimental.h */
    QSC_ALG_BFV_N4096              = 0x0900, /* BFV FHE, N=4096, RNS Q (3 primes), t=257 */
    QSC_ALG_UNKNOWN                = 0xFFFF
} qsc_algorithm_id_t;

typedef qs_u32 qsc_capabilities_t;
#define QSC_CAP_ENCRYPT       (1u << 0)
#define QSC_CAP_DECRYPT       (1u << 1)
#define QSC_CAP_AEAD          (1u << 2)
#define QSC_CAP_HASH          (1u << 3)
#define QSC_CAP_MAC           (1u << 4)
#define QSC_CAP_KDF           (1u << 5)
#define QSC_CAP_SIGN          (1u << 6)
#define QSC_CAP_VERIFY        (1u << 7)
#define QSC_CAP_KEM_ENCAP     (1u << 8)
#define QSC_CAP_KEM_DECAP     (1u << 9)
#define QSC_CAP_POST_QUANTUM  (1u << 10)
#define QSC_CAP_EXPERIMENTAL  (1u << 11)
#define QSC_CAP_STREAM_CIPHER (1u << 12)
#define QSC_CAP_KEY_AGREE     (1u << 13)

/* Opaque handles. Never dereference or sizeof from outside the module. */
typedef struct qsc_ctx        qsc_ctx_t;
typedef struct qsc_key        qsc_key_t;
typedef struct qsc_keypair    qsc_keypair_t;
typedef struct qsc_pubkey     qsc_pubkey_t;
typedef struct qsc_hash_ctx   qsc_hash_ctx_t;
typedef struct qsc_rng        qsc_rng_t;

typedef struct { qs_u8 data[32]; qs_u64 length; } qsc_nonce_t;
typedef struct { qs_u8 data[64]; qs_u64 length; } qsc_tag_t;
typedef struct { qs_u8 data[64]; qs_u64 length; } qsc_digest_t;

typedef struct {
    qsc_algorithm_id_t id;
    qsc_capabilities_t capabilities;
    qs_u64             key_size_bytes;     /* 0 = variable or N/A */
    qs_u64             nonce_size_bytes;   /* 0 = N/A */
    qs_u64             tag_size_bytes;     /* 0 = N/A */
    qs_u64             digest_size_bytes;  /* 0 = N/A */
    const char*        name;
    qs_bool_t          experimental;
    qs_bool_t          post_quantum;
} qsc_algorithm_info_t;

/* Mutable output buffer: caller provides storage via qsc_buffer_t.data and capacity in length. */
typedef struct { qs_u8* data; qs_u64 length; } qsc_buffer_t;

/* Immutable input slice. */
typedef struct { const qs_u8* data; qs_u64 length; } qsc_slice_t;

#define QSC_SLICE_OF(arr) ((qsc_slice_t){ (const qs_u8*)(arr), sizeof(arr) })

#ifdef __cplusplus
}
#endif
#endif
