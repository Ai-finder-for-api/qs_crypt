/**
 * @file qs_crypt_registry.c
 * @brief Algorithm registry and capability discovery.
 *
 * `implemented` describes THIS build. Identifiers with implemented=0 are reserved for
 * future work or for a compatibility backend.
 */
#include "qs_crypt/qs_crypt.h"
#include <stddef.h>

typedef struct {
    qsc_algorithm_id_t id;
    qsc_capabilities_t caps;
    qs_u64 key, nonce, tag, digest;
    const char* name;
    qs_bool_t experimental, post_quantum, implemented;
} qsc_registry_entry_t;

#define ENT(id, caps, k, n, t, d, name, exp, pq, impl) \
    { id, caps, k, n, t, d, name, exp, pq, impl }

static const qsc_registry_entry_t g_registry[] = {
    /* Symmetric / AEAD */
    ENT(QSC_ALG_CHACHA20, QSC_CAP_ENCRYPT | QSC_CAP_DECRYPT | QSC_CAP_STREAM_CIPHER,
        32, 12, 0, 0, "ChaCha20 (RFC 8439; unauthenticated)", QS_FALSE, QS_FALSE, QS_TRUE),
    ENT(QSC_ALG_CHACHA20_POLY1305, QSC_CAP_ENCRYPT | QSC_CAP_DECRYPT | QSC_CAP_AEAD,
        32, 12, 16, 0, "ChaCha20-Poly1305 (RFC 8439)", QS_FALSE, QS_FALSE, QS_TRUE),
    ENT(QSC_ALG_AES_128_GCM, QSC_CAP_ENCRYPT | QSC_CAP_DECRYPT | QSC_CAP_AEAD,
        16, 12, 16, 0, "AES-128-GCM (SP 800-38D; table-based AES)", QS_FALSE, QS_FALSE, QS_TRUE),
    ENT(QSC_ALG_AES_256_GCM, QSC_CAP_ENCRYPT | QSC_CAP_DECRYPT | QSC_CAP_AEAD,
        32, 12, 16, 0, "AES-256-GCM (SP 800-38D; table-based AES)", QS_FALSE, QS_FALSE, QS_TRUE),
    /* Hash / XOF */
    ENT(QSC_ALG_SHA2_256, QSC_CAP_HASH, 0, 0, 0, 32, "SHA-256 (FIPS 180-4)",
        QS_FALSE, QS_FALSE, QS_TRUE),
    ENT(QSC_ALG_SHA2_384, QSC_CAP_HASH, 0, 0, 0, 48, "SHA-384 (FIPS 180-4)",
        QS_FALSE, QS_FALSE, QS_TRUE),
    ENT(QSC_ALG_SHA2_512, QSC_CAP_HASH, 0, 0, 0, 64, "SHA-512 (FIPS 180-4)",
        QS_FALSE, QS_FALSE, QS_TRUE),
    ENT(QSC_ALG_SHA3_256, QSC_CAP_HASH, 0, 0, 0, 32, "SHA3-256 (FIPS 202)",
        QS_FALSE, QS_FALSE, QS_TRUE),
    ENT(QSC_ALG_SHA3_512, QSC_CAP_HASH, 0, 0, 0, 64, "SHA3-512 (FIPS 202)",
        QS_FALSE, QS_FALSE, QS_TRUE),
    ENT(QSC_ALG_SHAKE256, QSC_CAP_HASH, 0, 0, 0, 0, "SHAKE256 XOF (FIPS 202; use qsc_shake256)",
        QS_FALSE, QS_FALSE, QS_TRUE),
    /* MAC / KDF */
    ENT(QSC_ALG_HMAC_SHA2_256, QSC_CAP_MAC, 32, 0, 32, 0, "HMAC-SHA-256 (RFC 2104)",
        QS_FALSE, QS_FALSE, QS_TRUE),
    ENT(QSC_ALG_HMAC_SHA2_384, QSC_CAP_MAC, 48, 0, 48, 0, "HMAC-SHA-384 (RFC 2104)",
        QS_FALSE, QS_FALSE, QS_TRUE),
    ENT(QSC_ALG_HMAC_SHA2_512, QSC_CAP_MAC, 64, 0, 64, 0, "HMAC-SHA-512 (RFC 2104)",
        QS_FALSE, QS_FALSE, QS_TRUE),
    ENT(QSC_ALG_HKDF_SHA2_256, QSC_CAP_KDF, 0, 0, 0, 32, "HKDF-SHA-256 (RFC 5869)",
        QS_FALSE, QS_FALSE, QS_TRUE),
    ENT(QSC_ALG_HKDF_SHA2_512, QSC_CAP_KDF, 0, 0, 0, 64, "HKDF-SHA-512 (RFC 5869)",
        QS_FALSE, QS_FALSE, QS_TRUE),
    /* Key agreement */
    ENT(QSC_ALG_X25519, QSC_CAP_KEY_AGREE, 32, 0, 0, 0, "X25519 (RFC 7748)",
        QS_FALSE, QS_FALSE, QS_TRUE),
    /* Backend-only (not implemented natively) */
    ENT(QSC_ALG_ED25519, QSC_CAP_SIGN | QSC_CAP_VERIFY, 32, 0, 0, 0,
        "Ed25519 (RFC 8032, PureEd25519)", QS_FALSE, QS_FALSE, QS_TRUE),
    ENT(QSC_ALG_ML_KEM_768, QSC_CAP_KEM_ENCAP | QSC_CAP_KEM_DECAP | QSC_CAP_POST_QUANTUM,
        0, 0, 0, 0, "ML-KEM-768 (FIPS 203)", QS_FALSE, QS_TRUE, QS_FALSE),
    ENT(QSC_ALG_ECDSA_P256_SHA256, QSC_CAP_SIGN | QSC_CAP_VERIFY, 0, 0, 0, 0,
        "ECDSA P-256 (SHA-256, raw r||s)", QS_FALSE, QS_FALSE, QS_FALSE),
    ENT(QSC_ALG_ML_DSA_65, QSC_CAP_SIGN | QSC_CAP_VERIFY | QSC_CAP_POST_QUANTUM,
        0, 0, 0, 0, "ML-DSA-65 (FIPS 204, pure, 1952/4032/3309)", QS_FALSE, QS_TRUE, QS_FALSE),
    /* RSA: OAEP-SHA256 encryption, PSS-SHA256 signatures (2048/3072/4096-bit keys) */
    ENT(QSC_ALG_RSA_OAEP_SHA256, QSC_CAP_ENCRYPT | QSC_CAP_DECRYPT, 0, 0, 0, 0,
        "RSA-OAEP (SHA-256, 2048/3072/4096-bit)", QS_FALSE, QS_FALSE, QS_FALSE),
    ENT(QSC_ALG_RSA_PSS_SHA256, QSC_CAP_SIGN | QSC_CAP_VERIFY, 0, 0, 0, 0,
        "RSA-PSS (SHA-256, salt 32, 2048/3072/4096-bit)", QS_FALSE, QS_FALSE, QS_FALSE),
    /* FHE: BFV, N=4096, RNS modulus (3 primes), t=257 (add/sub/dense plain-multiply) */
    ENT(QSC_ALG_BFV_N4096, QSC_CAP_ENCRYPT | QSC_CAP_DECRYPT, 0, 0, 0, 0,
        "BFV FHE (N=4096, RNS Q, t=257; no ciphertext multiply yet)", QS_FALSE, QS_FALSE, QS_TRUE),
    /* EXPERIMENTAL: opt-in header only; not in qs_crypt.h */
    ENT(QSC_ALG_EXPERIMENTAL_QS_XOF, QSC_CAP_HASH | QSC_CAP_EXPERIMENTAL, 0, 0, 0, 0,
        "QScrypt experimental XOF v0 (NOT FOR PRODUCTION)", QS_TRUE, QS_FALSE, QS_TRUE),
};

#define REGISTRY_COUNT (sizeof g_registry / sizeof g_registry[0])

static const qsc_registry_entry_t* find_entry(qsc_algorithm_id_t id) {
    for (size_t i = 0; i < REGISTRY_COUNT; i++)
        if (g_registry[i].id == id) return &g_registry[i];
    return NULL;
}

qsc_error_t qsc_algorithm_info(qsc_algorithm_id_t id, qsc_algorithm_info_t* info) {
    const qsc_registry_entry_t* e;
    if (!info) return QSC_ERROR_INVALID_ARGUMENT;
    e = find_entry(id);
    if (!e) return QSC_ERROR_UNSUPPORTED;
    info->id = e->id;
    info->capabilities = e->caps;
    info->key_size_bytes = e->key;
    info->nonce_size_bytes = e->nonce;
    info->tag_size_bytes = e->tag;
    info->digest_size_bytes = e->digest;
    info->name = e->name;
    info->experimental = e->experimental;
    info->post_quantum = e->post_quantum;
    return QSC_OK;
}

qs_bool_t qsc_algorithm_supported(qsc_algorithm_id_t id) {
    const qsc_registry_entry_t* e = find_entry(id);
    return (e && e->implemented) ? QS_TRUE : QS_FALSE;
}

qs_bool_t qsc_algorithm_is_experimental(qsc_algorithm_id_t id) {
    const qsc_registry_entry_t* e = find_entry(id);
    return (e && e->experimental) ? QS_TRUE : QS_FALSE;
}

qs_bool_t qsc_algorithm_is_post_quantum(qsc_algorithm_id_t id) {
    const qsc_registry_entry_t* e = find_entry(id);
    return (e && e->post_quantum) ? QS_TRUE : QS_FALSE;
}

qsc_error_t qsc_algorithm_require_capabilities(qsc_algorithm_id_t id,
                                               qsc_capabilities_t required) {
    const qsc_registry_entry_t* e = find_entry(id);
    if (!e || !e->implemented) return QSC_ERROR_UNSUPPORTED;
    if ((e->caps & required) != required) return QSC_ERROR_CAPABILITY_MISMATCH;
    return QSC_OK;
}

qsc_error_t qsc_algorithm_enumerate(qsc_algorithm_info_t* out_buf,
                                    qs_u64 capacity, qs_u64* count) {
    if (!count) return QSC_ERROR_INVALID_ARGUMENT;
    *count = REGISTRY_COUNT;
    if (!out_buf) return QSC_OK;
    for (qs_u64 i = 0; i < capacity && i < REGISTRY_COUNT; i++)
        (void)qsc_algorithm_info(g_registry[i].id, &out_buf[i]);
    return QSC_OK;
}
