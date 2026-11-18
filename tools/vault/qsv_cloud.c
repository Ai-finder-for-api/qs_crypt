/**
 * @file qsv_cloud.c
 * @brief Cloud validation layer (disabled unless QSV_CLOUD_ENABLED is 1).
 */
#include "qsv_cloud.h"
#include "qsv_config.h"
#include <stdio.h>
#include <string.h>

static qsv_cloud_transport_fn transport = NULL;
static char base_url[512] = "";

static const char COMMIT_LABEL[] = "QSV1-cloud-commit";

qsc_error_t qsv_cloud_commitment(const uint8_t ckey[32], uint8_t out[32]) {
    uint8_t buf[sizeof COMMIT_LABEL - 1 + 32];
    qsc_digest_t d;
    if (!ckey || !out) return QSC_ERROR_INVALID_ARGUMENT;
    memcpy(buf, COMMIT_LABEL, sizeof COMMIT_LABEL - 1);
    memcpy(buf + sizeof COMMIT_LABEL - 1, ckey, 32);
    qsc_error_t e = qsc_hash(QSC_ALG_SHA2_256, (qsc_slice_t){ buf, (qs_u64)sizeof buf }, &d);
    if (e == QSC_OK) memcpy(out, d.data, 32);
    qsc_secure_zero(buf, sizeof buf);
    return e;
}

void qsv_cloud_set_transport(qsv_cloud_transport_fn fn, const char* url) {
    transport = fn;
    if (url) {
        strncpy(base_url, url, sizeof base_url - 1);
        base_url[sizeof base_url - 1] = '\0';
    } else {
        base_url[0] = '\0';
    }
}

#if QSV_CLOUD_ENABLED

static qsc_error_t post_commitment(const char* path, const uint8_t commitment[32]) {
    static const char hex[] = "0123456789abcdef";
    char body[96], url[640], resp[256];
    char hexstr[65];
    size_t i;
    if (!transport || base_url[0] == '\0') return QSC_ERROR_UNSUPPORTED;
    for (i = 0; i < 32; i++) {
        hexstr[2 * i] = hex[commitment[i] >> 4];
        hexstr[2 * i + 1] = hex[commitment[i] & 0x0F];
    }
    hexstr[64] = '\0';
    snprintf(body, sizeof body, "{\"commitment\":\"%s\"}", hexstr);
    snprintf(url, sizeof url, "%s%s", base_url, path);
    memset(resp, 0, sizeof resp);
    if (transport(url, body, resp, sizeof resp - 1) != QSC_OK) return QSC_ERROR_UNSUPPORTED;
    /* Expect {"ok":true}. Anything else, including a revoked key, is a rejection. */
    if (strstr(resp, "\"ok\":true") == NULL) return QSC_ERROR_AUTH_FAILED;
    return QSC_OK;
}

qsc_error_t qsv_cloud_register(const uint8_t commitment[32]) {
    if (!commitment) return QSC_ERROR_INVALID_ARGUMENT;
    return post_commitment("/register", commitment);
}

qsc_error_t qsv_cloud_validate(const uint8_t commitment[32]) {
    if (!commitment) return QSC_ERROR_INVALID_ARGUMENT;
    return post_commitment("/validate", commitment);
}

#else

qsc_error_t qsv_cloud_register(const uint8_t commitment[32]) {
    (void)commitment;
    return QSC_ERROR_UNSUPPORTED; /* cloud layer disabled at build time */
}

qsc_error_t qsv_cloud_validate(const uint8_t commitment[32]) {
    (void)commitment;
    return QSC_ERROR_UNSUPPORTED; /* cloud layer disabled at build time */
}

#endif
