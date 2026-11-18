/**
 * @file qsv_cloudstore.c
 * @brief Cloud backup and restore of .qs.ckey files. See qsv_cloudstore.h.
 */
#include "qsv_cloudstore.h"
#include "qsv_core.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t CLOUDKEY_MAGIC[8] = { 'Q', 'S', 'C', 'L', 'D', '0', '0', '2' };
static const char    B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#define CKEY_BYTES 40u
#define RESP_MAX   (96u * 1024u)
#define BLOB_MAX   (64u * 1024u)

/* ---- base64 ------------------------------------------------------------------ */

static char* b64_encode(const uint8_t* in, size_t n) {
    size_t outl = 4 * ((n + 2) / 3);
    char* out = (char*)malloc(outl + 1);
    size_t i = 0, o = 0;
    if (!out) return NULL;
    for (; i + 2 < n; i += 3) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) | (uint32_t)in[i + 2];
        out[o++] = B64[(v >> 18) & 63u];
        out[o++] = B64[(v >> 12) & 63u];
        out[o++] = B64[(v >> 6) & 63u];
        out[o++] = B64[v & 63u];
    }
    if (i < n) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (i + 1 < n) v |= (uint32_t)in[i + 1] << 8;
        out[o++] = B64[(v >> 18) & 63u];
        out[o++] = B64[(v >> 12) & 63u];
        out[o++] = (i + 1 < n) ? B64[(v >> 6) & 63u] : '=';
        out[o++] = '=';
    }
    out[o] = '\0';
    return out;
}

static int b64_val(char c) {
    const char* p;
    if (c == '\0') return -1;
    p = strchr(B64, c);
    return p ? (int)(p - B64) : -1;
}

static uint8_t* b64_decode(const char* s, size_t* outl) {
    size_t n = strlen(s), i, o = 0;
    uint8_t* out;
    if (n == 0 || (n % 4) != 0) return NULL;
    out = (uint8_t*)malloc(n / 4 * 3 + 1);
    if (!out) return NULL;
    for (i = 0; i < n; i += 4) {
        int a = b64_val(s[i]);
        int b = b64_val(s[i + 1]);
        int c = (s[i + 2] == '=') ? 0 : b64_val(s[i + 2]);
        int d = (s[i + 3] == '=') ? 0 : b64_val(s[i + 3]);
        if (a < 0 || b < 0 || c < 0 || d < 0) { free(out); return NULL; }
        out[o++] = (uint8_t)((a << 2) | (b >> 4));
        if (s[i + 2] != '=') out[o++] = (uint8_t)(((b & 15) << 4) | (c >> 2));
        if (s[i + 3] != '=') out[o++] = (uint8_t)(((c & 3) << 6) | d);
    }
    *outl = o;
    return out;
}

/* ---- flat JSON string fields ------------------------------------------------- */

/* Copies the string value of "key" from a flat JSON object. Returns 1 if found and it fits. */
static int json_str(const char* json, const char* key, char* out, size_t cap) {
    char pat[64];
    const char* p;
    const char* e;
    size_t n;
    snprintf(pat, sizeof pat, "\"%s\":\"", key);
    p = strstr(json, pat);
    if (!p) return 0;
    p += strlen(pat);
    e = strchr(p, '"');
    if (!e) return 0;
    n = (size_t)(e - p);
    if (n + 1 > cap) return 0;
    memcpy(out, p, n);
    out[n] = '\0';
    return 1;
}

/* ---- cloud key file ---------------------------------------------------------- */

qsc_error_t qsv_cs_cloudkey_make(uint8_t out[QSV_CS_CLOUDKEY_BYTES]) {
    uint8_t rnd[8];
    char hex[17];
    size_t i;
    qsc_error_t e;
    if (!out) return QSC_ERROR_INVALID_ARGUMENT;
    e = qsc_random_bytes(rnd, sizeof rnd);
    if (e != QSC_OK) return e;
    for (i = 0; i < 8; i++) {
        static const char digits[] = "0123456789abcdef";
        hex[2 * i] = digits[rnd[i] >> 4];
        hex[2 * i + 1] = digits[rnd[i] & 15];
    }
    hex[16] = '\0';
    memcpy(out, CLOUDKEY_MAGIC, 8);
    memcpy(out + 8, "key-", 4);
    memcpy(out + 12, hex, 16);
    qsc_secure_zero(rnd, sizeof rnd);
    return qsc_random_bytes(out + 28, 32);
}

qsc_error_t qsv_cs_cloudkey_parse(const uint8_t* in, size_t inl,
                                  char id[QSV_CS_ID_LEN + 1], uint8_t secret[32]) {
    size_t i;
    if (!in || !id || !secret || inl != QSV_CS_CLOUDKEY_BYTES) return QSC_ERROR_MALFORMED_DATA;
    if (memcmp(in, CLOUDKEY_MAGIC, 8) != 0 || memcmp(in + 8, "key-", 4) != 0)
        return QSC_ERROR_MALFORMED_DATA;
    for (i = 0; i < 16; i++) {
        char c = (char)in[12 + i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return QSC_ERROR_MALFORMED_DATA;
    }
    memcpy(id, in + 8, QSV_CS_ID_LEN);
    id[QSV_CS_ID_LEN] = '\0';
    memcpy(secret, in + 28, 32);
    return QSC_OK;
}

/* ---- backup and restore ------------------------------------------------------ */

qsc_error_t qsv_cs_backup(qsv_cs_call_fn call,
                          const uint8_t* cloudkey, size_t cloudkey_len,
                          const uint8_t* password, size_t password_len,
                          const uint8_t ckey[40], uint32_t iterations,
                          char created[QSV_CS_TIME_MAX]) {
    char id[QSV_CS_ID_LEN + 1];
    uint8_t secret[32];
    qsv_secrets_t s;
    uint8_t* blob = NULL;
    size_t bl = 0;
    char* b64 = NULL;
    char* body = NULL;
    char* resp = NULL;
    size_t bodylen = 0;
    qsc_error_t e;

    e = qsv_cs_cloudkey_parse(cloudkey, cloudkey_len, id, secret);
    if (e != QSC_OK) return e;
    if (!call || !password || password_len == 0 || !ckey || !created) {
        e = QSC_ERROR_INVALID_ARGUMENT;
        goto done;
    }

    memset(&s, 0, sizeof s);
    s.password = password;
    s.password_len = password_len;
    s.ckey = secret;
    s.iterations = iterations;
    e = qsv_encrypt(&s, ckey, CKEY_BYTES, &blob, &bl);
    if (e != QSC_OK) goto done;

    b64 = b64_encode(blob, bl);
    if (!b64) { e = QSC_ERROR_OOM; goto done; }
    if (strlen(b64) > BLOB_MAX) { e = QSC_ERROR_OUTPUT_SIZE_MISMATCH; goto done; }

    bodylen = strlen(b64) + QSV_CS_ID_LEN + 64;
    body = (char*)malloc(bodylen);
    resp = (char*)malloc(RESP_MAX);
    if (!body || !resp) { e = QSC_ERROR_OOM; goto done; }
    snprintf(body, bodylen, "{\"id\":\"%s\",\"blob\":\"%s\"}", id, b64);

    memset(resp, 0, RESP_MAX);
    e = call("/put", body, resp, RESP_MAX);
    if (e != QSC_OK) goto done;
    if (strstr(resp, "\"ok\":true") == NULL) { e = QSC_ERROR_AUTH_FAILED; goto done; }
    if (!json_str(resp, "created_at", created, QSV_CS_TIME_MAX)) { e = QSC_ERROR_MALFORMED_DATA; goto done; }
    e = QSC_OK;

done:
    if (blob) qsv_free(blob, bl);
    if (b64) { qsc_secure_zero(b64, strlen(b64)); free(b64); }
    if (body) { qsc_secure_zero(body, bodylen); free(body); }
    if (resp) free(resp);
    qsc_secure_zero(secret, sizeof secret);
    return e;
}

qsc_error_t qsv_cs_restore(qsv_cs_call_fn call,
                           const uint8_t* cloudkey, size_t cloudkey_len,
                           const uint8_t* password, size_t password_len,
                           uint8_t ckey[40], char created[QSV_CS_TIME_MAX]) {
    char id[QSV_CS_ID_LEN + 1];
    uint8_t secret[32];
    char body[96];
    char* resp = NULL;
    char* b64 = NULL;
    uint8_t* blob = NULL;
    size_t bl = 0;
    uint8_t* plain = NULL;
    size_t pl = 0;
    qsv_secrets_t s;
    qsc_error_t e;

    e = qsv_cs_cloudkey_parse(cloudkey, cloudkey_len, id, secret);
    if (e != QSC_OK) return e;
    if (!call || !password || password_len == 0 || !ckey || !created) {
        e = QSC_ERROR_INVALID_ARGUMENT;
        goto done;
    }

    snprintf(body, sizeof body, "{\"id\":\"%s\"}", id);
    resp = (char*)malloc(RESP_MAX);
    b64 = (char*)malloc(RESP_MAX);
    if (!resp || !b64) { e = QSC_ERROR_OOM; goto done; }
    memset(resp, 0, RESP_MAX);

    e = call("/get", body, resp, RESP_MAX);
    if (e != QSC_OK) goto done;
    /* Not found and any other refusal both come back without "ok":true. */
    if (strstr(resp, "\"ok\":true") == NULL) { e = QSC_ERROR_INVALID_KEY; goto done; }
    if (!json_str(resp, "created_at", created, QSV_CS_TIME_MAX) ||
        !json_str(resp, "blob", b64, RESP_MAX)) {
        e = QSC_ERROR_MALFORMED_DATA;
        goto done;
    }

    blob = b64_decode(b64, &bl);
    if (!blob) { e = QSC_ERROR_MALFORMED_DATA; goto done; }

    memset(&s, 0, sizeof s);
    s.password = password;
    s.password_len = password_len;
    s.ckey = secret;
    e = qsv_decrypt(&s, NULL, blob, bl, &plain, &pl);
    if (e != QSC_OK) goto done;
    if (pl != CKEY_BYTES) { e = QSC_ERROR_MALFORMED_DATA; goto done; }
    memcpy(ckey, plain, CKEY_BYTES);
    e = QSC_OK;

done:
    if (plain) qsv_free(plain, pl);
    if (blob) qsv_free(blob, bl);
    if (b64) { qsc_secure_zero(b64, RESP_MAX); free(b64); }
    if (resp) free(resp);
    qsc_secure_zero(secret, sizeof secret);
    return e;
}

/* ---- local index ------------------------------------------------------------- */

int qsv_cs_index_check(const char* path, const char* id, const char* created) {
    FILE* f = fopen(path, "r");
    char line[256];
    if (!f) return 0; /* no index yet: this is a new machine */
    while (fgets(line, sizeof line, f)) {
        char lid[64], lts[64];
        if (sscanf(line, "%63s %63s", lid, lts) == 2 && strcmp(lid, id) == 0) {
            fclose(f);
            return strcmp(lts, created) == 0 ? 0 : 1;
        }
    }
    fclose(f);
    return 0;
}

qsc_error_t qsv_cs_index_write(const char* path, const char* id, const char* created) {
    char tmp[512];
    char line[256];
    FILE* in;
    FILE* out;
    snprintf(tmp, sizeof tmp, "%s.new", path);
    out = fopen(tmp, "w");
    if (!out) return QSC_ERROR_UNSUPPORTED;
    in = fopen(path, "r");
    if (in) {
        while (fgets(line, sizeof line, in)) {
            char lid[64], lts[64];
            if (sscanf(line, "%63s %63s", lid, lts) == 2 && strcmp(lid, id) == 0) continue;
            fputs(line, out);
        }
        fclose(in);
    }
    fprintf(out, "%s %s\n", id, created);
    fclose(out);
    remove(path);
    if (rename(tmp, path) != 0) return QSC_ERROR_UNSUPPORTED;
    return QSC_OK;
}
