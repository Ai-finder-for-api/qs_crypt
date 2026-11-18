/**
 * @file test_cloudstore.c
 * @brief Tests for cloud backup and restore, using an in-memory stand-in for the server.
 *        Runs in both builds; it does not touch the network.
 */
#include "qsv_cloudstore.h"
#include "qsv_core.h"
#include "qsv_cloud.h"
#include "qsv_config.h"
#include "qs_crypt/qs_crypt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* In the cloud build, encrypt and decrypt also register and validate commitments. Those calls go
 * through the transport, so this test supplies one that always accepts. */
static qsc_error_t fake_cloud_transport(const char* url, const char* body, char* resp, size_t cap) {
    (void)url;
    (void)body;
    snprintf(resp, cap, "{\"ok\":true}");
    return QSC_OK;
}

static int failures = 0;
#define CHECK(c) do { if (!(c)) { failures++; fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)

#define TIMESTAMP "2026-10-20T10:00:00Z"
static char g_body[80000];
static int  g_has = 0;

/* Pulls the string value of a key out of a flat JSON body. Returns 1 on success. */
static int field(const char* json, const char* key, char* out, size_t cap) {
    char pat[32];
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

/* Fake server: one slot per id. /put stores the body; /get returns it only for the same id. */
static qsc_error_t fake_call(const char* path, const char* body, char* resp, size_t cap) {
    char req_id[32], stored_id[32], blob[70000];
    if (strcmp(path, "/put") == 0) {
        if (!field(body, "id", req_id, sizeof req_id)) return QSC_ERROR_UNSUPPORTED;
        if (g_has) { snprintf(resp, cap, "{\"ok\":false,\"error\":\"exists\"}"); return QSC_OK; }
        strncpy(g_body, body, sizeof g_body - 1);
        g_body[sizeof g_body - 1] = '\0';
        g_has = 1;
        snprintf(resp, cap, "{\"ok\":true,\"created_at\":\"%s\"}", TIMESTAMP);
        return QSC_OK;
    }
    if (strcmp(path, "/get") == 0) {
        if (!field(body, "id", req_id, sizeof req_id)) return QSC_ERROR_UNSUPPORTED;
        if (!g_has || !field(g_body, "id", stored_id, sizeof stored_id) || strcmp(stored_id, req_id) != 0) {
            snprintf(resp, cap, "{\"ok\":false,\"error\":\"not_found\"}");
            return QSC_OK;
        }
        if (!field(g_body, "blob", blob, sizeof blob)) return QSC_ERROR_UNSUPPORTED;
        snprintf(resp, cap, "{\"ok\":true,\"created_at\":\"%s\",\"blob\":\"%s\"}", TIMESTAMP, blob);
        return QSC_OK;
    }
    return QSC_ERROR_UNSUPPORTED;
}

static void test_cloudkey_format(void) {
    uint8_t ck[QSV_CS_CLOUDKEY_BYTES], bad[QSV_CS_CLOUDKEY_BYTES];
    char id[QSV_CS_ID_LEN + 1];
    uint8_t secret[32];
    CHECK(QSV_CS_CLOUDKEY_BYTES == 60);
    CHECK(qsv_cs_cloudkey_make(ck) == QSC_OK);
    CHECK(qsv_cs_cloudkey_parse(ck, sizeof ck, id, secret) == QSC_OK);
    CHECK(strlen(id) == QSV_CS_ID_LEN && strncmp(id, "key-", 4) == 0);

    memcpy(bad, ck, sizeof bad);
    bad[0] ^= 0xFF;
    CHECK(qsv_cs_cloudkey_parse(bad, sizeof bad, id, secret) == QSC_ERROR_MALFORMED_DATA);

    memcpy(bad, ck, sizeof bad);
    bad[12] = 'Z';
    CHECK(qsv_cs_cloudkey_parse(bad, sizeof bad, id, secret) == QSC_ERROR_MALFORMED_DATA);

    CHECK(qsv_cs_cloudkey_parse(ck, sizeof ck - 1, id, secret) == QSC_ERROR_MALFORMED_DATA);
}

static void test_backup_restore(void) {
    uint8_t cloud[QSV_CS_CLOUDKEY_BYTES], ckey[40], back[40];
    uint8_t kf[QSV_KEYFILE_BYTES];
    char created[QSV_CS_TIME_MAX] = "";
    char created2[QSV_CS_TIME_MAX] = "";
    const char* pw = "correct horse battery";
    g_has = 0;

    CHECK(qsv_cs_cloudkey_make(cloud) == QSC_OK);
    CHECK(qsv_keyfile_make(kf) == QSC_OK);
    memcpy(ckey, kf, 40);

    CHECK(qsv_cs_backup(fake_call, cloud, sizeof cloud, (const uint8_t*)pw, strlen(pw), ckey, 1000, created)
          == QSC_OK);
    CHECK(strcmp(created, TIMESTAMP) == 0);

    CHECK(qsv_cs_restore(fake_call, cloud, sizeof cloud, (const uint8_t*)pw, strlen(pw), back, created2)
          == QSC_OK);
    CHECK(memcmp(back, ckey, 40) == 0);
    CHECK(strcmp(created2, TIMESTAMP) == 0);

    /* Wrong password. */
    CHECK(qsv_cs_restore(fake_call, cloud, sizeof cloud, (const uint8_t*)"wrong password!!", 16, back, created2)
          == QSC_ERROR_AUTH_FAILED);

    /* A different cloud key: different id, so nothing is stored under it. */
    {
        uint8_t other[QSV_CS_CLOUDKEY_BYTES];
        CHECK(qsv_cs_cloudkey_make(other) == QSC_OK);
        CHECK(qsv_cs_restore(fake_call, other, sizeof other, (const uint8_t*)pw, strlen(pw), back, created2)
              == QSC_ERROR_INVALID_KEY);
    }

    /* Same id, wrong secret: the key-id check catches it before any decryption is attempted. */
    {
        uint8_t forged[QSV_CS_CLOUDKEY_BYTES];
        memcpy(forged, cloud, sizeof forged);
        forged[40] ^= 0x01;
        CHECK(qsv_cs_restore(fake_call, forged, sizeof forged, (const uint8_t*)pw, strlen(pw), back, created2)
              == QSC_ERROR_INVALID_KEY);
    }

    /* A second backup under the same id is refused. */
    CHECK(qsv_cs_backup(fake_call, cloud, sizeof cloud, (const uint8_t*)pw, strlen(pw), ckey, 1000, created)
          == QSC_ERROR_AUTH_FAILED);
}

static void test_index(void) {
    const char* path = "build/test_cloud_index.txt";
    const char* id = "key-0123456789abcdef";
    remove(path);
    CHECK(qsv_cs_index_check(path, id, TIMESTAMP) == 0);      /* no file: new machine */
    CHECK(qsv_cs_index_write(path, id, TIMESTAMP) == QSC_OK);
    CHECK(qsv_cs_index_check(path, id, TIMESTAMP) == 0);      /* matches */
    CHECK(qsv_cs_index_check(path, id, "2020-01-01T00:00:00Z") == 1); /* differs */
    CHECK(qsv_cs_index_check(path, "key-ffffffffffffffff", "x") == 0); /* other key: no entry */
    CHECK(qsv_cs_index_write(path, id, "2027-01-01T00:00:00Z") == QSC_OK); /* rewrite replaces the line */
    CHECK(qsv_cs_index_check(path, id, "2027-01-01T00:00:00Z") == 0);
    remove(path);
}

int main(void) {
    if (qsc_init() != QSC_OK) { fprintf(stderr, "init failed\n"); return 2; }
#if QSV_CLOUD_ENABLED
    qsv_cloud_set_transport(fake_cloud_transport, "https://test.invalid/qsv");
#endif
    test_cloudkey_format();
    test_backup_restore();
    test_index();
    if (failures) {
        fprintf(stderr, "cloudstore tests: %d failures\n", failures);
        return 1;
    }
    printf("cloudstore tests: all passed\n");
    return 0;
}
