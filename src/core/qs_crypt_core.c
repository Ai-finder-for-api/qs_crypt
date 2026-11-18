/**
 * @file qs_crypt_core.c
 * @brief Library lifecycle, secure memory utilities, allocation shim.
 */
#include "qs_crypt/qs_crypt.h"
#include "qs_crypt_internal.h"
#include <string.h>

static volatile int g_initialized = 0;

int qsc_is_initialized(void) { return g_initialized; }

qsc_error_t qsc_init(void) {
    qs_u8 probe[16];
    if (qsc_os_entropy(probe, sizeof probe) != QSC_OK) return QSC_ERROR_ENTROPY_UNAVAILABLE;
    qsc_secure_zero(probe, sizeof probe);
    qsc_aes_init_tables();
    g_initialized = 1;
    return QSC_OK;
}

void qsc_shutdown(void) { g_initialized = 0; }

void qsc_version(qs_u32* major, qs_u32* minor, qs_u32* patch) {
    if (major) *major = QS_CRYPT_VERSION_MAJOR;
    if (minor) *minor = QS_CRYPT_VERSION_MINOR;
    if (patch) *patch = QS_CRYPT_VERSION_PATCH;
}

const char* qsc_build_info(void) {
    return "QScrypt 0.2.0 (qs_crypt standalone build; experimental XOF is opt-in)";
}

void qsc_secure_zero(void* ptr, qs_u64 size) {
    volatile unsigned char* p = (volatile unsigned char*)ptr;
    while (size--) *p++ = 0;
}

qs_bool_t qsc_constant_time_equal(const qs_u8* a, const qs_u8* b, qs_u64 length) {
    qs_u8 diff = 0;
    if (length == 0) return QS_TRUE;
    if (!a || !b) return QS_FALSE;
    for (qs_u64 i = 0; i < length; i++) diff |= (qs_u8)(a[i] ^ b[i]);
    return diff == 0 ? QS_TRUE : QS_FALSE;
}

void qsc_buffer_free(qsc_buffer_t* buf) {
    if (!buf) return;
    qsc_free_zero(buf->data, (size_t)buf->length);
    buf->data = NULL;
    buf->length = 0;
}
