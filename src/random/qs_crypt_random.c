/**
 * @file qs_crypt_random.c
 * @brief OS-entropy CSPRNG. Failure is always reported; there is no fallback.
 *
 * Linux:   getrandom(2)
 * Windows: BCryptGenRandom with the system-preferred RNG (link: bcrypt)
 * Other POSIX: /dev/urandom
 */
#include "qs_crypt/qs_crypt.h"
#include "../core/qs_crypt_internal.h"

#if defined(_WIN32)
  #ifndef WIN32_LEAN_AND_MEAN
  #define WIN32_LEAN_AND_MEAN
  #endif
  #include <windows.h>
  #include <bcrypt.h>
#else
  #include <errno.h>
  #include <stdio.h>
  #include <sys/types.h>
  #if defined(__linux__)
    #include <sys/random.h>
  #endif
#endif

qsc_error_t qsc_os_entropy(qs_u8* out, qs_u64 length) {
    if (!out || length == 0) return QSC_ERROR_INVALID_ARGUMENT;
#if defined(_WIN32)
    {
        qs_u64 off = 0;
        while (off < length) {
            qs_u64 chunk = length - off;
            if (chunk > 0x7FFFFFFFu) chunk = 0x7FFFFFFFu;
            if (BCryptGenRandom(NULL, out + off, (ULONG)chunk,
                                BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
                return QSC_ERROR_ENTROPY_UNAVAILABLE;
            off += chunk;
        }
        return QSC_OK;
    }
#elif defined(__linux__)
    {
        qs_u64 off = 0;
        while (off < length) {
            ssize_t r = getrandom(out + off, (size_t)(length - off), 0);
            if (r < 0) {
                if (errno == EINTR) continue;
                return QSC_ERROR_ENTROPY_UNAVAILABLE;
            }
            if (r == 0) return QSC_ERROR_ENTROPY_UNAVAILABLE;
            off += (qs_u64)r;
        }
        return QSC_OK;
    }
#elif defined(__unix__) || defined(__APPLE__)
    {
        FILE* f = fopen("/dev/urandom", "rb");
        size_t got;
        if (!f) return QSC_ERROR_ENTROPY_UNAVAILABLE;
        got = fread(out, 1, (size_t)length, f);
        fclose(f);
        return (got == (size_t)length) ? QSC_OK : QSC_ERROR_ENTROPY_UNAVAILABLE;
    }
#else
    (void)out; (void)length;
    return QSC_ERROR_ENTROPY_UNAVAILABLE;
#endif
}

qsc_error_t qsc_rng_create(qsc_rng_t** rng) {
    qsc_rng_t* r;
    qs_u8 probe[8];
    if (!rng) return QSC_ERROR_INVALID_ARGUMENT;
    if (qsc_os_entropy(probe, sizeof probe) != QSC_OK) return QSC_ERROR_ENTROPY_UNAVAILABLE;
    r = (qsc_rng_t*)qsc_alloc(sizeof(qsc_rng_t));
    if (!r) return QSC_ERROR_OOM;
    r->magic = 0x51534352u; /* 'QSCR' */
    *rng = r;
    return QSC_OK;
}

void qsc_rng_destroy(qsc_rng_t* rng) {
    if (rng) qsc_free_zero(rng, sizeof(qsc_rng_t));
}

qsc_error_t qsc_rng_fill(qsc_rng_t* rng, qs_u8* out, qs_u64 length) {
    if (!rng || rng->magic != 0x51534352u) return QSC_ERROR_NOT_INITIALIZED;
    return qsc_os_entropy(out, length);
}

qsc_error_t qsc_random_bytes(qs_u8* out, qs_u64 length) {
    if (!qsc_is_initialized()) return QSC_ERROR_NOT_INITIALIZED;
    return qsc_os_entropy(out, length);
}
