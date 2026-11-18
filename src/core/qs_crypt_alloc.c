/**
 * @file qs_crypt_alloc.c
 * @brief QScrypt-local memory pool. Does NOT depend on qs_memory.
 *
 * Design:
 *   - Small requests (<= 4096 B) come from power-of-two size classes (16..4096 B).
 *     Each class has a free list. Slabs of 64 KiB are obtained from the system
 *     allocator and are never returned to it before process exit.
 *   - Large requests (> 4096 B) go straight to the system allocator.
 *   - Every block has a 16-byte header {magic, class, size}. Free() validates the
 *     magic, so invalid and double frees are detected (not all of them: a stale
 *     pointer whose block was re-issued can still slip through).
 *   - Freed memory is zeroized before it is reused.
 *   - All operations are serialized by a lock (SRWLOCK on Windows, pthread mutex
 *     on POSIX). Lock-free use from multiple threads is not supported.
 *
 * Counters (qsc_alloc_stats) let tests assert there are no leaks.
 */
#include "qs_crypt_internal.h"
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
  #ifndef WIN32_LEAN_AND_MEAN
  #define WIN32_LEAN_AND_MEAN
  #endif
  #include <windows.h>
  static SRWLOCK g_alloc_lock = SRWLOCK_INIT;
  #define QSC_LOCK()   AcquireSRWLockExclusive(&g_alloc_lock)
  #define QSC_UNLOCK() ReleaseSRWLockExclusive(&g_alloc_lock)
#elif defined(__unix__) || defined(__APPLE__)
  #include <pthread.h>
  static pthread_mutex_t g_alloc_lock = PTHREAD_MUTEX_INITIALIZER;
  #define QSC_LOCK()   pthread_mutex_lock(&g_alloc_lock)
  #define QSC_UNLOCK() pthread_mutex_unlock(&g_alloc_lock)
#else
  #define QSC_LOCK()
  #define QSC_UNLOCK()
#endif

#define QSC_HDR_SIZE     16u
#define QSC_MAGIC_LIVE   0x51534D31u   /* 'QSM1' */
#define QSC_MAGIC_FREE   0x51534D30u   /* 'QSM0' */
#define QSC_CLASS_COUNT  9u            /* usable 16 << k, k = 0..8  ->  16 .. 4096 */
#define QSC_SMALL_MAX    4096u
#define QSC_SLAB_BYTES   (64u * 1024u)
#define QSC_SLAB_MAX     4096u         /* pool ceiling: 256 MiB of slabs */
#define QSC_CLASS_LARGE  0xFFFFu

typedef struct {
    uint32_t magic;
    uint32_t cls;
    uint64_t size;   /* bytes requested by the caller */
} qsc_alloc_hdr;

_Static_assert(sizeof(qsc_alloc_hdr) == QSC_HDR_SIZE, "allocator header must be 16 bytes");

static void*  g_free_list[QSC_CLASS_COUNT];
static void*  g_slabs[QSC_SLAB_MAX];
static size_t g_slab_count;
static size_t g_live_blocks;
static size_t g_live_bytes;
static size_t g_invalid_frees;

static unsigned class_for(size_t n) {
    unsigned k = 0;
    size_t c = 16;
    while (c < n) { c <<= 1; k++; }
    return k;
}

/* Carve a fresh slab into blocks of the given class. Caller holds the lock. */
static int refill(unsigned k) {
    size_t usable = (size_t)16 << k;
    size_t block  = QSC_HDR_SIZE + usable;
    size_t count  = QSC_SLAB_BYTES / block;
    uint8_t* slab;
    if (g_slab_count >= QSC_SLAB_MAX) return 0;
    slab = (uint8_t*)malloc(QSC_SLAB_BYTES);
    if (!slab) return 0;
    g_slabs[g_slab_count++] = slab;
    for (size_t i = count; i-- > 0; ) {
        qsc_alloc_hdr* h = (qsc_alloc_hdr*)(slab + i * block);
        h->magic = QSC_MAGIC_FREE;
        h->cls = k;
        h->size = 0;
        *(void**)(h + 1) = g_free_list[k];
        g_free_list[k] = h;
    }
    return 1;
}

void* qsc_alloc(size_t n) {
    qsc_alloc_hdr* h = NULL;
    void* out = NULL;
    if (n == 0) n = 1;
    QSC_LOCK();
    if (n <= QSC_SMALL_MAX) {
        unsigned k = class_for(n);
        size_t usable = (size_t)16 << k;
        if (!g_free_list[k] && !refill(k)) goto done;
        h = (qsc_alloc_hdr*)g_free_list[k];
        g_free_list[k] = *(void**)(h + 1);
        memset(h + 1, 0, usable);
        h->magic = QSC_MAGIC_LIVE;
        h->cls = k;
        h->size = n;
    } else {
        h = (qsc_alloc_hdr*)malloc(sizeof *h + n);
        if (!h) goto done;
        h->magic = QSC_MAGIC_LIVE;
        h->cls = QSC_CLASS_LARGE;
        h->size = n;
        memset(h + 1, 0, n);
    }
    g_live_blocks++;
    g_live_bytes += n;
    out = h + 1;
done:
    QSC_UNLOCK();
    return out;
}

void qsc_free_zero(void* p, size_t n) {
    qsc_alloc_hdr* h;
    (void)n;
    if (!p) return;
    QSC_LOCK();
    h = (qsc_alloc_hdr*)p - 1;
    if (h->magic != QSC_MAGIC_LIVE) {
        g_invalid_frees++;
        QSC_UNLOCK();
        return;
    }
    {
        size_t wipe = (h->cls == QSC_CLASS_LARGE) ? (size_t)h->size : ((size_t)16 << h->cls);
        volatile unsigned char* v = (volatile unsigned char*)p;
        while (wipe--) *v++ = 0;
    }
    g_live_blocks--;
    g_live_bytes -= (size_t)h->size;
    h->magic = QSC_MAGIC_FREE;
    if (h->cls == QSC_CLASS_LARGE) {
        free(h);
    } else {
        unsigned k = h->cls;
        *(void**)(h + 1) = g_free_list[k];
        g_free_list[k] = h;
    }
    QSC_UNLOCK();
}

void qsc_alloc_stats(size_t* live_blocks, size_t* live_bytes, size_t* invalid_frees) {
    QSC_LOCK();
    if (live_blocks)    *live_blocks = g_live_blocks;
    if (live_bytes)     *live_bytes = g_live_bytes;
    if (invalid_frees)  *invalid_frees = g_invalid_frees;
    QSC_UNLOCK();
}
