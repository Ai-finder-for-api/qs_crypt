/**
 * @file qs_types.h
 * @brief LOCAL STAND-IN for core/qs_types.h, used only so qs_crypt builds standalone.
 * In the monorepo, the real core/qs_types.h is used and this file is NOT on the include path.
 * Mirrors the names and widths from the master architecture document, Section 15.
 */
#ifndef QS_TYPES_H
#define QS_TYPES_H
typedef unsigned long long qs_u64;
typedef long long          qs_i64;
typedef unsigned int       qs_u32;
typedef int                qs_i32;
typedef unsigned char      qs_u8;
typedef float              qs_f32;
typedef double             qs_f64;
typedef enum { QS_FALSE = 0, QS_TRUE = 1 } qs_bool_t;
typedef enum {
    QS_OK = 0, QS_ERROR_OOM, QS_ERROR_INVALID_ARGUMENT, QS_ERROR_NOT_FOUND,
    QS_ERROR_IO, QS_ERROR_CORRUPTED, QS_ERROR_UNSUPPORTED
} qs_result_t;
#endif
