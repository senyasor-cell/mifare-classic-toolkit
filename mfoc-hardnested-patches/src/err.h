/*
 * err.h — минимальная совместимость для MinGW-w64.
 * Реализует BSD-функции err/errx/warn/warnx через fprintf и exit.
 */
#ifndef _MFOC_ERR_H_SHIM
#define _MFOC_ERR_H_SHIM

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

static inline void warn(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "warning: ");
    vfprintf(stderr, fmt, ap);
    if (errno) fprintf(stderr, ": %s", strerror(errno));
    fprintf(stderr, "\n");
    va_end(ap);
}

static inline void warnx(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "warning: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

static inline void err(int eval, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "error: ");
    vfprintf(stderr, fmt, ap);
    if (errno) fprintf(stderr, ": %s", strerror(errno));
    fprintf(stderr, "\n");
    va_end(ap);
    exit(eval);
}

static inline void errx(int eval, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "error: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(eval);
}

#ifdef __cplusplus
}
#endif

#endif /* _MFOC_ERR_H_SHIM */
