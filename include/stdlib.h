/*
 * stdlib.h compatibility shim
 * Public domain
 */

#include_next <stdlib.h>

#ifndef LIBCOMPAT_STDLIB_H
#define LIBCOMPAT_STDLIB_H

#include <stdint.h>

#ifndef HAVE_ARC4RANDOM_
uint32_t arc4random(void);
uint32_t arc4random_uniform(uint32_t);
void arc4random_buf(void *, size_t);
#endif

#ifndef HAVE_DAEMON
int daemon(int, int);
#endif

#ifndef HAVE_FREEZERO
void freezero(void *, size_t);
#endif

#ifndef HAVE_REALLOCARRAY
void *reallocarray(void *, size_t, size_t);
#endif

#ifndef HAVE_RECALLOCARRAY
void *recallocarray(void *, size_t, size_t, size_t);
#endif

#ifndef HAVE_SETPROCTITLE
void compat_init_setproctitle(int, char *[]);
void setproctitle(const char *, ...);
#endif

#ifndef HAVE_STRTONUM
long long strtonum(const char *, long long, long long, const char **);
#endif

#endif
