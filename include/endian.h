/*
 * endian.h compatibility shim
 * Public domain
 */

#ifdef HAVE_ENDIAN_H
#include_next <endian.h>
#else
#include <sys/endian.h>
#endif
