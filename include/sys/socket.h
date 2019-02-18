/*
 * Public domain
 * sys/socket.h compatibility shim
 */

#include_next <sys/socket.h>

#ifndef HAVE_GETRTABLE
int getrtable(void);
#endif

#ifndef RT_TABLEID_MAX
#define RT_TABLEID_MAX	255
#endif
