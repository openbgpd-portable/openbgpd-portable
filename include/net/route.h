/*
 * Public domain
 * net/route.h compatibility shim
 */

#include_next <net/route.h>

#ifndef RTLABEL_LEN
#define RTLABEL_LEN	32
#endif
