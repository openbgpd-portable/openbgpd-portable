/*
 * Public domain
 * netinet/in.h compatibility shim
 */

#include_next <netinet/in.h>

#ifdef HAVE_LINUX_IN6_H
#include <linux/in6.h>
#endif
