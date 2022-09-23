/*
 * Public domain
 * net/if.h compatibility shim
 */

#ifndef HAVE_LINUX_IF_H
#include_next <net/if.h>
#else
#include_next <linux/if.h>
#endif
