/*
 * Public domain
 * net/if.h compatibility shim
 */

#include_next <net/if.h>

#ifdef HAVE_LINUX_IF_H
#include <linux/if.h>
#endif
