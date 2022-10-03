/*
 * Public domain
 * netinet/in.h compatibility shim
 */

#include_next <netinet/in.h>

#ifdef HAVE_LINUX_IN6_H
#include <net/if.h>
#include <linux/in6.h>
#endif

#ifndef HAVE_INET_NET_PTON
int	inet_net_pton(int, const char *, void *, size_t);
#endif
