/*
 * Public domain
 * linux/rtnetlink.h compatibility shim
 */

#include_next <linux/rtnetlink.h>

#ifndef LIBCOMPAT_LINUX_RTNETLINK_H
#define LIBCOMPAT_LINUX_RTNETLINK_H

#ifndef RTPROT_BGP
#define RTPROT_BGP		186	/* BGP Routes */
#endif

#endif
