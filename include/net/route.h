/*
 * Public domain
 * net/route.h compatibility shim
 */

#include_next <net/route.h>

#ifndef RTP_NONE
#define RTP_NONE	0
#endif
#ifndef RTP_LOCAL
#define RTP_LOCAL	1
#endif
#ifndef RTP_BGP
#define RTP_BGP		48
#endif
#ifndef RTP_MAX
#define RTP_MAX		63
#endif
#ifndef RTP_ANY
#define RTP_ANY		64
#endif

#ifndef RTLABEL_LEN
#define RTLABEL_LEN	32
#endif
