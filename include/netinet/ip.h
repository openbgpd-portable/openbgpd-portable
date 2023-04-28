/*
 * Public domain
 * netinet/ip.h compatibility shim
 */

#include_next <netinet/ip.h>

#ifndef IPTOS_DSCP_CS0
#define	IPTOS_DSCP_CS0		0x00
#endif
#ifndef IPTOS_DSCP_LE
#define	IPTOS_DSCP_LE		0x04
#endif
#ifndef IPTOS_DSCP_CS1
#define	IPTOS_DSCP_CS1		0x20
#endif
#ifndef IPTOS_DSCP_AF11
#define	IPTOS_DSCP_AF11		0x28
#endif
#ifndef IPTOS_DSCP_AF12
#define	IPTOS_DSCP_AF12		0x30
#endif
#ifndef IPTOS_DSCP_AF13
#define	IPTOS_DSCP_AF13		0x38
#endif
#ifndef IPTOS_DSCP_CS2
#define	IPTOS_DSCP_CS2		0x40
#endif
#ifndef IPTOS_DSCP_AF21
#define	IPTOS_DSCP_AF21		0x48
#endif
#ifndef IPTOS_DSCP_AF22
#define	IPTOS_DSCP_AF22		0x50
#endif
#ifndef IPTOS_DSCP_AF23
#define	IPTOS_DSCP_AF23		0x58
#endif
#ifndef IPTOS_DSCP_CS3
#define	IPTOS_DSCP_CS3		0x60
#endif
#ifndef IPTOS_DSCP_AF31
#define	IPTOS_DSCP_AF31		0x68
#endif
#ifndef IPTOS_DSCP_AF32
#define	IPTOS_DSCP_AF32		0x70
#endif
#ifndef IPTOS_DSCP_AF33
#define	IPTOS_DSCP_AF33		0x78
#endif
#ifndef IPTOS_DSCP_CS4
#define	IPTOS_DSCP_CS4		0x80
#endif
#ifndef IPTOS_DSCP_AF41
#define	IPTOS_DSCP_AF41		0x88
#endif
#ifndef IPTOS_DSCP_AF42
#define	IPTOS_DSCP_AF42		0x90
#endif
#ifndef IPTOS_DSCP_AF43
#define	IPTOS_DSCP_AF43		0x98
#endif
#ifndef IPTOS_DSCP_CS5
#define	IPTOS_DSCP_CS5		0xa0
#endif
#ifndef IPTOS_DSCP_EF
#define	IPTOS_DSCP_EF		0xb8
#endif
#ifndef IPTOS_DSCP_CS6
#define	IPTOS_DSCP_CS6		0xc0
#endif
#ifndef IPTOS_DSCP_CS7
#define	IPTOS_DSCP_CS7		0xe0
#endif
