/*
 * Public domain
 * netinet/ip_ipsp.h compatibility shim
 */

#ifdef HAVE_NETINET_IP_IPSP_H
#include_next <netinet/ip_ipsp.h>
#else
#define SPI_RESERVED_MAX	255
#endif
