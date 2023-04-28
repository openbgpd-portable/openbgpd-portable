/*
 * Public domain
 * netinet/icmp6.h compatibility shim
 */

#include_next <netinet/icmp6.h>

#ifndef ICMP6_MEMBERSHIP_QUERY
#define ICMP6_MEMBERSHIP_QUERY		130	/* group membership query */
#endif
#ifndef ICMP6_MEMBERSHIP_REPORT
#define ICMP6_MEMBERSHIP_REPORT		131	/* group membership report */
#endif
#ifndef ICMP6_MEMBERSHIP_REDUCTION
#define ICMP6_MEMBERSHIP_REDUCTION	132	/* group membership termination */
#endif
#ifndef ICMP6_ROUTER_RENUMBERING
#define ICMP6_ROUTER_RENUMBERING	138	/* router renumbering */
#endif
#ifndef ICMP6_WRUREQUEST
#define ICMP6_WRUREQUEST		139	/* who are you request */
#endif
#ifndef ICMP6_WRUREPLY
#define ICMP6_WRUREPLY			140	/* who are you reply */
#endif
#ifndef ICMP6_FQDN_QUERY
#define ICMP6_FQDN_QUERY		139	/* FQDN query */
#endif
#ifndef ICMP6_FQDN_REPLY
#define ICMP6_FQDN_REPLY		140	/* FQDN reply */
#endif
#ifndef ICMP6_NI_QUERY
#define ICMP6_NI_QUERY			139	/* node information request */
#endif
#ifndef ICMP6_NI_REPLY
#define ICMP6_NI_REPLY			140	/* node information reply */
#endif
#ifndef MLD_LISTENER_DONE
#define MLD_LISTENER_DONE		132	/* multicast listener done */
#endif
#ifndef MLDV2_LISTENER_REPORT
#define MLDV2_LISTENER_REPORT		143	/* RFC3810 listener report */
#endif
#ifndef MLD_MTRACE_RESP
#define MLD_MTRACE_RESP			200	/* mtrace response(to sender) */
#endif
#ifndef MLD_MTRACE
#define MLD_MTRACE			201	/* mtrace messages */
#endif
#ifndef ND_REDIRECT_ONLINK
#define ND_REDIRECT_ONLINK	0	/* redirect to an on-link node */
#endif
#ifndef ND_REDIRECT_ROUTER
#define ND_REDIRECT_ROUTER	1	/* redirect to a better router */
#endif
