/*	$OpenBSD$ */

/*
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
 * Copyright (c) 2019 Claudio Jeker <claudio@openbsd.org>
 * Copyright (c) 2021 Ariadne Conill <ariadne@dereferenced.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <sys/tree.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <libmnl/libmnl.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>

#include "bgpd.h"
#include "session.h"
#include "log.h"

struct {
	struct mnl_socket	*nl;
	uint32_t		pid;
	uint32_t		nlmsg_seq;
} kr_state;

struct kroute_node {
	RB_ENTRY(kroute_node)	 entry;
	struct kroute		 r;
	struct kroute_node	*next;
};

struct kroute6_node {
	RB_ENTRY(kroute6_node)	 entry;
	struct kroute6		 r;
	struct kroute6_node	*next;
};

struct knexthop_node {
	RB_ENTRY(knexthop_node)	 entry;
	struct bgpd_addr	 nexthop;
	void			*kroute;
};

struct kredist_node {
	RB_ENTRY(kredist_node)	 entry;
	struct bgpd_addr	 prefix;
	uint64_t		 rd;
	uint8_t			 prefixlen;
	uint8_t			 dynamic;
};

struct kif_kr {
	LIST_ENTRY(kif_kr)	 entry;
	struct kroute_node	*kr;
};

struct kif_kr6 {
	LIST_ENTRY(kif_kr6)	 entry;
	struct kroute6_node	*kr;
};

LIST_HEAD(kif_kr_head, kif_kr);
LIST_HEAD(kif_kr6_head, kif_kr6);

struct kif_node {
	RB_ENTRY(kif_node)	 entry;
	struct kif		 k;
	struct kif_kr_head	 kroute_l;
	struct kif_kr6_head	 kroute6_l;
};

int	kroute_compare(struct kroute_node *, struct kroute_node *);
int	kroute6_compare(struct kroute6_node *, struct kroute6_node *);
int	kif_compare(struct kif_node *, struct kif_node *);

RB_PROTOTYPE(kroute_tree, kroute_node, entry, kroute_compare)
RB_GENERATE(kroute_tree, kroute_node, entry, kroute_compare)

RB_PROTOTYPE(kroute6_tree, kroute6_node, entry, kroute6_compare)
RB_GENERATE(kroute6_tree, kroute6_node, entry, kroute6_compare)

struct kroute_node	*kroute_find(struct ktable *, in_addr_t, uint8_t,
			    uint8_t);
struct kroute_node	*kroute_matchgw(struct kroute_node *,
			    struct sockaddr_in *);
int			 kroute_insert(struct ktable *, struct kroute_node *);
int			 kroute_remove(struct ktable *, struct kroute_node *);
void			 kroute_clear(struct ktable *);

struct kroute6_node	*kroute6_find(struct ktable *, const struct in6_addr *,
			    uint8_t, uint8_t);
struct kroute6_node	*kroute6_matchgw(struct kroute6_node *,
			    struct sockaddr_in6 *);
int			 kroute6_insert(struct ktable *, struct kroute6_node *);
int			 kroute6_remove(struct ktable *, struct kroute6_node *);
void			 kroute6_clear(struct ktable *);

struct kif_node		*kif_find(int);
int			 kif_insert(struct kif_node *);
int			 kif_remove(struct kif_node *, u_int);
void			 kif_clear(u_int);

int			 kif_kr_insert(struct kroute_node *);
int			 kif_kr_remove(struct kroute_node *);

int			 kif_kr6_insert(struct kroute6_node *);
int			 kif_kr6_remove(struct kroute6_node *);

RB_HEAD(kif_tree, kif_node)		kit;
RB_PROTOTYPE(kif_tree, kif_node, entry, kif_compare)
RB_GENERATE(kif_tree, kif_node, entry, kif_compare)

struct ktable	 krt;
const u_int	 krt_size = 1;

struct ktable	*ktable_get(u_int);

static uint8_t	mask2prefixlen(in_addr_t);
static uint8_t	mask2prefixlen6(struct sockaddr_in6 *);

int	kr4_change(struct ktable *, struct kroute_full *, uint8_t);
int	kr6_change(struct ktable *, struct kroute_full *, uint8_t);

int	kr4_delete(struct ktable *, struct kroute_full *, uint8_t);
int	kr6_delete(struct ktable *, struct kroute_full *, uint8_t);

static int	send_rtmsg(struct mnl_socket *, int, struct ktable *,
		    struct kroute *, uint8_t);
static int	send_rt6msg(struct mnl_socket *, int, struct ktable *,
		    struct kroute6 *, uint8_t);

static void	kr_redistribute(int, struct ktable *, struct kroute *);
static void	kr_redistribute6(int, struct ktable *, struct kroute6 *);

static int	kr_net_match(struct ktable *, struct network_config *,
		    uint16_t, int);
static struct network *kr_net_find(struct ktable *, struct network *);
static void	kr_net_clear(struct ktable *);

static struct kroute_full *
kr_tofull(struct kroute *kr)
{
	static struct kroute_full	kf;

	bzero(&kf, sizeof(kf));

	kf.prefix.aid = AID_INET;
	kf.prefix.v4.s_addr = kr->prefix.s_addr;
	kf.nexthop.aid = AID_INET;
	kf.nexthop.v4.s_addr = kr->nexthop.s_addr;
	strlcpy(kf.label, rtlabel_id2name(kr->labelid), sizeof(kf.label));
	kf.flags = kr->flags;
	kf.ifindex = kr->ifindex;
	kf.prefixlen = kr->prefixlen;
	kf.priority = kr->priority;

	return (&kf);
}

static struct kroute_full *
kr6_tofull(struct kroute6 *kr6)
{
	static struct kroute_full	kf;

	bzero(&kf, sizeof(kf));

	kf.prefix.aid = AID_INET6;
	memcpy(&kf.prefix.v6, &kr6->prefix, sizeof(struct in6_addr));
	kf.nexthop.aid = AID_INET6;
	memcpy(&kf.nexthop.v6, &kr6->nexthop, sizeof(struct in6_addr));
	strlcpy(kf.label, rtlabel_id2name(kr6->labelid), sizeof(kf.label));
	kf.flags = kr6->flags;
	kf.ifindex = kr6->ifindex;
	kf.prefixlen = kr6->prefixlen;
	kf.priority = kr6->priority;

	return (&kf);
}

static inline int
knexthop_compare(struct knexthop_node *a, struct knexthop_node *b)
{
	int	i;

	if (a->nexthop.aid != b->nexthop.aid)
		return (b->nexthop.aid - a->nexthop.aid);

	switch (a->nexthop.aid) {
	case AID_INET:
		if (ntohl(a->nexthop.v4.s_addr) < ntohl(b->nexthop.v4.s_addr))
			return (-1);
		if (ntohl(a->nexthop.v4.s_addr) > ntohl(b->nexthop.v4.s_addr))
			return (1);
		break;
	case AID_INET6:
		for (i = 0; i < 16; i++) {
			if (a->nexthop.v6.s6_addr[i] < b->nexthop.v6.s6_addr[i])
				return (-1);
			if (a->nexthop.v6.s6_addr[i] > b->nexthop.v6.s6_addr[i])
				return (1);
		}
		break;
	default:
		fatalx("%s: unknown AF", __func__);
	}

	return (0);
}

static inline int
kredist_compare(struct kredist_node *a, struct kredist_node *b)
{
	int	i;

	if (a->prefix.aid != b->prefix.aid)
		return (b->prefix.aid - a->prefix.aid);

	if (a->prefixlen < b->prefixlen)
		return (-1);
	if (a->prefixlen > b->prefixlen)
		return (1);

	switch (a->prefix.aid) {
	case AID_INET:
		if (ntohl(a->prefix.v4.s_addr) < ntohl(b->prefix.v4.s_addr))
			return (-1);
		if (ntohl(a->prefix.v4.s_addr) > ntohl(b->prefix.v4.s_addr))
			return (1);
		break;
	case AID_INET6:
		for (i = 0; i < 16; i++) {
			if (a->prefix.v6.s6_addr[i] < b->prefix.v6.s6_addr[i])
				return (-1);
			if (a->prefix.v6.s6_addr[i] > b->prefix.v6.s6_addr[i])
				return (1);
		}
		break;
	default:
		fatalx("%s: unknown AF", __func__);
	}

	if (a->rd < b->rd)
		return (-1);
	if (a->rd > b->rd)
		return (1);

	return (0);
}

RB_PROTOTYPE(knexthop_tree, knexthop_node, entry, knexthop_compare)
RB_GENERATE(knexthop_tree, knexthop_node, entry, knexthop_compare)

RB_PROTOTYPE(kredist_tree, kredist_node, entry, kredist_compare)
RB_GENERATE(kredist_tree, kredist_node, entry, kredist_compare)

#define KT2KNT(x)	(&(ktable_get((x)->nhtableid)->knt))

void	knexthop_track(struct ktable *, void *);
void	knexthop_send_update(struct knexthop_node *);

/*
 * rtsock related functions
 */

int
send_rtmsg(struct mnl_socket *nl, int action, struct ktable *kt,
    struct kroute *kroute, uint8_t fib_prio)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct rtmsg *rtm;

	if (!kt->fib_sync)
		return (0);

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = action;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE;
	nlh->nlmsg_seq = kr_state.nlmsg_seq++;

	rtm = mnl_nlmsg_put_extra_header(nlh, sizeof *rtm);
	rtm->rtm_family = AF_INET;
	rtm->rtm_dst_len = kroute->prefixlen;
	rtm->rtm_src_len = 0;
	rtm->rtm_tos = 0;
	rtm->rtm_protocol = RTPROT_BGP;
	rtm->rtm_table = kt->rtableid;
	rtm->rtm_type = RTN_UNICAST;
	if (kroute->flags & F_BLACKHOLE)
		rtm->rtm_type = RTN_BLACKHOLE;
	if (kroute->flags & F_REJECT)
		rtm->rtm_type = RTN_PROHIBIT;
	rtm->rtm_scope = RT_SCOPE_UNIVERSE;
	rtm->rtm_flags = 0;

	mnl_attr_put_u32(nlh, RTA_DST, kroute->prefix.s_addr);
	if (kroute->nexthop.s_addr != 0) {
		mnl_attr_put_u32(nlh, RTA_GATEWAY, kroute->nexthop.s_addr);
	}

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		log_warn("%s: action %u, prefix %s/%u", __func__,
		    nlh->nlmsg_type, inet_ntoa(kroute->prefix),
		    kroute->prefixlen);
		return (0);
	}

	return (0);
}

int
send_rt6msg(struct mnl_socket *nl, int action, struct ktable *kt,
    struct kroute6 *kroute, uint8_t fib_prio)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct rtmsg *rtm;

	if (!kt->fib_sync)
		return (0);

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = action;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE;
	nlh->nlmsg_seq = kr_state.nlmsg_seq++;

	rtm = mnl_nlmsg_put_extra_header(nlh, sizeof *rtm);
	rtm->rtm_family = AF_INET6;
	rtm->rtm_dst_len = kroute->prefixlen;
	rtm->rtm_src_len = 0;
	rtm->rtm_tos = 0;
	rtm->rtm_protocol = RTPROT_BGP;
	rtm->rtm_table = kt->rtableid;
	rtm->rtm_type = RTN_UNICAST;
	if (kroute->flags & F_BLACKHOLE)
		rtm->rtm_type = RTN_BLACKHOLE;
	if (kroute->flags & F_REJECT)
		rtm->rtm_type = RTN_PROHIBIT;
	rtm->rtm_scope = RT_SCOPE_UNIVERSE;
	rtm->rtm_flags = 0;

	mnl_attr_put(nlh, RTA_DST, sizeof(struct in6_addr), &kroute->prefix);
	if (memcmp(&kroute->nexthop, &in6addr_any, sizeof(struct in6_addr))) {
		mnl_attr_put(nlh, RTA_GATEWAY, sizeof(struct in6_addr),
		    &kroute->nexthop);
	}

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		log_warn("%s: action %u, prefix %s/%u", __func__,
		    nlh->nlmsg_type, log_in6addr(&kroute->prefix),
		    kroute->prefixlen);
		return (0);
	}

	return (0);
}


static struct knexthop_node *
knexthop_find(struct ktable *kt, struct bgpd_addr *addr)
{
	struct knexthop_node	s;

	bzero(&s, sizeof(s));
	memcpy(&s.nexthop, addr, sizeof(s.nexthop));

	return (RB_FIND(knexthop_tree, KT2KNT(kt), &s));
}

static int
knexthop_insert(struct ktable *kt, struct knexthop_node *kn)
{
	if (RB_INSERT(knexthop_tree, KT2KNT(kt), kn) != NULL) {
		log_warnx("%s: failed for %s", __func__,
		    log_addr(&kn->nexthop));
		free(kn);
		return (-1);
	}

	knexthop_send_update(kn);

	return (0);
}

static int
knexthop_remove(struct ktable *kt, struct knexthop_node *kn)
{
	if (RB_REMOVE(knexthop_tree, KT2KNT(kt), kn) == NULL) {
		log_warnx("%s: failed for %s", __func__,
		    log_addr(&kn->nexthop));
		return (-1);
	}

	free(kn);
	return (0);
}

static struct kroute_node *
kroute_match(struct ktable *kt, in_addr_t key, int matchall)
{
	int			 i;
	struct kroute_node	*kr;
	in_addr_t		 ina;

	ina = ntohl(key);

	/* this will never match the default route */
	for (i = 32; i > 0; i--)
		if ((kr = kroute_find(kt, htonl(ina & prefixlen2mask(i)), i,
		    RTP_ANY)) != NULL)
			if (matchall || bgpd_filternexthop(&kr->r, NULL) == 0)
			    return (kr);

	/* so if there is no match yet, lookup the default route */
	if ((kr = kroute_find(kt, 0, 0, RTP_ANY)) != NULL)
		if (matchall || bgpd_filternexthop(&kr->r, NULL) == 0)
			return (kr);

	return (NULL);
}

static struct kroute6_node *
kroute6_match(struct ktable *kt, struct in6_addr *key, int matchall)
{
	int			 i;
	struct kroute6_node	*kr6;
	struct in6_addr		 ina;

	/* this will never match the default route */
	for (i = 128; i > 0; i--) {
		inet6applymask(&ina, key, i);
		if ((kr6 = kroute6_find(kt, &ina, i, RTP_ANY)) != NULL)
			if (matchall || bgpd_filternexthop(NULL, &kr6->r) == 0)
				return (kr6);
	}

	/* so if there is no match yet, lookup the default route */
	if ((kr6 = kroute6_find(kt, &in6addr_any, 0, RTP_ANY)) != NULL)
		if (matchall || bgpd_filternexthop(NULL, &kr6->r) == 0)
			return (kr6);

	return (NULL);
}

static void
kroute_detach_nexthop(struct ktable *kt, struct knexthop_node *kn)
{
	struct knexthop_node	*s;
	struct kroute_node	*k;
	struct kroute6_node	*k6;

	if (kn->kroute == NULL)
		return;

	/*
	 * check whether there's another nexthop depending on this kroute
	 * if not remove the flag
	 */
	RB_FOREACH(s, knexthop_tree, KT2KNT(kt))
		if (s->kroute == kn->kroute && s != kn)
			break;

	if (s == NULL) {
		switch (kn->nexthop.aid) {
		case AID_INET:
			k = kn->kroute;
			k->r.flags &= ~F_NEXTHOP;
			break;
		case AID_INET6:
			k6 = kn->kroute;
			k6->r.flags &= ~F_NEXTHOP;
			break;
		}
	}

	kn->kroute = NULL;
}

static void
knexthop_validate(struct ktable *kt, struct knexthop_node *kn)
{
	void			*oldk;
	struct kroute_node	*kr;
	struct kroute6_node	*kr6;

	oldk = kn->kroute;
	kroute_detach_nexthop(kt, kn);

	if ((kt = ktable_get(kt->nhtableid)) == NULL)
		fatalx("%s: lost nexthop routing table", __func__);

	switch (kn->nexthop.aid) {
	case AID_INET:
		kr = kroute_match(kt, kn->nexthop.v4.s_addr, 0);

		if (kr) {
			kn->kroute = kr;
			kr->r.flags |= F_NEXTHOP;
		}

		/*
		 * Send update if nexthop route changed under us if
		 * the route remains the same then the NH state has not
		 * changed. State changes are tracked by knexthop_track().
		 */
		if (kr != oldk)
			knexthop_send_update(kn);
		break;
	case AID_INET6:
		kr6 = kroute6_match(kt, &kn->nexthop.v6, 0);

		if (kr6) {
			kn->kroute = kr6;
			kr6->r.flags |= F_NEXTHOP;
		}

		if (kr6 != oldk)
			knexthop_send_update(kn);
		break;
	}
}

static void
knexthop_clear(struct ktable *kt)
{
	struct knexthop_node	*kn;

	while ((kn = RB_MIN(knexthop_tree, KT2KNT(kt))) != NULL)
		knexthop_remove(kt, kn);
}

int
kr_nexthop_add(u_int rtableid, struct bgpd_addr *addr, struct bgpd_config *conf)
{
	struct ktable		*kt;
	struct knexthop_node	*h;

	if (rtableid == 0)
		rtableid = conf->default_tableid;

	if ((kt = ktable_get(rtableid)) == NULL) {
		log_warnx("%s: non-existent rtableid %d", __func__, rtableid);
		return (0);
	}
	if ((h = knexthop_find(kt, addr)) != NULL) {
		/* should not happen... this is actually an error path */
		knexthop_send_update(h);
	} else {
		if ((h = calloc(1, sizeof(struct knexthop_node))) == NULL) {
			log_warn("%s", __func__);
			return (-1);
		}
		memcpy(&h->nexthop, addr, sizeof(h->nexthop));

		if (knexthop_insert(kt, h) == -1)
			return (-1);
	}

	return (0);
}

void
kr_nexthop_delete(u_int rtableid, struct bgpd_addr *addr,
    struct bgpd_config *conf)
{
	struct ktable		*kt;
	struct knexthop_node	*kn;

	if (rtableid == 0)
		rtableid = conf->default_tableid;

	if ((kt = ktable_get(rtableid)) == NULL) {
		log_warnx("%s: non-existent rtableid %d", __func__,
		    rtableid);
		return;
	}
	if ((kn = knexthop_find(kt, addr)) == NULL)
		return;

	knexthop_remove(kt, kn);
}

void
knexthop_track(struct ktable *kt, void *krp)
{
	struct knexthop_node	*kn;

	RB_FOREACH(kn, knexthop_tree, KT2KNT(kt))
		if (kn->kroute == krp)
			knexthop_send_update(kn);
}

void
knexthop_send_update(struct knexthop_node *kn)
{
	struct kroute_nexthop	 n;
#if 0
	struct kroute_node	*kr;
	struct kroute6_node	*kr6;
#endif
	struct ifaddrs		*ifap, *ifa;

	bzero(&n, sizeof(n));
	memcpy(&n.nexthop, &kn->nexthop, sizeof(n.nexthop));

#if 0
	if (kn->kroute == NULL) {
		n.valid = 0;	/* NH is not valid */
		send_nexthop_update(&n);
		return;
	}

	switch (kn->nexthop.aid) {
	case AID_INET:
		kr = kn->kroute;
		n.valid = kroute_validate(&kr->r);
		n.connected = kr->r.flags & F_CONNECTED;
		if (kr->r.nexthop.s_addr != 0) {
			n.gateway.aid = AID_INET;
			n.gateway.v4.s_addr = kr->r.nexthop.s_addr;
		}
		if (n.connected) {
			n.net.aid = AID_INET;
			n.net.v4.s_addr = kr->r.prefix.s_addr;
			n.netlen = kr->r.prefixlen;
		}
		break;
	case AID_INET6:
		kr6 = kn->kroute;
		n.valid = kroute6_validate(&kr6->r);
		n.connected = kr6->r.flags & F_CONNECTED;
		if (memcmp(&kr6->r.nexthop, &in6addr_any,
		    sizeof(struct in6_addr)) != 0) {
			n.gateway.aid = AID_INET6;
			memcpy(&n.gateway.v6, &kr6->r.nexthop,
			    sizeof(struct in6_addr));
		}
		if (n.connected) {
			n.net.aid = AID_INET6;
			memcpy(&n.net.v6, &kr6->r.prefix,
			    sizeof(struct in6_addr));
			n.netlen = kr6->r.prefixlen;
		}
		break;
	}
#else
	n.valid = 1;		/* NH is always valid */
	memcpy(&n.gateway, &kn->nexthop, sizeof(n.gateway));

	if (getifaddrs(&ifap) == -1)
		fatal("getifaddrs");

	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		struct bgpd_addr addr;
		struct sockaddr_in *m4;
		struct sockaddr_in6 *m6;
		int plen;

		if (ifa->ifa_addr == NULL)
			continue;

		switch (ifa->ifa_addr->sa_family) {
		case AF_INET:
			m4 = (struct sockaddr_in *)ifa->ifa_netmask;
			if (m4 == NULL)
				plen = 32;
			else
				plen = mask2prefixlen(m4->sin_addr.s_addr);
			break;
		case AF_INET6:
			m6 = (struct sockaddr_in6 *)ifa->ifa_netmask;
			if (m6 == NULL)
				plen = 128;
			else
				plen = mask2prefixlen6(m6);
			break;
		default:
			continue;
		}
		sa2addr(ifa->ifa_addr, &addr, NULL);
		if (prefix_compare(&n.nexthop, &addr, plen) != 0)
			continue;

		n.connected = F_CONNECTED;
		n.gateway = addr;
		n.net = addr;
		n.netlen = plen;
		break;
	}

        freeifaddrs(ifap);
#endif
	send_nexthop_update(&n);
}

int
kr_init(int *fd)
{
	struct ktable	*kt = &krt;;

	/* initialize structure ... */
	strlcpy(kt->descr, "rdomain_0", sizeof(kt->descr));
	RB_INIT(&kt->krt);
	RB_INIT(&kt->krt6);
	RB_INIT(&kt->knt);
	TAILQ_INIT(&kt->krn);
	kt->fib_conf = kt->fib_sync = 0;
	kt->rtableid = 0;
	kt->nhtableid = 0;

	kr_state.nl = mnl_socket_open(NETLINK_ROUTE);
	if (kr_state.nl == NULL) {
		log_warn("%s: mnl_socket_open", __func__);
		return (-1);
	}

	if (mnl_socket_bind(kr_state.nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		log_warn("%s: mnl_socket_bind", __func__);
		return (-1);
	}

	kr_state.pid = mnl_socket_get_portid(kr_state.nl);
	kr_state.nlmsg_seq = 1;

	*fd = mnl_socket_get_fd(kr_state.nl);
	return (0);
}

void
kr_shutdown(uint8_t fib_prio, u_int rdomain)
{
	mnl_socket_close(kr_state.nl);
	knexthop_clear(&krt);
}

void
kr_fib_couple(u_int rtableid, uint8_t fib_prio)
{
	struct ktable		*kt;
	struct kroute_node	*kr;
	struct kroute6_node	*kr6;

	if ((kt = ktable_get(rtableid)) == NULL)  /* table does not exist */
		return;

	if (kt->fib_sync)	/* already coupled */
		return;

	kt->fib_sync = 1;

	RB_FOREACH(kr, kroute_tree, &kt->krt)
		if ((kr->r.flags & F_BGPD_INSERTED))
			send_rtmsg(kr_state.nl, RTM_NEWROUTE, kt, &kr->r,
			    fib_prio);
	RB_FOREACH(kr6, kroute6_tree, &kt->krt6)
		if ((kr6->r.flags & F_BGPD_INSERTED))
			send_rt6msg(kr_state.nl, RTM_NEWROUTE, kt, &kr6->r,
			    fib_prio);

	log_info("kernel routing table %u (%s) coupled", kt->rtableid,
	    kt->descr);
}

void
kr_fib_couple_all(uint8_t fib_prio)
{
	u_int	 i;

	for (i = krt_size; i > 0; i--)
		kr_fib_couple(i - 1, fib_prio);
}

void
kr_fib_decouple(u_int rtableid, uint8_t fib_prio)
{
	struct ktable		*kt;
	struct kroute_node	*kr;
	struct kroute6_node	*kr6;

	if ((kt = ktable_get(rtableid)) == NULL)  /* table does not exist */
		return;

	if (!kt->fib_sync)	/* already decoupled */
		return;

	RB_FOREACH(kr, kroute_tree, &kt->krt)
		if ((kr->r.flags & F_BGPD_INSERTED))
			send_rtmsg(kr_state.nl, RTM_DELROUTE, kt, &kr->r,
			    fib_prio);
	RB_FOREACH(kr6, kroute6_tree, &kt->krt6)
		if ((kr6->r.flags & F_BGPD_INSERTED))
			send_rt6msg(kr_state.nl, RTM_DELROUTE, kt, &kr6->r,
			    fib_prio);

	kt->fib_sync = 0;

	log_info("kernel routing table %u (%s) decoupled", kt->rtableid,
	    kt->descr);
}

void
kr_fib_decouple_all(uint8_t fib_prio)
{
	u_int	 i;

	for (i = krt_size; i > 0; i--)
		kr_fib_decouple(i - 1, fib_prio);
}

void
kr_fib_update_prio_all(uint8_t fib_prio)
{
}

static int
rtmsg_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	/* skip unsupported attribute in user-space */
	if (mnl_attr_type_valid(attr, RTA_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case RTA_TABLE:
	case RTA_DST:
	case RTA_SRC:
	case RTA_OIF:
	case RTA_FLOW:
	case RTA_PREFSRC:
	case RTA_GATEWAY:
	case RTA_PRIORITY:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
			log_warn("%s: mnl_attr_validate failed.", __func__);
			return MNL_CB_ERROR;
		}
		break;
	case RTA_METRICS:
		if (mnl_attr_validate(attr, MNL_TYPE_NESTED) < 0) {
			log_warn("%s: mnl_attr_validate failed.", __func__);
			return MNL_CB_ERROR;
		}
		break;
	}
	tb[type] = attr;
	return MNL_CB_OK;
}

static int
rt6msg_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	/* skip unsupported attribute in user-space */
	if (mnl_attr_type_valid(attr, RTA_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case RTA_TABLE:
	case RTA_OIF:
	case RTA_FLOW:
	case RTA_PRIORITY:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
			log_warn("%s: mnl_attr_validate failed.", __func__);
			return MNL_CB_ERROR;
		}
		break;
	case RTA_DST:
	case RTA_SRC:
	case RTA_PREFSRC:
	case RTA_GATEWAY:
		if (mnl_attr_validate2(attr, MNL_TYPE_BINARY,
					sizeof(struct in6_addr)) < 0) {
			log_warn("%s: mnl_attr_validate2 failed.", __func__);
			return MNL_CB_ERROR;
		}
		break;
	case RTA_METRICS:
		if (mnl_attr_validate(attr, MNL_TYPE_NESTED) < 0) {
			log_warn("%s: mnl_attr_validate failed.", __func__);
			return MNL_CB_ERROR;
		}
		break;
	}
	tb[type] = attr;
	return MNL_CB_OK;
}

static int
dispatch_rtmsg_addr(const struct nlmsghdr *nlh, const struct rtmsg *rm,
    struct nlattr **tb, struct ktable *kt)
{
	struct sockaddr		*sa = NULL;
	struct sockaddr_in	 sa_in = {};
	struct sockaddr_in6	 sa_in6 = {};
	struct in6_addr		*in6;
	struct kroute_node	*kr;
	struct kroute6_node	*kr6;
	struct bgpd_addr	 prefix;
	int			 flags, oflags, mpath = 0, changed = 0;
	int			 rtlabel_changed = 0;
	uint16_t		 ifindex;
	uint8_t			 prefixlen;
	uint8_t			 prio;

	flags = F_KERNEL;
	ifindex = 0;
	prefixlen = 0;
	bzero(&prefix, sizeof(prefix));

	if (tb[RTA_DST] == NULL) {
		log_warnx("empty route message");
		return (0);
	}

	if (rm->rtm_protocol == RTPROT_STATIC)
		flags |= F_STATIC;
	if (rm->rtm_type == RTN_BLACKHOLE)
		flags |= F_BLACKHOLE;
	if (rm->rtm_type == RTN_PROHIBIT)
		flags |= F_REJECT;

	prio = 0;

	switch (rm->rtm_family) {
	case AF_INET:
		sa = (struct sockaddr *) &sa_in;
		sa_in.sin_addr.s_addr = mnl_attr_get_u32(tb[RTA_DST]);
		prefix.aid = AID_INET;
		prefix.v4.s_addr = sa_in.sin_addr.s_addr;
		prefixlen = rm->rtm_dst_len;
		break;
	case AF_INET6:
		sa = (struct sockaddr *) &sa_in6;
		in6 = mnl_attr_get_payload(tb[RTA_DST]);
		memcpy(&sa_in6.sin6_addr, in6, sizeof(struct in6_addr));
		prefix.aid = AID_INET6;
		memcpy(&prefix.v6, in6, sizeof(struct in6_addr));
		prefixlen = rm->rtm_dst_len;
		break;
	default:
		return (0);
	}

	/* we assume anything with a gateway is non-mpath for now */
	if (tb[RTA_GATEWAY] != NULL) {
		flags |= F_CONNECTED;
		ifindex = 0;
		mpath = 0; /* link local stuff can't be mpath */
	}

	if (nlh->nlmsg_type == RTM_DELROUTE) {
		switch (prefix.aid) {
		case AID_INET:
			if ((kr = kroute_find(kt, prefix.v4.s_addr,
			    prefixlen, prio)) == NULL)
				return (0);
			if (!(kr->r.flags & F_KERNEL))
				return (0);

			if (mpath)
				/* get the correct route */
				if ((kr = kroute_matchgw(kr, &sa_in)) == NULL) {
					log_warnx("%s[delete]: "
					    "mpath route not found", __func__);
					return (0);
				}

			if (kroute_remove(kt, kr) == -1)
				return (-1);
			break;
		case AID_INET6:
			if ((kr6 = kroute6_find(kt, &prefix.v6, prefixlen,
			    prio)) == NULL)
				return (0);
			if (!(kr6->r.flags & F_KERNEL))
				return (0);

			if (mpath)
				/* get the correct route */
				if ((kr6 = kroute6_matchgw(kr6, &sa_in6)) ==
				    NULL) {
					log_warnx("%s[delete]: IPv6 mpath "
					    "route not found", __func__);
					return (0);
				}

			if (kroute6_remove(kt, kr6) == -1)
				return (-1);
			break;
		}
		return (0);
	}

	if (sa == NULL && !(flags & F_CONNECTED)) {
		log_warnx("%s: no nexthop for %s/%u",
		    __func__, log_addr(&prefix), prefixlen);
		return (0);
	}

	switch (prefix.aid) {
	case AID_INET:
		if ((kr = kroute_find(kt, prefix.v4.s_addr, prefixlen,
		    prio)) != NULL) {
			if (kr->r.flags & F_KERNEL) {
				/* get the correct route */
				if (mpath && rm->rtm_type == RTM_NEWROUTE)
					goto add4;

				if (sa == (struct sockaddr *) &sa_in) {
					if (kr->r.nexthop.s_addr !=
					    sa_in.sin_addr.s_addr)
						changed = 1;
					kr->r.nexthop.s_addr =
					    sa_in.sin_addr.s_addr;
				} else {
					if (kr->r.nexthop.s_addr != 0)
						changed = 1;
					kr->r.nexthop.s_addr = 0;
				}

				if (kr->r.flags & F_NEXTHOP)
					flags |= F_NEXTHOP;

				if (kr->r.labelid) {
					rtlabel_unref(kr->r.labelid);
					kr->r.labelid = 0;
					flags &= ~F_RTLABEL;
					rtlabel_changed = 1;
				}

				oflags = kr->r.flags;
				if (flags != oflags)
					changed = 1;
				kr->r.flags = flags;

				if (rtlabel_changed)
					kr_redistribute(IMSG_NETWORK_ADD,
					    kt, &kr->r);

				if ((oflags & F_CONNECTED) &&
				    !(flags & F_CONNECTED)) {
					kif_kr_remove(kr);
					kr_redistribute(IMSG_NETWORK_ADD,
					    kt, &kr->r);
				}
				if ((flags & F_CONNECTED) &&
				    !(oflags & F_CONNECTED)) {
					kif_kr_insert(kr);
					kr_redistribute(IMSG_NETWORK_ADD,
					    kt, &kr->r);
				}
				if (kr->r.flags & F_NEXTHOP && changed)
					knexthop_track(kt, kr);
			}
		} else {
add4:
			if ((kr = calloc(1,
			    sizeof(struct kroute_node))) == NULL) {
				log_warn("%s", __func__);
				return (-1);
			}
			kr->r.prefix.s_addr = prefix.v4.s_addr;
			kr->r.prefixlen = prefixlen;
			if (sa == (struct sockaddr *) &sa_in)
				kr->r.nexthop.s_addr = sa_in.sin_addr.s_addr;
			else
				kr->r.nexthop.s_addr = 0;
			kr->r.flags = flags;
			kr->r.ifindex = ifindex;
			kr->r.priority = prio;

			kroute_insert(kt, kr);
		}
		break;
	case AID_INET6:
		if ((kr6 = kroute6_find(kt, &prefix.v6, prefixlen, prio)) !=
		    NULL) {
			if (kr6->r.flags & F_KERNEL) {
				/* get the correct route */
				if (mpath && rm->rtm_type == RTM_NEWROUTE)
					goto add6;

				if (sa == (struct sockaddr *) &sa_in6) {
					if (memcmp(&kr6->r.nexthop,
					    &sa_in6.sin6_addr,
					    sizeof(struct in6_addr)))
						changed = 1;
					memcpy(&kr6->r.nexthop,
					    &sa_in6.sin6_addr,
					    sizeof(struct in6_addr));
				} else {
					if (memcmp(&kr6->r.nexthop,
					    &in6addr_any,
					    sizeof(struct in6_addr)))
						changed = 1;
					memcpy(&kr6->r.nexthop,
					    &in6addr_any,
					    sizeof(struct in6_addr));
				}

				if (kr6->r.flags & F_NEXTHOP)
					flags |= F_NEXTHOP;

				if (kr6->r.labelid) {
					rtlabel_unref(kr6->r.labelid);
					kr6->r.labelid = 0;
					flags &= ~F_RTLABEL;
					rtlabel_changed = 1;
				}

				oflags = kr6->r.flags;
				if (flags != oflags)
					changed = 1;
				kr6->r.flags = flags;

				if (rtlabel_changed)
					kr_redistribute6(IMSG_NETWORK_ADD,
					    kt, &kr6->r);

				if ((oflags & F_CONNECTED) &&
				    !(flags & F_CONNECTED)) {
					kif_kr6_remove(kr6);
					kr_redistribute6(IMSG_NETWORK_ADD,
					    kt, &kr6->r);
				}
				if ((flags & F_CONNECTED) &&
				    !(oflags & F_CONNECTED)) {
					kif_kr6_insert(kr6);
					kr_redistribute6(IMSG_NETWORK_ADD,
					    kt, &kr6->r);
				}

				if (kr6->r.flags & F_NEXTHOP && changed)
					knexthop_track(kt, kr6);
			}
		} else {
add6:
			if ((kr6 = calloc(1,
			    sizeof(struct kroute6_node))) == NULL) {
				log_warn("%s", __func__);
				return (-1);
			}
			memcpy(&kr6->r.prefix, &prefix.v6,
			    sizeof(struct in6_addr));
			kr6->r.prefixlen = prefixlen;
			if (sa == (struct sockaddr *) &sa_in6)
				memcpy(&kr6->r.nexthop, &sa_in6.sin6_addr,
				    sizeof(struct in6_addr));
			else
				memcpy(&kr6->r.nexthop, &in6addr_any,
				    sizeof(struct in6_addr));
			kr6->r.flags = flags;
			kr6->r.ifindex = ifindex;
			kr6->r.priority = prio;

			kroute6_insert(kt, kr6);
		}
		break;
	}

	return (0);
}

static int
dispatch_rtmsg(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *tb[RTA_MAX+1] = {};
	struct rtmsg *rm = mnl_nlmsg_get_payload(nlh);
	struct ktable *kt;
	(void) data;

	switch (rm->rtm_family) {
	case AF_INET:
		mnl_attr_parse(nlh, sizeof(*rm), rtmsg_attr_cb, tb);
		break;
	case AF_INET6:
		mnl_attr_parse(nlh, sizeof(*rm), rt6msg_attr_cb, tb);
		break;
	default:
		log_warn("%s: unhandled routing family %d", __func__,
		    rm->rtm_family);
		return MNL_CB_ERROR;
	}

	switch (nlh->nlmsg_type) {
	case RTM_NEWROUTE:
	case RTM_DELROUTE:
		if (nlh->nlmsg_pid == kr_state.pid)
			return MNL_CB_OK;

		if ((kt = ktable_get(rm->rtm_table)) == NULL)
			return MNL_CB_OK;

		if (dispatch_rtmsg_addr(nlh, rm, tb, kt) == -1)
			return MNL_CB_OK;

		break;
	default:
		log_warn("%s: unhandled routing message %d", __func__,
		    nlh->nlmsg_type);
		break;
	}

	return MNL_CB_OK;
}

int
kr_dispatch_msg(u_int rdomain)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	int ret;

	ret = mnl_socket_recvfrom(kr_state.nl, buf, sizeof buf);
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, 0, 0, dispatch_rtmsg, NULL);
		if (ret <= MNL_CB_STOP)
			break;
		ret = mnl_socket_recvfrom(kr_state.nl, buf, sizeof buf);
	}
	if (ret == -1) {
		if (errno == EAGAIN || errno == EINTR)
			return (0);
		log_warn("%s: read error", __func__);
	}

	return (0);
}

int
kr_change(u_int rtableid, struct kroute_full *kl, uint8_t fib_prio)
{
	struct ktable		*kt;

	if ((kt = ktable_get(rtableid)) == NULL)
		/* too noisy during reloads, just ignore */
		return (0);
	switch (kl->prefix.aid) {
	case AID_INET:
		return (kr4_change(kt, kl, fib_prio));
	case AID_INET6:
		return (kr6_change(kt, kl, fib_prio));
#ifdef NOTYET
	/* XXX: support MPLS */
	case AID_VPN_IPv4:
		return (krVPN4_change(kt, kl, fib_prio));
	case AID_VPN_IPv6:
		return (krVPN6_change(kt, kl, fib_prio));
#endif
	}
	log_warnx("%s: not handled AID", __func__);
	return (-1);
}

int
kr4_change(struct ktable *kt, struct kroute_full *kl, uint8_t fib_prio)
{
	struct kroute_node	*kr;
	uint16_t		 labelid;

	/* for blackhole and reject routes nexthop needs to be 127.0.0.1 */
	if (kl->flags & (F_BLACKHOLE|F_REJECT))
		kl->nexthop.v4.s_addr = htonl(INADDR_LOOPBACK);
	/* nexthop within 127/8 -> ignore silently */
	else if ((kl->nexthop.v4.s_addr & htonl(IN_CLASSA_NET)) ==
	    htonl(INADDR_LOOPBACK & IN_CLASSA_NET))
		return (0);

	labelid = rtlabel_name2id(kl->label);

	/* Linux does not have anything like RTM_CHANGE, so we have to delete
	 * the old route then add a new one. */
	if ((kr = kroute_find(kt, kl->prefix.v4.s_addr, kl->prefixlen,
	    fib_prio)) != NULL) {
		kr4_delete(kt, kr_tofull(&kr->r), fib_prio);
	}

	if ((kr = calloc(1, sizeof(struct kroute_node))) == NULL) {
		log_warn("%s", __func__);
		return (-1);
	}
	kr->r.prefix.s_addr = kl->prefix.v4.s_addr;
	kr->r.prefixlen = kl->prefixlen;
	kr->r.nexthop.s_addr = kl->nexthop.v4.s_addr;
	kr->r.flags = kl->flags | F_BGPD_INSERTED;
	kr->r.priority = fib_prio;
	kr->r.labelid = labelid;

	if (kroute_insert(kt, kr) == -1) {
		free(kr);
		return (-1);
	}

	if (send_rtmsg(kr_state.nl, RTM_NEWROUTE, kt, &kr->r, fib_prio) == -1)
		return (-1);

	return (0);
}

int
kr6_change(struct ktable *kt, struct kroute_full *kl, uint8_t fib_prio)
{
	struct kroute6_node	*kr6;
	struct in6_addr		 lo6 = IN6ADDR_LOOPBACK_INIT;
	uint16_t		 labelid;

	/* for blackhole and reject routes nexthop needs to be ::1 */
	if (kl->flags & (F_BLACKHOLE|F_REJECT))
		bcopy(&lo6, &kl->nexthop.v6, sizeof(kl->nexthop.v6));
	/* nexthop to loopback -> ignore silently */
	else if (IN6_IS_ADDR_LOOPBACK(&kl->nexthop.v6))
		return (0);

	labelid = rtlabel_name2id(kl->label);

	/* Linux does not have anything like RTM_CHANGE, so we have to delete
	 * the old route then add a new one. */
	if ((kr6 = kroute6_find(kt, &kl->prefix.v6, kl->prefixlen, fib_prio)) !=
	    NULL)
		kr6_delete(kt, kr6_tofull(&kr6->r), fib_prio);

	if ((kr6 = calloc(1, sizeof(struct kroute6_node))) == NULL) {
		log_warn("%s", __func__);
		return (-1);
	}
	memcpy(&kr6->r.prefix, &kl->prefix.v6, sizeof(struct in6_addr));
	kr6->r.prefixlen = kl->prefixlen;
	memcpy(&kr6->r.nexthop, &kl->nexthop.v6, sizeof(struct in6_addr));
	kr6->r.flags = kl->flags | F_BGPD_INSERTED;
	kr6->r.priority = fib_prio;
	kr6->r.labelid = labelid;

	if (kroute6_insert(kt, kr6) == -1) {
		free(kr6);
		return (-1);
	}

	if (send_rt6msg(kr_state.nl, RTM_NEWROUTE, kt, &kr6->r, fib_prio) == -1)
		return (-1);

	return (0);
}

int
kr_delete(u_int rtableid, struct kroute_full *kl, uint8_t fib_prio)
{
	struct ktable		*kt;

	if ((kt = ktable_get(rtableid)) == NULL)
		/* too noisy during reloads, just ignore */
		return (0);

	switch (kl->prefix.aid) {
	case AID_INET:
		return (kr4_delete(kt, kl, fib_prio));
	case AID_INET6:
		return (kr6_delete(kt, kl, fib_prio));
#ifdef NOTYET
	case AID_VPN_IPv4:
		return (krVPN4_delete(kt, kl, fib_prio));
	case AID_VPN_IPv6:
		return (krVPN6_delete(kt, kl, fib_prio));
#endif
	}
	log_warnx("%s: not handled AID", __func__);
	return (-1);
}

int
kr_flush(u_int rtableid)
{
	struct ktable		*kt;
	struct kroute_node	*kr, *next;
	struct kroute6_node	*kr6, *next6;

	if ((kt = ktable_get(rtableid)) == NULL)
		/* too noisy during reloads, just ignore */
		return (0);

	RB_FOREACH_SAFE(kr, kroute_tree, &kt->krt, next)
		if ((kr->r.flags & F_BGPD_INSERTED)) {
			if (kt->fib_sync)	/* coupled */
				send_rtmsg(kr_state.nl, RTM_DELROUTE, kt,
				    &kr->r, kr->r.priority);
			rtlabel_unref(kr->r.labelid);

			if (kroute_remove(kt, kr) == -1)
				return (-1);
		}
	RB_FOREACH_SAFE(kr6, kroute6_tree, &kt->krt6, next6)
		if ((kr6->r.flags & F_BGPD_INSERTED)) {
			if (kt->fib_sync)	/* coupled */
				send_rt6msg(kr_state.nl, RTM_DELROUTE, kt,
				    &kr6->r, kr6->r.priority);
			rtlabel_unref(kr6->r.labelid);

			if (kroute6_remove(kt, kr6) == -1)
				return (-1);
		}

	kt->fib_sync = 0;
	return (0);
}

int
kr4_delete(struct ktable *kt, struct kroute_full *kl, uint8_t fib_prio)
{
	struct kroute_node	*kr;

	if ((kr = kroute_find(kt, kl->prefix.v4.s_addr, kl->prefixlen,
	    fib_prio)) == NULL)
		return (0);

	if (!(kr->r.flags & F_BGPD_INSERTED))
		return (0);

	if (send_rtmsg(kr_state.nl, RTM_DELROUTE, kt, &kr->r, fib_prio) == -1)
		return (-1);

	rtlabel_unref(kr->r.labelid);

	if (kroute_remove(kt, kr) == -1)
		return (-1);

	return (0);
}

int
kr6_delete(struct ktable *kt, struct kroute_full *kl, uint8_t fib_prio)
{
	struct kroute6_node	*kr6;

	if ((kr6 = kroute6_find(kt, &kl->prefix.v6, kl->prefixlen, fib_prio)) ==
	    NULL)
		return (0);

	if (!(kr6->r.flags & F_BGPD_INSERTED))
		return (0);

	if (send_rt6msg(kr_state.nl, RTM_DELROUTE, kt, &kr6->r, fib_prio) == -1)
		return (-1);

	rtlabel_unref(kr6->r.labelid);

	if (kroute6_remove(kt, kr6) == -1)
		return (-1);

	return (0);
}

static int
kr_net_redist_add(struct ktable *kt, struct network_config *net,
    struct filter_set_head *attr, int dynamic)
{
	struct kredist_node *r, *xr;

	if ((r = calloc(1, sizeof(*r))) == NULL)
		fatal("%s", __func__);
	r->prefix = net->prefix;
	r->prefixlen = net->prefixlen;
	r->rd = net->rd;
	r->dynamic = dynamic;

	xr = RB_INSERT(kredist_tree, &kt->kredist, r);
	if (xr != NULL) {
		free(r);

		if (dynamic != xr->dynamic && dynamic) {
			/*
			 * ignore update a non-dynamic announcement is
			 * already present which has preference.
			 */
			return 0;
		}
		/*
		 * only equal or non-dynamic announcement ends up here.
		 * In both cases reset the dynamic flag (nop for equal) and
		 * redistribute.
		 */
		xr->dynamic = dynamic;
	}

	if (send_network(IMSG_NETWORK_ADD, net, attr) == -1)
		log_warnx("%s: faild to send network update", __func__);
	return 1;
}

static void
kr_net_redist_del(struct ktable *kt, struct network_config *net, int dynamic)
{
	struct kredist_node *r, node;

	bzero(&node, sizeof(node));
	node.prefix = net->prefix;
	node.prefixlen = net->prefixlen;
	node.rd = net->rd;

	r = RB_FIND(kredist_tree, &kt->kredist, &node);
	if (r == NULL || dynamic != r->dynamic)
		return;

	if (RB_REMOVE(kredist_tree, &kt->kredist, r) == NULL) {
		log_warnx("%s: failed to remove network %s/%u", __func__,
		    log_addr(&node.prefix), node.prefixlen);
		return;
	}
	free(r);

	if (send_network(IMSG_NETWORK_REMOVE, net, NULL) == -1)
		log_warnx("%s: faild to send network removal", __func__);
}

static struct network *
kr_net_find(struct ktable *kt, struct network *n)
{
	struct network		*xn;

	TAILQ_FOREACH(xn, &kt->krn, entry) {
		if (n->net.type != xn->net.type ||
		    n->net.prefixlen != xn->net.prefixlen ||
		    n->net.rd != xn->net.rd)
			continue;
		if (memcmp(&n->net.prefix, &xn->net.prefix,
		    sizeof(n->net.prefix)) == 0)
			return (xn);
	}
	return (NULL);
}

static void
kr_net_delete(struct network *n)
{
	filterset_free(&n->net.attrset);
	free(n);
}

void
kr_net_reload(u_int rtableid, uint64_t rd, struct network_head *nh)
{
	struct network		*n, *xn;
	struct ktable		*kt;

	if ((kt = ktable_get(rtableid)) == NULL)
		fatalx("%s: non-existent rtableid %d", __func__, rtableid);

	while ((n = TAILQ_FIRST(nh)) != NULL) {
		TAILQ_REMOVE(nh, n, entry);

		if (n->net.type != NETWORK_DEFAULT) {
			log_warnx("dynamic network statements unimplemened, "
			    "network ignored");
			kr_net_delete(n);
			continue;
		}

		n->net.old = 0;
		n->net.rd = rd;
		xn = kr_net_find(kt, n);
		if (xn) {
			xn->net.old = 0;
			filterset_free(&xn->net.attrset);
			filterset_move(&n->net.attrset, &xn->net.attrset);
			kr_net_delete(n);
		} else {
			TAILQ_INSERT_TAIL(&kt->krn, n, entry);
		}
	}
}

int
kr_reload(void)
{
	struct ktable		*kt;
	struct network		*n;
	u_int			 rid;

	for (rid = 0; rid < krt_size; rid++) {
		if ((kt = ktable_get(rid)) == NULL)
			continue;

		TAILQ_FOREACH(n, &kt->krn, entry)
			if (n->net.type == NETWORK_DEFAULT) {
				kr_net_redist_add(kt, &n->net,
				    &n->net.attrset, 0);
			} else
				fatalx("%s: dynamic networks not implemented",
				    __func__);
	}

	return (0);
}

void
kr_show_route(struct imsg *imsg)
{
	struct ctl_show_nexthop	 snh;
	struct ktable		*kt;
	struct knexthop_node	*h;
	int			 code;

	switch (imsg->hdr.type) {
	case IMSG_CTL_SHOW_NEXTHOP:
		kt = ktable_get(imsg->hdr.peerid);
		if (kt == NULL) {
			log_warnx("%s: table %u does not exist", __func__,
			    imsg->hdr.peerid);
			break;
		}
		RB_FOREACH(h, knexthop_tree, KT2KNT(kt)) {
			bzero(&snh, sizeof(snh));
			memcpy(&snh.addr, &h->nexthop, sizeof(snh.addr));
#if 0
			if (h->kroute != NULL) {
				switch (h->nexthop.aid) {
				case AID_INET:
					kr = h->kroute;
					snh.valid = kroute_validate(&kr->r);
					snh.krvalid = 1;
					memcpy(&snh.kr.kr4, &kr->r,
					    sizeof(snh.kr.kr4));
					ifindex = kr->r.ifindex;
					break;
				case AID_INET6:
					kr6 = h->kroute;
					snh.valid = kroute6_validate(&kr6->r);
					snh.krvalid = 1;
					memcpy(&snh.kr.kr6, &kr6->r,
					    sizeof(snh.kr.kr6));
					ifindex = kr6->r.ifindex;
					break;
				}
				if ((kif = kif_find(ifindex)) != NULL)
					memcpy(&snh.iface,
					    kr_show_interface(&kif->k),
					    sizeof(snh.iface));
			}
#else
			snh.valid = 1;
			snh.krvalid = 1;
#endif
			send_imsg_session(IMSG_CTL_SHOW_NEXTHOP, imsg->hdr.pid,
			    &snh, sizeof(snh));
		}
		break;
	case IMSG_CTL_SHOW_FIB_TABLES:
		{
			struct ktable	ktab;

			ktab = krt;
			/* do not leak internal information */
			RB_INIT(&ktab.krt);
			RB_INIT(&ktab.krt6);
			RB_INIT(&ktab.knt);
			TAILQ_INIT(&ktab.krn);

			send_imsg_session(IMSG_CTL_SHOW_FIB_TABLES,
			    imsg->hdr.pid, &ktab, sizeof(ktab));
		}
		break;
	default:	/* nada */
		code = CTL_RES_DENIED /* XXX */;
		send_imsg_session(IMSG_CTL_RESULT, imsg->hdr.pid,
		    &code, sizeof(code));
		return;
	}

	send_imsg_session(IMSG_CTL_END, imsg->hdr.pid, NULL, 0);
}

void
kr_ifinfo(char *ifname)
{
}

int
ktable_exists(u_int rtableid, u_int *rdomid)
{
	if (rtableid == 0) {
		*rdomid = 0;
		return (1);
	}
	return (0);
}

struct ktable *
ktable_get(u_int rtableid)
{
	if (rtableid == 0)
		return &krt;
	return NULL;
}

static void
ktable_free(u_int rtableid, uint8_t fib_prio)
{
	fatalx("%s not implemented", __func__);
}

int
ktable_update(u_int rtableid, char *name, int flags, uint8_t fib_prio)
{
	struct ktable	*kt;

	kt = ktable_get(rtableid);
	if (kt == NULL) {
		return (-1);
	} else {
		/* fib sync has higher preference then no sync */
		if (kt->state == RECONF_DELETE) {
			kt->fib_conf = !(flags & F_RIB_NOFIBSYNC);
			kt->state = RECONF_KEEP;
		} else if (!kt->fib_conf)
			kt->fib_conf = !(flags & F_RIB_NOFIBSYNC);

		strlcpy(kt->descr, name, sizeof(kt->descr));
	}
	return (0);
}

void
ktable_preload(void)
{
	struct ktable	*kt;
	struct network	*n;
	u_int		 i;

	for (i = 0; i < krt_size; i++) {
		if ((kt = ktable_get(i)) == NULL)
			continue;
		kt->state = RECONF_DELETE;

		/* mark all networks as old */
		TAILQ_FOREACH(n, &kt->krn, entry)
			n->net.old = 1;
	}
}

void
ktable_postload(uint8_t fib_prio)
{
	struct ktable	*kt;
	struct network	*n, *xn;
	u_int		 i;

	for (i = krt_size; i > 0; i--) {
		if ((kt = ktable_get(i - 1)) == NULL)
			continue;
		if (kt->state == RECONF_DELETE) {
			ktable_free(i - 1, fib_prio);
			continue;
		} else if (kt->state == RECONF_REINIT)
			kt->fib_sync = kt->fib_conf;

		/* cleanup old networks */
		TAILQ_FOREACH_SAFE(n, &kt->krn, entry, xn) {
			if (n->net.old) {
				TAILQ_REMOVE(&kt->krn, n, entry);
				if (n->net.type == NETWORK_DEFAULT)
					kr_net_redist_del(kt, &n->net, 0);
				kr_net_delete(n);
			}
		}
	}
}

int
get_mpe_config(const char *name, u_int *rdomain, u_int *label)
{
	return (-1);
}

static uint8_t
mask2prefixlen(in_addr_t ina)
{
	if (ina == 0)
		return (0);
	else
		return (33 - ffs(ntohl(ina)));
}

static uint8_t
mask2prefixlen6(struct sockaddr_in6 *sa_in6)
{
	uint8_t	*ap, *ep;
	u_int	 l = 0;

	/*
	 * There is no sin6_len for portability so calculate the end pointer
	 * so that a full IPv6 address fits. On systems without sa_len this
	 * is fine, on OpenBSD this is also correct. On other systems the
	 * assumtion is they behave like OpenBSD or that there is at least
	 * a 0 byte right after the end of the truncated sockaddr_in6.
	 */
	ap = (uint8_t *)&sa_in6->sin6_addr;
	ep = ap + sizeof(struct in6_addr);
	for (; ap < ep; ap++) {
		/* this "beauty" is adopted from sbin/route/show.c ... */
		switch (*ap) {
		case 0xff:
			l += 8;
			break;
		case 0xfe:
			l += 7;
			goto done;
		case 0xfc:
			l += 6;
			goto done;
		case 0xf8:
			l += 5;
			goto done;
		case 0xf0:
			l += 4;
			goto done;
		case 0xe0:
			l += 3;
			goto done;
		case 0xc0:
			l += 2;
			goto done;
		case 0x80:
			l += 1;
			goto done;
		case 0x00:
			goto done;
		default:
			fatalx("non contiguous inet6 netmask");
		}
	}

 done:
	if (l > sizeof(struct in6_addr) * 8)
		fatalx("%s: prefixlen %d out of bound", __func__, l);
	return (l);
}

int
kroute_compare(struct kroute_node *a, struct kroute_node *b)
{
	if (ntohl(a->r.prefix.s_addr) < ntohl(b->r.prefix.s_addr))
		return (-1);
	if (ntohl(a->r.prefix.s_addr) > ntohl(b->r.prefix.s_addr))
		return (1);
	if (a->r.prefixlen < b->r.prefixlen)
		return (-1);
	if (a->r.prefixlen > b->r.prefixlen)
		return (1);

	/* if the priority is RTP_ANY finish on the first address hit */
	if (a->r.priority == RTP_ANY || b->r.priority == RTP_ANY)
		return (0);
	if (a->r.priority < b->r.priority)
		return (-1);
	if (a->r.priority > b->r.priority)
		return (1);
	return (0);
}

int
kroute6_compare(struct kroute6_node *a, struct kroute6_node *b)
{
	int i;

	for (i = 0; i < 16; i++) {
		if (a->r.prefix.s6_addr[i] < b->r.prefix.s6_addr[i])
			return (-1);
		if (a->r.prefix.s6_addr[i] > b->r.prefix.s6_addr[i])
			return (1);
	}

	if (a->r.prefixlen < b->r.prefixlen)
		return (-1);
	if (a->r.prefixlen > b->r.prefixlen)
		return (1);

	/* if the priority is RTP_ANY finish on the first address hit */
	if (a->r.priority == RTP_ANY || b->r.priority == RTP_ANY)
		return (0);
	if (a->r.priority < b->r.priority)
		return (-1);
	if (a->r.priority > b->r.priority)
		return (1);
	return (0);
}

/*
 * tree management functions
 */

struct kroute_node *
kroute_find(struct ktable *kt, in_addr_t prefix, uint8_t prefixlen,
    uint8_t prio)
{
	struct kroute_node	s;
	struct kroute_node	*kn, *tmp;

	s.r.prefix.s_addr = prefix;
	s.r.prefixlen = prefixlen;
	s.r.priority = prio;

	kn = RB_FIND(kroute_tree, &kt->krt, &s);
	if (kn && prio == RTP_ANY) {
		tmp = RB_PREV(kroute_tree, &kt->krt, kn);
		while (tmp) {
			if (kroute_compare(&s, tmp) == 0)
				kn = tmp;
			else
				break;
			tmp = RB_PREV(kroute_tree, &kt->krt, kn);
		}
	}
	return (kn);
}

struct kroute_node *
kroute_matchgw(struct kroute_node *kr, struct sockaddr_in *sa_in)
{
	in_addr_t	nexthop;

	if (sa_in == NULL) {
		log_warnx("%s: no nexthop defined", __func__);
		return (NULL);
	}
	nexthop = sa_in->sin_addr.s_addr;

	while (kr) {
		if (kr->r.nexthop.s_addr == nexthop)
			return (kr);
		kr = kr->next;
	}

	return (NULL);
}

int
kroute_insert(struct ktable *kt, struct kroute_node *kr)
{
	struct kroute_node	*krm;
	struct knexthop_node	*h;
	in_addr_t		 mask, ina;

	if ((krm = RB_INSERT(kroute_tree, &kt->krt, kr)) != NULL) {
		/* multipath route, add at end of list */
		while (krm->next != NULL)
			krm = krm->next;
		krm->next = kr;
		kr->next = NULL; /* to be sure */
	}

	/* XXX this is wrong for nexthop validated via BGP */
	if (kr->r.flags & F_KERNEL) {
		mask = prefixlen2mask(kr->r.prefixlen);
		ina = ntohl(kr->r.prefix.s_addr);
		RB_FOREACH(h, knexthop_tree, KT2KNT(kt))
			if (h->nexthop.aid == AID_INET &&
			    (ntohl(h->nexthop.v4.s_addr) & mask) == ina)
				knexthop_validate(kt, h);

#ifdef NOTYET
		if (kr->r.flags & F_CONNECTED)
			if (kif_kr_insert(kr) == -1)
				return (-1);
#endif

		if (krm == NULL)
			/* redistribute multipath routes only once */
			kr_redistribute(IMSG_NETWORK_ADD, kt, &kr->r);
	}
	return (0);
}


int
kroute_remove(struct ktable *kt, struct kroute_node *kr)
{
	struct kroute_node	*krm;
	struct knexthop_node	*s;

	if ((krm = RB_FIND(kroute_tree, &kt->krt, kr)) == NULL) {
		log_warnx("%s: failed to find %s/%u", __func__,
		    inet_ntoa(kr->r.prefix), kr->r.prefixlen);
		return (-1);
	}

	if (krm == kr) {
		/* head element */
		if (RB_REMOVE(kroute_tree, &kt->krt, kr) == NULL) {
			log_warnx("%s: failed for %s/%u", __func__,
			    inet_ntoa(kr->r.prefix), kr->r.prefixlen);
			return (-1);
		}
		if (kr->next != NULL) {
			if (RB_INSERT(kroute_tree, &kt->krt, kr->next) !=
			    NULL) {
				log_warnx("%s: failed to add %s/%u", __func__,
				    inet_ntoa(kr->r.prefix), kr->r.prefixlen);
				return (-1);
			}
		}
	} else {
		/* somewhere in the list */
		while (krm->next != kr && krm->next != NULL)
			krm = krm->next;
		if (krm->next == NULL) {
			log_warnx("%s: multipath list corrupted "
			    "for %s/%u", inet_ntoa(kr->r.prefix), __func__,
			    kr->r.prefixlen);
			return (-1);
		}
		krm->next = kr->next;
	}

	/* check whether a nexthop depends on this kroute */
	if (kr->r.flags & F_NEXTHOP)
		RB_FOREACH(s, knexthop_tree, KT2KNT(kt))
			if (s->kroute == kr)
				knexthop_validate(kt, s);

	if (kr->r.flags & F_KERNEL && kr == krm && kr->next == NULL)
		/* again remove only once */
		kr_redistribute(IMSG_NETWORK_REMOVE, kt, &kr->r);

#ifdef NOTYET
	if (kr->r.flags & F_CONNECTED)
		if (kif_kr_remove(kr) == -1) {
			free(kr);
			return (-1);
		}
#endif

	free(kr);
	return (0);
}

void
kroute_clear(struct ktable *kt)
{
	struct kroute_node	*kr;

	while ((kr = RB_MIN(kroute_tree, &kt->krt)) != NULL)
		kroute_remove(kt, kr);
}

struct kroute6_node *
kroute6_find(struct ktable *kt, const struct in6_addr *prefix,
    uint8_t prefixlen, uint8_t prio)
{
	struct kroute6_node	s;
	struct kroute6_node	*kn6, *tmp;

	memcpy(&s.r.prefix, prefix, sizeof(struct in6_addr));
	s.r.prefixlen = prefixlen;
	s.r.priority = prio;

	kn6 = RB_FIND(kroute6_tree, &kt->krt6, &s);
	if (kn6 && prio == RTP_ANY) {
		tmp = RB_PREV(kroute6_tree, &kt->krt6, kn6);
		while (tmp) {
			if (kroute6_compare(&s, tmp) == 0)
				kn6 = tmp;
			else
				break;
			tmp = RB_PREV(kroute6_tree, &kt->krt6, kn6);
		}
	}
	return (kn6);
}

struct kroute6_node *
kroute6_matchgw(struct kroute6_node *kr, struct sockaddr_in6 *sa_in6)
{
	struct in6_addr	nexthop;

	if (sa_in6 == NULL) {
		log_warnx("%s: no nexthop defined", __func__);
		return (NULL);
	}
	memcpy(&nexthop, &sa_in6->sin6_addr, sizeof(nexthop));

	while (kr) {
		if (memcmp(&kr->r.nexthop, &nexthop, sizeof(nexthop)) == 0)
			return (kr);
		kr = kr->next;
	}

	return (NULL);
}

int
kroute6_insert(struct ktable *kt, struct kroute6_node *kr)
{
	struct kroute6_node	*krm;
	struct knexthop_node	*h;
	struct in6_addr		 ina, inb;

	if ((krm = RB_INSERT(kroute6_tree, &kt->krt6, kr)) != NULL) {
		/* multipath route, add at end of list */
		while (krm->next != NULL)
			krm = krm->next;
		krm->next = kr;
		kr->next = NULL; /* to be sure */
	}

	/* XXX this is wrong for nexthop validated via BGP */
	if (kr->r.flags & F_KERNEL) {
		inet6applymask(&ina, &kr->r.prefix, kr->r.prefixlen);
		RB_FOREACH(h, knexthop_tree, KT2KNT(kt))
			if (h->nexthop.aid == AID_INET6) {
				inet6applymask(&inb, &h->nexthop.v6,
				    kr->r.prefixlen);
				if (memcmp(&ina, &inb, sizeof(ina)) == 0)
					knexthop_validate(kt, h);
			}

#ifdef NOTYET
		if (kr->r.flags & F_CONNECTED)
			if (kif_kr6_insert(kr) == -1)
				return (-1);
#endif

		if (krm == NULL)
			/* redistribute multipath routes only once */
			kr_redistribute6(IMSG_NETWORK_ADD, kt, &kr->r);
	}

	return (0);
}

int
kroute6_remove(struct ktable *kt, struct kroute6_node *kr)
{
	struct kroute6_node	*krm;
	struct knexthop_node	*s;

	if ((krm = RB_FIND(kroute6_tree, &kt->krt6, kr)) == NULL) {
		log_warnx("%s: failed for %s/%u", __func__,
		    log_in6addr(&kr->r.prefix), kr->r.prefixlen);
		return (-1);
	}

	if (krm == kr) {
		/* head element */
		if (RB_REMOVE(kroute6_tree, &kt->krt6, kr) == NULL) {
			log_warnx("%s: failed for %s/%u", __func__,
			    log_in6addr(&kr->r.prefix), kr->r.prefixlen);
			return (-1);
		}
		if (kr->next != NULL) {
			if (RB_INSERT(kroute6_tree, &kt->krt6, kr->next) !=
			    NULL) {
				log_warnx("%s: failed to add %s/%u", __func__,
				    log_in6addr(&kr->r.prefix),
				    kr->r.prefixlen);
				return (-1);
			}
		}
	} else {
		/* somewhere in the list */
		while (krm->next != kr && krm->next != NULL)
			krm = krm->next;
		if (krm->next == NULL) {
			log_warnx("%s: multipath list corrupted "
			    "for %s/%u", __func__, log_in6addr(&kr->r.prefix),
			    kr->r.prefixlen);
			return (-1);
		}
		krm->next = kr->next;
	}

	/* check whether a nexthop depends on this kroute */
	if (kr->r.flags & F_NEXTHOP)
		RB_FOREACH(s, knexthop_tree, KT2KNT(kt))
			if (s->kroute == kr)
				knexthop_validate(kt, s);

	if (kr->r.flags & F_KERNEL && kr == krm && kr->next == NULL)
		/* again remove only once */
		kr_redistribute6(IMSG_NETWORK_REMOVE, kt, &kr->r);

#ifdef NOTYET
	if (kr->r.flags & F_CONNECTED)
		if (kif_kr6_remove(kr) == -1) {
			free(kr);
			return (-1);
		}
#endif

	free(kr);
	return (0);
}

void
kroute6_clear(struct ktable *kt)
{
	struct kroute6_node	*kr;

	while ((kr = RB_MIN(kroute6_tree, &kt->krt6)) != NULL)
		kroute6_remove(kt, kr);
}


static void
kr_redistribute(int type, struct ktable *kt, struct kroute *kr)
{
	struct network_config	 net;
	uint32_t		 a;
	int			 loflag = 0;

	bzero(&net, sizeof(net));
	net.prefix.aid = AID_INET;
	net.prefix.v4.s_addr = kr->prefix.s_addr;
	net.prefixlen = kr->prefixlen;
	net.rtlabel = kr->labelid;
	net.priority = kr->priority;

	/* shortcut for removals */
	if (type == IMSG_NETWORK_REMOVE) {
		kr_net_redist_del(kt, &net, 1);
		return;
	}

	if (!(kr->flags & F_KERNEL))
		return;

	/* Dynamic routes are not redistributable. */
	if (kr->flags & F_DYNAMIC)
		return;

	/*
	 * We consider the loopback net, multicast and experimental addresses
	 * as not redistributable.
	 */
	a = ntohl(kr->prefix.s_addr);
	if (IN_MULTICAST(a) || IN_BADCLASS(a) ||
	    (a >> IN_CLASSA_NSHIFT) == IN_LOOPBACKNET)
		return;

	/* Check if the nexthop is the loopback addr. */
	if (kr->nexthop.s_addr == htonl(INADDR_LOOPBACK))
		loflag = 1;

	/*
	 * never allow 0.0.0.0/0 the default route can only be redistributed
	 * with announce default.
	 */
	if (kr->prefix.s_addr == INADDR_ANY && kr->prefixlen == 0)
		return;

	if (kr_net_match(kt, &net, kr->flags, loflag) == 0)
		/* no longer matches, if still present remove it */
		kr_net_redist_del(kt, &net, 1);
}

static void
kr_redistribute6(int type, struct ktable *kt, struct kroute6 *kr6)
{
	struct network_config	net;
	int			loflag = 0;

	bzero(&net, sizeof(net));
	net.prefix.aid = AID_INET6;
	memcpy(&net.prefix.v6, &kr6->prefix, sizeof(struct in6_addr));
	net.prefixlen = kr6->prefixlen;
	net.rtlabel = kr6->labelid;
	net.priority = kr6->priority;

	/* shortcut for removals */
	if (type == IMSG_NETWORK_REMOVE) {
		kr_net_redist_del(kt, &net, 1);
		return;
	}

	if (!(kr6->flags & F_KERNEL))
		return;

	/* Dynamic routes are not redistributable. */
	if (kr6->flags & F_DYNAMIC)
		return;

	/*
	 * We consider unspecified, loopback, multicast, link- and site-local,
	 * IPv4 mapped and IPv4 compatible addresses as not redistributable.
	 */
	if (IN6_IS_ADDR_UNSPECIFIED(&kr6->prefix) ||
	    IN6_IS_ADDR_LOOPBACK(&kr6->prefix) ||
	    IN6_IS_ADDR_MULTICAST(&kr6->prefix) ||
	    IN6_IS_ADDR_LINKLOCAL(&kr6->prefix) ||
	    IN6_IS_ADDR_SITELOCAL(&kr6->prefix) ||
	    IN6_IS_ADDR_V4MAPPED(&kr6->prefix) ||
	    IN6_IS_ADDR_V4COMPAT(&kr6->prefix))
		return;

	/* Check if the nexthop is the loopback addr. */
	if (IN6_IS_ADDR_LOOPBACK(&kr6->nexthop))
		loflag = 1;

	/*
	 * never allow ::/0 the default route can only be redistributed
	 * with announce default.
	 */
	if (kr6->prefixlen == 0 &&
	    memcmp(&kr6->prefix, &in6addr_any, sizeof(struct in6_addr)) == 0)
		return;

	if (kr_net_match(kt, &net, kr6->flags, loflag) == 0)
		/* no longer matches, if still present remove it */
		kr_net_redist_del(kt, &net, 1);
}

int
kr_net_match(struct ktable *kt, struct network_config *net, uint16_t flags,
    int loopback)
{
	struct network		*xn;

	TAILQ_FOREACH(xn, &kt->krn, entry) {
		if (xn->net.prefix.aid != net->prefix.aid)
			continue;
		switch (xn->net.type) {
		case NETWORK_DEFAULT:
			/* static match already redistributed */
			continue;
		case NETWORK_STATIC:
			/* Skip networks with nexthop on loopback. */
			if (loopback)
				continue;
			if (flags & F_STATIC)
				break;
			continue;
		case NETWORK_CONNECTED:
			/* Skip networks with nexthop on loopback. */
			if (loopback)
				continue;
			if (flags & F_CONNECTED)
				break;
			continue;
		case NETWORK_RTLABEL:
			if (net->rtlabel == xn->net.rtlabel)
				break;
			continue;
		case NETWORK_PRIORITY:
			if (net->priority == xn->net.priority)
				break;
			continue;
		case NETWORK_MRTCLONE:
		case NETWORK_PREFIXSET:
			/* must not happen */
			log_warnx("%s: found a NETWORK_PREFIXSET, "
			    "please send a bug report", __func__);
			continue;
		}

		net->rd = xn->net.rd;
		if (kr_net_redist_add(kt, net, &xn->net.attrset, 1))
			return (1);
	}
	return (0);
}

struct kif_node *
kif_find(int ifindex)
{
	struct kif_node	s;

	bzero(&s, sizeof(s));
	s.k.ifindex = ifindex;

	return (RB_FIND(kif_tree, &kit, &s));
}

int
kif_compare(struct kif_node *a, struct kif_node *b)
{
	return (b->k.ifindex - a->k.ifindex);
}

int
kif_insert(struct kif_node *kif)
{
	LIST_INIT(&kif->kroute_l);
	LIST_INIT(&kif->kroute6_l);

	if (RB_INSERT(kif_tree, &kit, kif) != NULL) {
		log_warnx("RB_INSERT(kif_tree, &kit, kif)");
		free(kif);
		return (-1);
	}

	return (0);
}

int
kif_remove(struct kif_node *kif, u_int rdomain)
{
	struct ktable	*kt;
	struct kif_kr	*kkr;
	struct kif_kr6	*kkr6;

	if (RB_REMOVE(kif_tree, &kit, kif) == NULL) {
		log_warnx("RB_REMOVE(kif_tree, &kit, kif)");
		return (-1);
	}

	if ((kt = ktable_get(rdomain)) == NULL)
		goto done;

	while ((kkr = LIST_FIRST(&kif->kroute_l)) != NULL) {
		LIST_REMOVE(kkr, entry);
		kkr->kr->r.flags &= ~F_NEXTHOP;
		kroute_remove(kt, kkr->kr);
		free(kkr);
	}

	while ((kkr6 = LIST_FIRST(&kif->kroute6_l)) != NULL) {
		LIST_REMOVE(kkr6, entry);
		kkr6->kr->r.flags &= ~F_NEXTHOP;
		kroute6_remove(kt, kkr6->kr);
		free(kkr6);
	}
done:
	free(kif);
	return (0);
}

void
kif_clear(u_int rdomain)
{
	struct kif_node	*kif;

	while ((kif = RB_MIN(kif_tree, &kit)) != NULL)
		kif_remove(kif, rdomain);
}

int
kif_kr_insert(struct kroute_node *kr)
{
	struct kif_node	*kif;
	struct kif_kr	*kkr;

	if ((kif = kif_find(kr->r.ifindex)) == NULL) {
		if (kr->r.ifindex)
			log_warnx("%s: interface with index %u not found",
			    __func__, kr->r.ifindex);
		return (0);
	}

	if (kif->k.nh_reachable)
		kr->r.flags &= ~F_DOWN;
	else
		kr->r.flags |= F_DOWN;

	if ((kkr = calloc(1, sizeof(struct kif_kr))) == NULL) {
		log_warn("%s", __func__);
		return (-1);
	}

	kkr->kr = kr;

	LIST_INSERT_HEAD(&kif->kroute_l, kkr, entry);

	return (0);
}

int
kif_kr_remove(struct kroute_node *kr)
{
	struct kif_node	*kif;
	struct kif_kr	*kkr;

	if ((kif = kif_find(kr->r.ifindex)) == NULL) {
		if (kr->r.ifindex)
			log_warnx("%s: interface with index %u not found",
			    __func__, kr->r.ifindex);
		return (0);
	}

	for (kkr = LIST_FIRST(&kif->kroute_l); kkr != NULL && kkr->kr != kr;
	    kkr = LIST_NEXT(kkr, entry))
		;	/* nothing */

	if (kkr == NULL) {
		log_warnx("%s: can't remove connected route from interface "
		    "with index %u: not found", __func__, kr->r.ifindex);
		return (-1);
	}

	LIST_REMOVE(kkr, entry);
	free(kkr);

	return (0);
}

int
kif_kr6_insert(struct kroute6_node *kr)
{
	struct kif_node	*kif;
	struct kif_kr6	*kkr6;

	if ((kif = kif_find(kr->r.ifindex)) == NULL) {
		if (kr->r.ifindex)
			log_warnx("%s: interface with index %u not found",
			    __func__, kr->r.ifindex);
		return (0);
	}

	if (kif->k.nh_reachable)
		kr->r.flags &= ~F_DOWN;
	else
		kr->r.flags |= F_DOWN;

	if ((kkr6 = calloc(1, sizeof(struct kif_kr6))) == NULL) {
		log_warn("%s", __func__);
		return (-1);
	}

	kkr6->kr = kr;

	LIST_INSERT_HEAD(&kif->kroute6_l, kkr6, entry);

	return (0);
}

int
kif_kr6_remove(struct kroute6_node *kr)
{
	struct kif_node	*kif;
	struct kif_kr6	*kkr6;

	if ((kif = kif_find(kr->r.ifindex)) == NULL) {
		if (kr->r.ifindex)
			log_warnx("%s: interface with index %u not found",
			    __func__, kr->r.ifindex);
		return (0);
	}

	for (kkr6 = LIST_FIRST(&kif->kroute6_l); kkr6 != NULL && kkr6->kr != kr;
	    kkr6 = LIST_NEXT(kkr6, entry))
		;	/* nothing */

	if (kkr6 == NULL) {
		log_warnx("%s: can't remove connected route from interface "
		    "with index %u: not found", __func__, kr->r.ifindex);
		return (-1);
	}

	LIST_REMOVE(kkr6, entry);
	free(kkr6);

	return (0);
}
