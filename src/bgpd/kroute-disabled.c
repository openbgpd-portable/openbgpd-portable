/*	$OpenBSD$ */

/*
 * Copyright (c) 2019 Claudio Jeker <claudio@openbsd.org>
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

#include "bgpd.h"
#include "session.h"
#include "log.h"

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

struct ktable	 krt;
const u_int	 krt_size = 1;

struct ktable	*ktable_get(u_int);

static uint8_t	mask2prefixlen(in_addr_t);
static uint8_t	mask2prefixlen6(struct sockaddr_in6 *);

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

void	knexthop_send_update(struct knexthop_node *);

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

	/* XXX need to return an FD that can be polled */
	*fd = -1;
	return (0);
}

void
kr_shutdown(uint8_t fib_prio, u_int rdomain)
{
	knexthop_clear(&krt);
}

void
kr_fib_couple(u_int rtableid, uint8_t fib_prio)
{
}

void
kr_fib_couple_all(uint8_t fib_prio)
{
}

void
kr_fib_decouple(u_int rtableid, uint8_t fib_prio)
{
}

void
kr_fib_decouple_all(uint8_t fib_prio)
{
}

void
kr_fib_update_prio_all(uint8_t fib_prio)
{
}

int
kr_dispatch_msg(u_int rdomain)
{
	return (0);
}

int
kr_change(u_int rtableid, struct kroute_full *kl, uint8_t fib_prio)
{
	return (0);
}

int
kr_delete(u_int rtableid, struct kroute_full *kl, uint8_t fib_prio)
{
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

int
kr_flush(u_int rtableid)
{
	/* nothing to flush for now */
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
	u_int		 l = 0;

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
