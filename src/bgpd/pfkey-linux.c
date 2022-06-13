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

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <string.h>

#include "bgpd.h"
#include "session.h"
#include "log.h"

int
pfkey_read(int sd, struct sadb_msg *h)
{
	log_warnx("pfkey read disabled");
	return (-1);
}

int
pfkey_establish(struct peer *p)
{
	if (!p->auth.method)
		return (0);
	else
		return (-1);
}

int
pfkey_remove(struct peer *p)
{
	if (!p->auth.established)
		return (0);
	else
		return (-1);
}

int
pfkey_init(void)
{
	log_warnx("PF_KEY not available, disabling ipsec");
	return (-1);
}

int
tcp_md5_check(int fd, struct peer *p)
{
	/*
	 * No need to do the check on Linux.
	 * Only two options get us here:
	 *  - the session has no md5 and the SYN had no md5 option
	 *  - the session has md5 and the SYN had a valid md5 hash
	 */
	return (0);
}

/*
 * Add the TCP MD5SUM key to the kernel to enable TCP MD5SUM.
 */
static int
install_tcp_md5(int fd, struct bgpd_addr *addr, char *key, uint8_t key_len)
{
	struct tcp_md5sig md5;
	struct sockaddr *sa;
	socklen_t sa_len;

	if (key_len > TCP_MD5SIG_MAXKEYLEN) {
		/* not be possible unless TCP_MD5_KEY_LEN changes */
		errno = EINVAL;
		return -1;
	}

	memset(&md5, 0, sizeof(md5));
	if (key_len != 0) {
		md5.tcpm_keylen = key_len;
		memcpy(&md5.tcpm_key, key, md5.tcpm_keylen);
	}

	sa = addr2sa(addr, 0, &sa_len);
	memcpy(&md5.tcpm_addr, sa, sa_len);

	if (setsockopt(fd, IPPROTO_TCP, TCP_MD5SIG, &md5, sizeof(md5)) == -1) {
		/* ignore removals that fail because addr is not present */
		if (errno == ENOENT && key_len == 0)
			return 0;
		return -1;
	}
	return 0;
}

int
tcp_md5_set(int fd, struct peer *p)
{

	if (p->conf.auth.method == AUTH_MD5SIG) {
		if (install_tcp_md5(fd, &p->conf.remote_addr,
		    p->conf.auth.md5key, p->conf.auth.md5key_len) == -1) {
			log_peer_warn(&p->conf, "setsockopt md5sig");
			return -1;
		}
	}
	return 0;
}

static int
listener_match_peer(struct listen_addr *la, struct peer *p)
{
	struct sockaddr *sa, *la_sa;
	socklen_t sa_len;

	la_sa = (struct sockaddr *)&la->sa;

	/* first check remote_addr to be in same address family as socket */
	if (aid2af(p->conf.remote_addr.aid) != la_sa->sa_family)
		return 0;

	switch (p->conf.remote_addr.aid) {
	case AID_INET:
		sa = addr2sa(&p->conf.local_addr_v4, BGP_PORT, &sa_len);
		break;
	case AID_INET6:
		sa = addr2sa(&p->conf.local_addr_v6, BGP_PORT, &sa_len);
		break;
	default:
		return 0;
	}
	if (sa == NULL)
		/* undefined bind address will match any listener */
		return 1;

	if (sa_len == la->sa_len &&
	    memcmp(&sa->sa_data, &la_sa->sa_data, sa_len - 2) == 0)
		return 1;
	return 0;
}

int
tcp_md5_prep_listener(struct listen_addr *la, struct peer_head *peers)
{
	struct peer *p;

	RB_FOREACH(p, peer_head, peers) {
		if (p->conf.auth.method == AUTH_MD5SIG) {
			if (listener_match_peer(la, p) == 0)
				continue;

			if (install_tcp_md5(la->fd, &p->conf.remote_addr,
			    p->conf.auth.md5key,
			    p->conf.auth.md5key_len) == -1) {
				log_peer_warn(&p->conf,
				   "setsockopt md5sig on listening socket");
				return -1;
			}
		}
	}
	return 0;
}

void
tcp_md5_add_listener(struct bgpd_config *conf, struct peer *p)
{
	struct listen_addr *la;

	TAILQ_FOREACH(la, conf->listen_addrs, entry) {
		if (listener_match_peer(la, p) == 0)
			continue;

		if (install_tcp_md5(la->fd, &p->conf.remote_addr,
		    p->conf.auth.md5key, p->conf.auth.md5key_len) == -1)
			log_peer_warn(&p->conf,
			   "failed deletion of md5sig on listening socket");
	}
}

void
tcp_md5_del_listener(struct bgpd_config *conf, struct peer *p)
{
	struct listen_addr *la;

	TAILQ_FOREACH(la, conf->listen_addrs, entry) {
		if (listener_match_peer(la, p) == 0)
			continue;

		if (install_tcp_md5(la->fd, &p->conf.remote_addr,
		    NULL, 0) == -1)
			log_peer_warn(&p->conf,
			   "failed deletion of md5sig on listening socket");
	}
}
