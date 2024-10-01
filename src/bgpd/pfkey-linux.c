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
pfkey_establish(struct auth_state *as, struct auth_config *auth,
    const struct bgpd_addr *local_addr, const struct bgpd_addr *remote_addr)
{
	switch (auth->method) {
	case AUTH_NONE:
	case AUTH_MD5SIG:
		return (0);
	default:
		return (-1);
	}
}

int
pfkey_remove(struct auth_state *as)
{
	if (as->established == 0)
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
pfkey_send_conf(struct imsgbuf *imsgbuf, uint32_t id, struct auth_config *auth)
{
	/* SE needs the full md5 data (and there is no IPSec) */
	return imsg_compose(imsgbuf, IMSG_RECONF_PEER_AUTH, id, 0, -1,
	    auth, sizeof(*auth));
}

int
pfkey_recv_conf(struct peer *p, struct imsg *imsg)
{
	struct auth_config *auth = &p->auth_conf;

	return imsg_get_data(imsg, auth, sizeof(*auth));
}

int
tcp_md5_check(int fd, struct auth_config *auth)
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
tcp_md5_set(int fd, struct auth_config *auth, struct bgpd_addr *remote_addr)
{
	if (auth->method == AUTH_MD5SIG) {
		if (install_tcp_md5(fd, remote_addr, auth->md5key,
		    auth->md5key_len) == -1)
			return -1;
	}
	return 0;
}

static int
listener_match_peer(struct listen_addr *la, struct peer *p)
{
	struct bgpd_addr listen_addr, *local_addr;

	sa2addr((struct sockaddr *)&la->sa, &listen_addr, NULL);

	/* first check remote_addr to be in same address family as socket */
	if (p->conf.remote_addr.aid != listen_addr.aid)
		return 0;

	/* check if listening socket uses "wildcard" address */
	switch (listen_addr.aid) {
	case AID_INET:
		if (listen_addr.v4.s_addr == htonl(INADDR_ANY))
			return 1;
		break;
	case AID_INET6:
		if (IN6_IS_ADDR_UNSPECIFIED(&listen_addr.v6))
			return 1;
		break;
	default:
		fatalx("%s: %s is unsupported", __func__,
		    aid2str(listen_addr.aid));
	}

	switch (p->conf.remote_addr.aid) {
	case AID_INET:
		local_addr = &p->conf.local_addr_v4;
		break;
	case AID_INET6:
		local_addr = &p->conf.local_addr_v6;
		break;
	default:
		fatalx("%s: %s is unsupported", __func__,
		    aid2str(p->conf.remote_addr.aid));
	}
	if (local_addr->aid == AID_UNSPEC)
		/* undefined bind address will match any listener */
		return 1;

	if (memcmp(&listen_addr, local_addr, sizeof(listen_addr)) == 0)
		return 1;
	return 0;
}

int
tcp_md5_prep_listener(struct listen_addr *la, struct peer_head *peers)
{
	struct peer *p;

	RB_FOREACH(p, peer_head, peers) {
		if (p->auth_conf.method == AUTH_MD5SIG) {
			if (listener_match_peer(la, p) == 0)
				continue;

			if (install_tcp_md5(la->fd, &p->conf.remote_addr,
			    p->auth_conf.md5key,
			    p->auth_conf.md5key_len) == -1) {
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
		    p->auth_conf.md5key, p->auth_conf.md5key_len) == -1)
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
