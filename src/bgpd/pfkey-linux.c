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

#include <netinet/tcp.h>

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
	return (0);
}

/*
 * This function needs to be called on socket that is already bound locally.
 */
int
tcp_md5_set(int fd, struct peer *p)
{
	struct tcp_md5sig md5;
	struct sockaddr sa;
	socklen_t sa_len;

	memset(&md5, 0, sizeof(md5));
	if (p->conf.auth.method == AUTH_MD5SIG) {
		if (p->conf.auth.md5key_len > TCP_MD5SIG_MAXKEYLEN) {
			/* should not be possible */
			log_peer_warn(&p->conf, "md5sig key too long");
			return -1;
		}
		md5.tcpm_keylen = p->conf.auth.md5key_len;
		memcpy(&md5.tcpm_key, p->conf.auth.md5key, md5.tcpm_keylen);

		sa = addr2sa(&p->conf.remote_addr, 0, &sa_len);
		memcpy(&md5.tcpm_addr, sa, sa_len);

		if (setsockopt(fd, IPPROTO_TCP, TCP_MD5SIG,
		    &md5, sizeof(md5)) == -1) {
			log_peer_warn(&p->conf, "setsockopt md5sig");
			return -1;
		}
	}

	return 0;
}

int
tcp_md5_listen(int fd, struct peer_head *p)
{
	return (0);
}
