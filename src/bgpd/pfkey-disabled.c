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

int
tcp_md5_set(int fd, struct peer *p)
{
	return (0);
}

int
tcp_md5_prep_listener(struct listen_addr *la, struct peer_head *p)
{
	return (0);
}

/* add md5 key to all listening sockets, dummy function for portable */
void
tcp_md5_add_listener(struct bgpd_config *conf, struct peer *p)
{
}

/* delete md5 key form all listening sockets, dummy function for portable */
void
tcp_md5_del_listener(struct bgpd_config *conf, struct peer *p)
{
}
