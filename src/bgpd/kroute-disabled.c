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
kr_init(void)
{
	/* XXX need to return an FD that can be polled */
	return (-1);
}

void
kr_shutdown(u_int8_t fib_prio, u_int rdomain)
{
}

void
kr_fib_couple(u_int rtableid, u_int8_t fib_prio)
{
}

void
kr_fib_couple_all(u_int8_t fib_prio)
{
}

void
kr_fib_decouple(u_int rtableid, u_int8_t fib_prio)
{
}

void
kr_fib_decouple_all(u_int8_t fib_prio)
{
}

void
kr_fib_update_prio_all(u_int8_t fib_prio)
{
}

int
kr_dispatch_msg(u_int rdomain)
{
	return (0);
}

int
kr_change(u_int rtableid, struct kroute_full *kl, u_int8_t fib_prio)
{
	return (0);
}

int
kr_delete(u_int rtableid, struct kroute_full *kl, u_int8_t fib_prio)
{
	return (0);
}

int
kr_nexthop_add(u_int rtableid, struct bgpd_addr *addr, struct bgpd_config *conf)
{
	return (-1);
}

void
kr_nexthop_delete(u_int rtableid, struct bgpd_addr *addr,
    struct bgpd_config *conf)
{
}

int
kr_reload(void)
{
	return (0);
}

void
kr_net_reload(u_int rtableid, u_int64_t rd, struct network_head *nh)
{
}

void
kr_show_route(struct imsg *imsg)
{
	u_int code = CTL_RES_DENIED /* XXX */;

	send_imsg_session(IMSG_CTL_RESULT, imsg->hdr.pid,
	    &code, sizeof(code));
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

int
ktable_update(u_int rtableid, char *name, int flags, u_int8_t fib_prio)
{
	return (0);
}

void
ktable_preload(void)
{
}

void
ktable_postload(u_int8_t fib_prio)
{
}

int
get_mpe_config(const char *name, u_int *rdomain, u_int *label)
{
	return (-1);
}
