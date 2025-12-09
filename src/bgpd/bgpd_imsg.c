#include <errno.h>

#include "bgpd.h"
#include "log.h"

int
imsg_send_filterset(struct imsgbuf *imsgbuf, struct filter_set_head *set)
{
	struct filter_set	*s;
	struct ibuf		*msg;
	int			 nsets = 0;

	msg = imsg_create(imsgbuf, IMSG_FILTER_SET, 0, 0, 0);
	if (msg == NULL)
		return -1;

	TAILQ_FOREACH(s, set, entry)
		nsets++;
	if (ibuf_add_n16(msg, nsets) == -1)
		goto fail;

	TAILQ_FOREACH(s, set, entry) {
		if (ibuf_add_n32(msg, s->type) == -1)
			goto fail;

		switch (s->type) {
		case ACTION_SET_PREPEND_SELF:
		case ACTION_SET_PREPEND_PEER:
			if (ibuf_add_n8(msg, s->action.prepend) == -1)
				goto fail;
			break;
		case ACTION_SET_AS_OVERRIDE:
			break;
		case ACTION_SET_LOCALPREF:
		case ACTION_SET_MED:
		case ACTION_SET_WEIGHT:
			if (ibuf_add_n32(msg, s->action.metric) == -1)
				goto fail;
			break;
		case ACTION_SET_RELATIVE_LOCALPREF:
		case ACTION_SET_RELATIVE_MED:
		case ACTION_SET_RELATIVE_WEIGHT:
			if (ibuf_add_n32(msg, s->action.relative) == -1)
				goto fail;
			break;
		case ACTION_SET_NEXTHOP:
			if (ibuf_add(msg, &s->action.nexthop,
			    sizeof(s->action.nexthop)) == -1)
				goto fail;
			break;
		case ACTION_SET_NEXTHOP_BLACKHOLE:
		case ACTION_SET_NEXTHOP_REJECT:
		case ACTION_SET_NEXTHOP_NOMODIFY:
		case ACTION_SET_NEXTHOP_SELF:
			break;
		case ACTION_DEL_COMMUNITY:
		case ACTION_SET_COMMUNITY:
			if (ibuf_add(msg, &s->action.community,
			    sizeof(s->action.community)) == -1)
				goto fail;
			break;
		case ACTION_PFTABLE:
			if (ibuf_add_strbuf(msg, s->action.pftable,
			    sizeof(s->action.pftable)) == -1)
				goto fail;
			break;
		case ACTION_RTLABEL:
			if (ibuf_add_strbuf(msg, s->action.rtlabel,
			    sizeof(s->action.rtlabel)) == -1)
				goto fail;
			break;
		case ACTION_SET_ORIGIN:
			if (ibuf_add_n8(msg, s->action.origin) == -1)
				goto fail;
			break;
		case ACTION_SET_NEXTHOP_REF:
		case ACTION_RTLABEL_ID:
		case ACTION_PFTABLE_ID:
			goto fail;
		}
	}

	imsg_close(imsgbuf, msg);
	return 0;

fail:
	ibuf_free(msg);
	return -1;
}

