/*
 * PDS network helpers
 *
 * Copyright (c) 2017-2018 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "pds.h"

struct sk_buff *pds_rx_prepare(struct sk_buff *skb)
{
	if (skb->pkt_type == PACKET_OTHERHOST)
		goto drop;

	if ((skb = skb_share_check(skb, GFP_ATOMIC)) == NULL)
		return NULL;

	if (!skb_is_nonlinear(skb) || skb_linearize(skb) == 0)
		return skb;
drop:
	kfree_skb(skb);
	return NULL;
}

struct sk_buff *pds_alloc_skb(struct pds *pds, int type, unsigned len)
{
	struct net_device *dev = pds->master;
	struct sk_buff *skb;

	skb = netdev_alloc_skb(dev, len);
	if (skb == NULL)
		return NULL;

	skb_reset_network_header(skb);
	dev_hard_header(skb, dev, type, dev->broadcast, NULL, 0);
	return skb;
}

static
struct sk_buff *pds_hdlc_alloc_skb(struct dahdi_chan *o, unsigned len)
{
	struct pds_span *s = container_of(o->span, struct pds_span, span);
	struct sk_buff *skb;
	struct pds_hdlc_header *h;

	skb = pds_alloc_skb(o->pvt, ETH_P_PDS_HDLC, sizeof(*h) + len);
	if (skb == NULL)
		return NULL;

	h = (void *) skb_put(skb, sizeof(*h));

	h->span		= htons(o->span->offset + 1);
	h->cutoff	= len < 256 ? len : 0;
	h->flags	= 0;
	h->seq		= htons(atomic_inc_return(&s->hdlc_seq));
	h->channel	= htons(o->chanpos + 1);

	skb_set_transport_header(skb, 0);
	return skb;
}

int pds_hdlc_emit(struct dahdi_chan *o, const void *buf, size_t len)
{
	struct sk_buff *skb;

	skb = pds_hdlc_alloc_skb(o, len);
	if (skb == NULL)
		return -ENOMEM;

	memcpy(skb_put(skb, len), buf, len);

	pds_debug("%s: emit HDLC frame, %zu bytes\n", o->name, len);
	dev_queue_xmit(skb);
	return 0;
}

static
struct sk_buff *pds_ctl_alloc_skb(struct pds_span *o, int code, unsigned len)
{
	struct sk_buff *skb;
	struct pds_ctl_header *h;

	skb = pds_alloc_skb(pds_from_span(o), ETH_P_PDS_CTL, sizeof(*h) + len);
	if (skb == NULL)
		return NULL;

	h = (void *) skb_put(skb, sizeof(*h));

	h->span		= htons(o->span.offset + 1);
	h->code		= code;
	h->flags	= 0;
	h->seq		= htons(atomic_inc_return(&o->ctl_seq));

	skb_set_transport_header(skb, 0);
	return skb;
}

static
struct sk_buff *pds_ctl_start(struct pds_span *o, int code, unsigned len)
{
	struct sk_buff *skb;

	mutex_lock(&o->ctl_lock);

	skb = pds_ctl_alloc_skb(o, code, len);
	if (skb == NULL)
		goto no_skb;

	pds_req_start(&o->req, htons(atomic_read(&o->ctl_seq)), skb);
	return skb;
no_skb:
	mutex_unlock(&o->ctl_lock);
	return NULL;
}

static int pds_error_to_errno(enum pds_error e)
{
	switch (e) {
	case PDS_STATUS_OK:	return 0;
	case PDS_STATUS_NOSYS:	return ENOSYS;
	case PDS_STATUS_INVAL:	return EINVAL;
	case PDS_STATUS_BUSY:	return EBUSY;
	}

	return EPROTO;
}

static int pds_ctl_get_status(struct pds_span *o, int *ret)
{
	struct sk_buff *reply = pds_req_result(&o->req);
	struct pds_ctl_status *p;
	int found = 0;

	if (reply != NULL) {
		if (reply->len >= (sizeof (*p))) {
			p = (void *) reply->data;
			*ret = -pds_error_to_errno(ntohs(p->status));
			found = 1;
		}

		dev_kfree_skb(reply);
	}

	return found;
}

static int dev_queue_xmit_copy(struct sk_buff *skb)
{
	skb = skb_clone(skb, GFP_KERNEL);
	if (skb == NULL)
		return -ENOMEM;

	dev_queue_xmit(skb);
	return 0;
}

static int pds_ctl_done(struct pds_span *o)
{
	int ret = 0, i;
	long timeout;

	for (i = 3; i > 0; --i) {
		ret = dev_queue_xmit_copy(o->req.req);
		if (ret != 0)
			continue;

		for (timeout = HZ / 20; timeout > 0;) {
			timeout = schedule_timeout_uninterruptible(timeout);

			if (pds_ctl_get_status(o, &ret))
				goto done;
		}
	}
done:
	pds_req_end(&o->req);
	mutex_unlock(&o->ctl_lock);
	return ret;
}

int pds_ctl_reset(struct pds_span *o)
{
	struct sk_buff *skb;

	skb = pds_ctl_start(o, PDS_RESET, 0);
	if (skb == NULL)
		return -ENOMEM;

	pds_debug("%s: emit reset\n", o->span.name);
	return pds_ctl_done(o);
}

int pds_ctl_setup(struct pds_span *o, int sync, enum pds_line_code code,
		  enum pds_framing framing, enum pds_signaling sig)
{
	struct sk_buff *skb;
	__be16 *p;
	size_t len = sizeof (p[0]) * 4;

	skb = pds_ctl_start(o, PDS_SETUP, len);
	if (skb == NULL)
		return -ENOMEM;

	p = (void *) skb_put(skb, len);

	p[0] = htons(sync);
	p[1] = htons(code);
	p[2] = htons(framing);
	p[3] = htons(sig);

	pds_debug("%s: emit setup (sync = %d, code = %d, framing = %d, sig = %d)\n",
		  o->span.name, sync, code, framing, sig);
	return pds_ctl_done(o);
}

int pds_ctl_enslave(struct dahdi_chan *o)
{
	struct pds_span *s = container_of(o->span, struct pds_span, span);
	struct sk_buff *skb;
	__be16 *p;
	size_t len = sizeof (p[0]) * 2;

	skb = pds_ctl_start(s, PDS_ENSLAVE, len);
	if (skb == NULL)
		return -ENOMEM;

	p = (void *) skb_put(skb, len);

	p[0] = htons(o->chanpos + 1);
	p[1] = htons(o->master->chanpos + 1);

	pds_debug("%s: emit enslave to %s\n", o->name, o->master->name);
	return pds_ctl_done(s);
}

int pds_ctl_tdm_open(struct dahdi_chan *o)
{
	struct pds_span *s = container_of(o->span, struct pds_span, span);
	struct sk_buff *skb;
	__be16 *p;
	size_t len = sizeof (p[0]) * 1;

	skb = pds_ctl_start(s, PDS_OPEN_TDM, len);
	if (skb == NULL)
		return -ENOMEM;

	p = (void *) skb_put(skb, len);

	p[0] = htons(o->chanpos + 1);

	pds_debug("%s: emit TDM open\n", o->name);
	return pds_ctl_done(s);
}

int pds_ctl_hdlc_open(struct dahdi_chan *o)
{
	struct pds_span *s = container_of(o->span, struct pds_span, span);
	struct sk_buff *skb;
	__be16 *p;
	size_t len = sizeof (p[0]) * 1;

	skb = pds_ctl_start(s, PDS_OPEN_HDLC, len);
	if (skb == NULL)
		return -ENOMEM;

	p = (void *) skb_put(skb, len);

	p[0] = htons(o->chanpos + 1);

	pds_debug("%s: emit HDLC open\n", o->name);
	return pds_ctl_done(s);
}

int pds_ctl_close(struct dahdi_chan *o)
{
	struct pds_span *s = container_of(o->span, struct pds_span, span);
	struct sk_buff *skb;
	__be16 *p;
	size_t len = sizeof (p[0]) * 1;

	skb = pds_ctl_start(s, PDS_CLOSE, len);
	if (skb == NULL)
		return -ENOMEM;

	p = (void *) skb_put(skb, len);

	p[0] = htons(o->chanpos + 1);

	pds_debug("%s: emit close\n", o->name);
	return pds_ctl_done(s);
}
