/*
 * PDS network helpers
 *
 * Copyright (c) 2017 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "pds.h"

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

int pds_hdlc_emit(struct dahdi_chan *o, const void *buf, size_t len)
{
	struct pds_span *s = container_of(o->span, struct pds_span, span);
	struct sk_buff *skb;
	struct pds_hdlc_header *h;

	skb = pds_alloc_skb(o->pvt, ETH_P_PDS_HDLC, sizeof(*h) + len);
	if (skb == NULL)
		return -ENOMEM;

	h = (void *) skb_put(skb, sizeof(*h));

	h->span		= htons(o->span->offset + 1);
	h->reserved	= 0;
	h->flags	= 0;
	h->seq		= htons(s->hdlc_seq++);
	h->channel	= htons(o->chanpos + 1);

	skb_set_transport_header(skb, 0);
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
	h->seq		= htons(o->ctl_seq++);

	skb_set_transport_header(skb, 0);
	return skb;
}

int pds_ctl_reset(struct pds_span *o)
{
	struct sk_buff *skb;

	skb = pds_ctl_alloc_skb(o, PDS_RESET, 0);
	if (skb == NULL)
		return -ENOMEM;

	pds_debug("%s: emit reset\n", o->span.name);
	dev_queue_xmit(skb);
	return 0;
}

int pds_ctl_setup(struct pds_span *o, int sync, enum pds_line_code code,
		  enum pds_framing framing, enum pds_signaling sig)
{
	struct sk_buff *skb;
	__be16 *p;
	size_t len = sizeof (p[0]) * 4;

	skb = pds_ctl_alloc_skb(o, PDS_SETUP, len);
	if (skb == NULL)
		return -ENOMEM;

	p = (void *) skb_put(skb, len);

	p[0] = htons(sync);
	p[1] = htons(code);
	p[2] = htons(framing);
	p[3] = htons(sig);

	pds_debug("%s: emit setup (sync = %d, code = %d, framing = %d, sig = %d)\n",
		  o->span.name, sync, code, framing, sig);
	dev_queue_xmit(skb);
	return 0;
}

int pds_ctl_enslave(struct dahdi_chan *o)
{
	struct pds_span *s = container_of(o->span, struct pds_span, span);
	struct sk_buff *skb;
	__be16 *p;
	size_t len = sizeof (p[0]) * 2;

	skb = pds_ctl_alloc_skb(s, PDS_ENSLAVE, len);
	if (skb == NULL)
		return -ENOMEM;

	p = (void *) skb_put(skb, len);

	p[0] = htons(o->chanpos + 1);
	p[1] = htons(o->master->chanpos + 1);

	pds_debug("%s: emit enslave to %s\n", o->name, o->master->name);
	dev_queue_xmit(skb);
	return 0;
}

int pds_ctl_tdm_open(struct dahdi_chan *o)
{
	struct pds_span *s = container_of(o->span, struct pds_span, span);
	struct sk_buff *skb;
	__be16 *p;
	size_t len = sizeof (p[0]) * 1;

	skb = pds_ctl_alloc_skb(s, PDS_OPEN_TDM, len);
	if (skb == NULL)
		return -ENOMEM;

	p = (void *) skb_put(skb, len);

	p[0] = htons(o->chanpos + 1);

	pds_debug("%s: emit TDM open\n", o->name);
	dev_queue_xmit(skb);
	return 0;
}

int pds_ctl_hdlc_open(struct dahdi_chan *o)
{
	struct pds_span *s = container_of(o->span, struct pds_span, span);
	struct sk_buff *skb;
	__be16 *p;
	size_t len = sizeof (p[0]) * 1;

	skb = pds_ctl_alloc_skb(s, PDS_OPEN_HDLC, len);
	if (skb == NULL)
		return -ENOMEM;

	p = (void *) skb_put(skb, len);

	p[0] = htons(o->chanpos + 1);

	pds_debug("%s: emit HDLC open\n", o->name);
	dev_queue_xmit(skb);
	return 0;
}

int pds_ctl_close(struct dahdi_chan *o)
{
	struct pds_span *s = container_of(o->span, struct pds_span, span);
	struct sk_buff *skb;
	__be16 *p;
	size_t len = sizeof (p[0]) * 1;

	skb = pds_ctl_alloc_skb(s, PDS_CLOSE, len);
	if (skb == NULL)
		return -ENOMEM;

	p = (void *) skb_put(skb, len);

	p[0] = htons(o->chanpos + 1);

	pds_debug("%s: emit close\n", o->name);
	dev_queue_xmit(skb);
	return 0;
}
