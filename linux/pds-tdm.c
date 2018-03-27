/*
 * PDS TDM worker
 *
 * Copyright (c) 2017 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "pds.h"

static size_t pds_tdm_channel_count(struct pds_span *s)
{
	unsigned long i;
	size_t count = 0;

	for_each_set_bit(i, s->tdm.open, s->span.channels)
		++count;

	return count;
}

static size_t pds_tdm_sigmap_size(size_t count)
{
	return (count + 3) / 4;
}

static void pds_tdm_read_sigmap(struct pds_span *o, const void *from)
{
	const __be16 *sigmap = from;
	size_t i = 0;
	unsigned long c;
	__u16 bits = 0;

	for_each_set_bit(c, o->tdm.open, o->span.channels) {
		if ((i % 4) == 0)
			bits = ntohs(*sigmap++);

		o->chan[c].rxsig = (bits >> 12) & 0xf;

		bits <<= 4;
		++i;
	}
}

static void pds_tdm_write_sigmap(struct pds_span *o, void *to)
{
	__be16 *sigmap = to;
	size_t i = 0;
	unsigned long c;
	__u16 bits = 0;

	for_each_set_bit(c, o->tdm.open, o->span.channels) {
		bits |= o->chan[c].txsig;

		if ((i % 4) == 3)
			*sigmap++ = htons(bits);

		bits <<= 4;
		++i;
	}

	if ((i % 4) != 0)
		*sigmap = htons(bits);
}

static size_t pds_tdm_data_size(size_t count)
{
	return count * DAHDI_CHUNKSIZE;
}

static void pds_tdm_read_data(struct pds_span *o, const void *from)
{
	const unsigned char *buf = from;
	unsigned long i;

	for_each_set_bit(i, o->tdm.open, o->span.channels) {
		memcpy(o->chan[i].readchunk, buf, DAHDI_CHUNKSIZE);
		buf += DAHDI_CHUNKSIZE;
	}
}

static void pds_tdm_write_data(struct pds_span *o, void *to)
{
	unsigned char *buf = to;
	unsigned long i;

	for_each_set_bit(i, o->tdm.open, o->span.channels) {
		memcpy(buf, o->chan[i].writechunk, DAHDI_CHUNKSIZE);
		buf += DAHDI_CHUNKSIZE;
	}
}

static int pds_tdm_emit(struct pds_span *o)
{
	struct sk_buff *skb;
	struct pds_tdm_header *h;
	size_t count, sigmap_size, data_size;

	spin_lock(&o->span.lock);

	count       = pds_tdm_channel_count(o);
	sigmap_size = pds_tdm_sigmap_size(count);
	data_size   = pds_tdm_data_size(count);

	skb = pds_alloc_skb(pds_from_span(o), ETH_P_PDS_TDM,
			    sizeof(*h) + sigmap_size + data_size);
	if (skb == NULL)
		return -ENOMEM;

	h = (void *) skb_put(skb, sizeof(*h));

	h->span		= htons(o->span.offset + 1);
	h->chunk_size	= DAHDI_CHUNKSIZE;
	h->flags	= 0;
	h->seq		= htons(atomic_inc_return(&o->tdm.seq));
	h->channel_count = htons(count);

	skb_set_transport_header(skb, 0);
	pds_tdm_write_sigmap(o, skb_put(skb, sigmap_size));
	pds_tdm_write_data(o, skb_put(skb, data_size));

	spin_unlock(&o->span.lock);
	dev_queue_xmit(skb);
	return 0;
}

static bool pds_tdm_consume(struct net_device *dev,
			    const void *data, size_t len)
{
	const struct pds_tdm_header *h = data;
	struct pds_span *o;
	size_t count, sigmap_size, data_size;

	if (len < sizeof (*h) || h->chunk_size != DAHDI_CHUNKSIZE)
		return false;

	o = pds_find(dev, ntohs(h->span) - 1);
	if (o == NULL)
		return false;

	spin_lock(&o->span.lock);

	count = ntohs(h->channel_count);
	if (count != pds_tdm_channel_count(o))  /* TDM reconfigured */
		goto drop;

	data += sizeof (*h), len -= sizeof (*h);

	sigmap_size = pds_tdm_sigmap_size(count);
	data_size   = pds_tdm_data_size(count);

	if (len < (sigmap_size + data_size))
		goto drop;

	pds_tdm_read_sigmap(o, data);
	pds_tdm_read_data(o, data + sigmap_size);
	spin_unlock(&o->span.lock);

	dahdi_receive (&o->span);
	return true;
drop:
	spin_unlock(&o->span.lock);
	return false;
}

static int pds_tdm_recv(struct sk_buff *skb, struct net_device *dev,
			struct packet_type *p, struct net_device *orig_dev)
{
	bool ok = false;

	if ((skb = skb_share_check(skb, GFP_ATOMIC)) == NULL)
		return NET_RX_DROP;

	if (!skb_is_nonlinear(skb) || skb_linearize(skb) == 0)
		ok = pds_tdm_consume(dev, skb->data, skb->len);

	kfree_skb(skb);
	return ok ? NET_RX_SUCCESS : NET_RX_DROP;
}

#define PDS_TDM_PERIOD  (1000000000 / PDS_TDM_RATE)  /* PDS period in ns */

static enum hrtimer_restart pds_tdm_worker(struct hrtimer *timer)
{
	struct pds_tdm *tdm = container_of(timer, struct pds_tdm, timer);
	struct pds *o = container_of(tdm, struct pds, tdm);
	size_t i;
	struct pds_span *s;

	hrtimer_forward(timer, hrtimer_get_expires(timer),
			ktime_set(0, PDS_TDM_PERIOD));

	for (i = 0; i < ARRAY_SIZE (o->span); ++i) {
		s = o->span + i;

		/* NOTE: dahdi_receive called in receive path directly */

		dahdi_transmit(&s->span);
		pds_tdm_emit(s);
	}

	return HRTIMER_RESTART;
}

void pds_tdm_span_init(struct pds_span *o)
{
	bitmap_zero(o->tdm.open, o->span.channels);
	atomic_set(&o->tdm.seq, 0);
}

void pds_tdm_init(struct pds *o)
{
	hrtimer_init(&o->tdm.timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	o->tdm.timer.function = pds_tdm_worker;

	o->tdm.pt.type = htons(ETH_P_PDS_TDM);
	o->tdm.pt.dev  = o->master;
	o->tdm.pt.func = pds_tdm_recv;

	dev_add_pack(&o->tdm.pt);

	o->tdm.ref = 0;
}

static void pds_tdm_stop(struct pds *o);

void pds_tdm_fini(struct pds *o)
{
	pds_tdm_stop(o);

	dev_remove_pack(&o->tdm.pt);
}

static void pds_tdm_start(struct pds *o)
{
	return;  /* NOTE: TDM mode silently banned now */

	hrtimer_start(&o->tdm.timer, ktime_set(0, PDS_TDM_PERIOD),
		      HRTIMER_MODE_REL);
}

static void pds_tdm_stop(struct pds *o)
{
	hrtimer_cancel(&o->tdm.timer);
}

void pds_tdm_open(struct pds *o, struct dahdi_chan *c)
{
	struct pds_span *s = container_of(c->span, struct pds_span, span);

	spin_lock(&s->span.lock);

	if (!test_bit(c->chanpos, s->tdm.open)) {
		set_bit(c->chanpos, s->tdm.open);

		if (++o->tdm.ref == 1)
			pds_tdm_start(o);
	}

	spin_unlock(&s->span.lock);
}

void pds_tdm_close(struct pds *o, struct dahdi_chan *c)
{
	struct pds_span *s = container_of(c->span, struct pds_span, span);

	spin_lock(&s->span.lock);

	if (test_bit(c->chanpos, s->tdm.open)) {
		clear_bit(c->chanpos, s->tdm.open);

		if (--o->tdm.ref == 0)
			pds_tdm_stop(o);
	}

	spin_unlock(&s->span.lock);
}
