/*
 * PDS common definitions
 *
 * Copyright (c) 2017-2019 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef PDS_H
#define PDS_H  1

#include <linux/bitops.h>
#include <linux/hrtimer.h>
#include <linux/netdevice.h>
#include <linux/mutex.h>
#include <linux/skbuff.h>

#include <dahdi/kernel.h>

#ifndef DAHDI_CONFIG_UNFRAMED
#define DAHDI_CONFIG_UNFRAMED  0
#endif

#include "pds-conf.h"
#include "pds-proto.h"
#include "pds-req.h"
#include "pds-tdm.h"

struct pds_span {
	struct dahdi_span span;
	struct dahdi_chan chan[PDS_SPAN_CAPACITY];
	struct dahdi_chan *chan_list[PDS_SPAN_CAPACITY];

	atomic_t hdlc_seq, ctl_seq;

	struct mutex ctl_lock;
	struct pds_req req;

	struct pds_tdm_span tdm;
};

struct pds {
	struct dahdi_device *dev;
	struct pds_span span[4];
	struct net_device *master;

	struct packet_type hdlc, ctl;

	struct pds_tdm tdm;
};

struct pds_span *pds_find(struct net_device *dev, unsigned spanno);
struct dahdi_chan *pds_find_chan(struct net_device *dev,
				 unsigned spanno, unsigned channo);

static inline struct pds *pds_from_span(struct pds_span *o)
{
	return o->span.chans[0]->pvt;
}

/* network helpers */

struct sk_buff *pds_rx_prepare(struct sk_buff *skb);

struct sk_buff *pds_alloc_skb(struct pds *pds, int type, unsigned len);

struct sk_buff *pds_hdlc_alloc_skb(struct dahdi_chan *o, unsigned len);

int pds_ctl_reset(struct pds_span *o);
int pds_ctl_setup(struct pds_span *o, int sync, enum pds_line_code code,
		  enum pds_framing framing, enum pds_signaling sig);

int pds_ctl_enslave(struct dahdi_chan *o);
int pds_ctl_tdm_open(struct dahdi_chan *o);
int pds_ctl_hdlc_open(struct dahdi_chan *o);
int pds_ctl_close(struct dahdi_chan *o);

/* debug helpers */

extern bool debug;

#define pds_debug(fmt, args...)				\
do {							\
	if (debug)					\
		printk(KERN_DEBUG pr_fmt(fmt), ##args);	\
}							\
while (0)

#endif  /* PDS_H */
