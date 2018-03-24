/*
 * PDS common definitions
 *
 * Copyright (c) 2017 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef PDS_H
#define PDS_H  1

#include <linux/bitops.h>
#include <linux/hrtimer.h>
#include <linux/netdevice.h>

#include <dahdi/kernel.h>

#include "pds-proto.h"

#define PDS_SPAN_CAPACITY  31

struct pds_span {
	struct dahdi_span span;
	struct dahdi_chan chan[PDS_SPAN_CAPACITY];
	struct dahdi_chan *chan_list[PDS_SPAN_CAPACITY];

	/* todo: use span lock to protect it! */
	DECLARE_BITMAP(tdm_open, PDS_SPAN_CAPACITY);

	atomic_t tdm_seq, hdlc_seq, ctl_seq;
};

struct pds {
	struct dahdi_device *dev;
	struct pds_span span[4];
	struct net_device *master;

	struct packet_type hdlc;

	struct hrtimer tdm_timer;
	atomic_t tdm_ref;
};

struct pds_span *pds_find(struct net_device *dev, unsigned spanno);
struct dahdi_chan *pds_find_chan(struct net_device *dev,
				 unsigned spanno, unsigned channo);

static inline struct pds *pds_from_span(struct pds_span *o)
{
	return o->span.chans[0]->pvt;
}

/* network helpers */

struct sk_buff *pds_alloc_skb(struct pds *pds, int type, unsigned len);

int pds_hdlc_emit(struct dahdi_chan *o, const void *buf, size_t len);
int pds_hdlc_consume(struct dahdi_chan *o, const void *buf, size_t len);

int pds_ctl_reset(struct pds_span *o);
int pds_ctl_setup(struct pds_span *o, int sync, enum pds_line_code code,
		  enum pds_framing framing, enum pds_signaling sig);

int pds_ctl_enslave(struct dahdi_chan *o);
int pds_ctl_tdm_open(struct dahdi_chan *o);
int pds_ctl_hdlc_open(struct dahdi_chan *o);
int pds_ctl_close(struct dahdi_chan *o);

/* TDM worker */

void pds_tdm_init(struct pds *o);
void pds_tdm_fini(struct pds *o);
void pds_tdm_start(struct pds *o);
void pds_tdm_stop(struct pds *o);

/* debug helpers */

extern bool debug;

#define pds_debug(fmt, args...)				\
do {							\
	if (debug)					\
		printk(KERN_DEBUG pr_fmt(fmt), ##args);	\
}							\
while (0)

#endif  /* PDS_H */
