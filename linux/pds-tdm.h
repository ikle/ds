/*
 * PDS TDM worker
 *
 * Copyright (c) 2017-2018 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef PDS_TDM_H
#define PDS_TDM_H  1

#include <linux/bitops.h>
#include <linux/hrtimer.h>
#include <linux/netdevice.h>

#include <dahdi/kernel.h>

#include "pds-conf.h"

struct pds_tdm_span {
	DECLARE_BITMAP(open, PDS_SPAN_CAPACITY);
	__u16 seq;
};

struct pds_span;

void pds_tdm_span_init(struct pds_span *o);

struct pds_tdm {
	struct hrtimer timer;
	struct packet_type pt;
	int ref;
};

struct pds;

void pds_tdm_init(struct pds *o);
void pds_tdm_fini(struct pds *o);

void pds_tdm_open(struct pds *o, struct dahdi_chan *c);
void pds_tdm_close(struct pds *o, struct dahdi_chan *c);

#endif  /* PDS_TDM_H */
