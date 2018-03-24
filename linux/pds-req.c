/*
 * PDS request
 *
 * Copyright (c) 2018 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <linux/netdevice.h>

#include "pds-req.h"

void pds_req_init(struct pds_req *o)
{
	spin_lock_init(&o->lock);
	o->task  = NULL;
	o->req   = NULL;
	o->reply = NULL;
}

void pds_req_fini(struct pds_req *o)
{
	dev_kfree_skb_any(o->req);
	dev_kfree_skb_any(o->reply);
}

/* NOTE: skb will be consumed */
void pds_req_start(struct pds_req *o, int key, struct sk_buff *skb)
{
	spin_lock(&o->lock);

	pds_req_fini(o);

	o->task  = current;
	o->key   = key;
	o->req   = skb;
	o->reply = NULL;

	spin_unlock(&o->lock);
}

void pds_req_end(struct pds_req *o)
{
	spin_lock(&o->lock);

	pds_req_fini(o);

	o->task  = NULL;
	o->req   = NULL;
	o->reply = NULL;

	spin_unlock(&o->lock);
}

/* NOTE: skb will be consumed */
void pds_req_reply(struct pds_req *o, int key, struct sk_buff *skb)
{
	spin_lock(&o->lock);

	if (o->task != NULL && o->key == key) {
		dev_kfree_skb_any(o->reply);
		o->reply = skb;
		wake_up_process(o->task);
	}
	else
		dev_kfree_skb_any(skb);

	spin_unlock(&o->lock);
}

struct sk_buff *pds_req_result(struct pds_req *o)
{
	struct sk_buff *reply;

	spin_lock(&o->lock);

	reply = o->reply;
	o->reply = NULL;

	spin_unlock(&o->lock);
	return reply;
}

