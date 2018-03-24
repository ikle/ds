/*
 * PDS request
 *
 * Copyright (c) 2018 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef PDS_REQ_H
#define PDS_REQ_H  1

#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>

struct pds_req {
	spinlock_t lock;
	struct task_struct *task;
	int key;
	struct sk_buff *req, *reply;
};

void pds_req_init(struct pds_req *o);
void pds_req_fini(struct pds_req *o);

/* NOTE: skb will be consumed */
void pds_req_start(struct pds_req *o, int key, struct sk_buff *skb);
void pds_req_reply(struct pds_req *o, int key, struct sk_buff *skb);

struct sk_buff *pds_req_result(struct pds_req *o);
void pds_req_end(struct pds_req *o);

#endif  /* PDS_REQ_H */
