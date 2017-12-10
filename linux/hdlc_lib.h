/*
 * Common HDLC helpers
 *
 * Copyright (c) 2017 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef HDLC_LIB_H
#define HDLC_LIB_H  1

#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/socket.h>
#include <linux/version.h>

struct task_struct *kthread_periodic(bool (*fn)(void *data), void *data,
				     const char *name);

static inline void pause(void)
{
	might_sleep();
	__set_current_state(TASK_INTERRUPTIBLE);
	schedule();
}

int kernel_recvfrom(struct socket *sock, void *buf, size_t len,
		    const void *addr, size_t addr_len, long timeout);
int kernel_sendto(struct socket *sock, const void *buf, size_t len,
		  const void *addr, size_t addr_len, long timeout);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0)
#define dev_consume_skb_any  dev_kfree_skb_any
#endif

#endif  /* HDLC_LIB_H */
