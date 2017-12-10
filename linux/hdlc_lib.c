/*
 * Common HDLC helpers
 *
 * Copyright (c) 2017 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <linux/module.h>
#include <net/sock.h>

#include "hdlc_lib.h"

struct kthread_target {
	bool (*fn)(void *data);
	void *data;
};

static inline
void target_consume(struct kthread_target *to, struct kthread_target *from)
{
	*to = *from;
	smp_wmb();
	from->fn = NULL;  /* signal that target consumed */
}

static inline bool target_is_consumed(struct kthread_target *o)
{
	return ACCESS_ONCE(o->fn) == NULL;
}

static int periodic_fn(void *target)
{
	struct kthread_target o;
	bool sleep = true;

	pr_debug("%s: enter\n", current->comm);

	target_consume(&o, target);

	while (!kthread_should_stop())
		if (sleep) {
			pr_debug("%s: sleep\n", current->comm);
			pause();
			pr_debug("%s: wake up\n", current->comm);
			sleep = false;
		}
		else
			sleep = !o.fn (o.data);

	pr_debug("%s: leave\n", current->comm);
	return 0;
}

struct task_struct *kthread_periodic(bool (*fn)(void *data), void *data,
				     const char *name)
{
	struct kthread_target o;
	struct task_struct *task;

	if (fn == NULL)
		return ERR_PTR(-EINVAL);

	o.fn   = fn;
	o.data = data;

	task = kthread_run(periodic_fn, &o, name);

	while (!target_is_consumed(&o))
		yield();

	return task;
}
EXPORT_SYMBOL(kthread_periodic);

int kernel_recvfrom(struct socket *sock, void *buf, size_t len,
		    const void *addr, size_t addr_len, long timeout)
{
	struct msghdr msg;
	struct kvec v;
	long sock_timeout = sock->sk->sk_rcvtimeo;
	int ret;

	msg.msg_name	= (void *) addr;
	msg.msg_namelen	= addr_len;
	msg.msg_control	= NULL;
	msg.msg_controllen = 0;
	msg.msg_flags	= 0;

	v.iov_base = buf;
	v.iov_len  = len;

	sock->sk->sk_rcvtimeo = timeout < 0 ? MAX_SCHEDULE_TIMEOUT : timeout;
	ret = kernel_recvmsg(sock, &msg, &v, 1, len, 0);
	sock->sk->sk_rcvtimeo = sock_timeout;
	return ret;
}
EXPORT_SYMBOL(kernel_recvfrom);

int kernel_sendto(struct socket *sock, const void *buf, size_t len,
		  const void *addr, size_t addr_len, long timeout)
{
	struct msghdr msg;
	struct kvec v;
	long sock_timeout = sock->sk->sk_rcvtimeo;
	int ret;

	msg.msg_name	= (void *) addr;
	msg.msg_namelen	= addr_len;
	msg.msg_control	= NULL;
	msg.msg_controllen = 0;
	msg.msg_flags	= 0;

	v.iov_base = (void *) buf;
	v.iov_len  = len;

	sock->sk->sk_sndtimeo = timeout < 0 ? MAX_SCHEDULE_TIMEOUT : timeout;
	ret = kernel_sendmsg(sock, &msg, &v, 1, len);
	sock->sk->sk_sndtimeo = sock_timeout;
	return ret;
}
EXPORT_SYMBOL(kernel_sendto);

static int __init mod_init(void)
{
	return 0;
}

static void __exit mod_exit(void)
{
}

module_init(mod_init);
module_exit(mod_exit);

MODULE_AUTHOR("Alexei A. Smekalkine <ikle@ikle.ru>");
MODULE_DESCRIPTION("Common HDLC helpers");
MODULE_LICENSE("Dual BSD/GPL");
