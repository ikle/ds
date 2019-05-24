/*
 * Cisco HDLC Ethernet encapsulation
 *
 * Copyright (c) 2017 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/capability.h>
#include <linux/errno.h>
#include <linux/etherdevice.h>
#include <linux/hdlc.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/version.h>

static bool debug = false;

#undef netdev_debug
#define netdev_debug(dev, format, args...)				\
do {									\
	if (debug)							\
		netdev_printk(KERN_DEBUG, dev, format, ##args);		\
}									\
while (0)

static inline void netdev_dump(const char *prefix, struct sk_buff *skb)
{
	unsigned len;
	char buf[32], *p;

	if (!debug)
		return;

	len = skb->len > sizeof (buf) ? sizeof (buf) : skb->len;

	p = skb_header_pointer(skb, 0, len, &buf);
	if (p != NULL)
		print_hex_dump_bytes(prefix, DUMP_PREFIX_OFFSET, p, len);
}

#ifndef IF_PROTO_CISCO_ETH
#define IF_PROTO_CISCO_ETH	0x200D	/* Cisco HDLC, Ethernet emulation */
#endif

#define CISCO_MULTICAST	0x8f	/* Cisco multicast address */
#define CISCO_UNICAST	0x0f	/* Cisco unicast address */

struct cisco_hdlc {
	u8 address;		/* CISCO_UNICAST */
	u8 control;		/* zero always   */
	__be16 protocol;	/* ETH_P_TEB     */
}
__attribute__((packed));

static __be16 cisco_eth_type_trans(struct sk_buff *skb, struct net_device *dev)
{
	struct cisco_hdlc *h = (void *) skb->data;

	if (skb->len < sizeof (*h) ||
	    (h->address != CISCO_UNICAST && h->address != CISCO_MULTICAST) ||
	    h->protocol != cpu_to_be16(ETH_P_TEB)) {
		skb->pkt_type = PACKET_LOOPBACK;  /* hack: prevent bridging */
		return cpu_to_be16(ETH_P_HDLC);
	}

	netdev_debug(dev, "cisco-eth: got %d bytes\n", skb->len);
	skb_pull_inline(skb, sizeof (*h));
	return eth_type_trans(skb, dev);
}

static netdev_tx_t cisco_eth_tx(struct sk_buff *skb, struct net_device *dev)
{
	struct cisco_hdlc *h;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,19,0)
	if (skb_padto(skb, ETH_ZLEN) != 0)
		goto drop;

	if (skb->len < ETH_ZLEN)
		skb->len = ETH_ZLEN;
#else
	if (skb_put_padto(skb, ETH_ZLEN) != 0)
		goto drop;
#endif

	if (skb_cow_head(skb, sizeof (*h)) != 0)
		goto drop;

	h = (void *) skb_push(skb, sizeof (*h));

	h->address  = CISCO_UNICAST;
	h->control  = 0;
	h->protocol = cpu_to_be16(ETH_P_TEB);

	netdev_debug(dev, "cisco-eth: transport header at %u, "
		     "network header at %u, mac header at %u\n",
		     skb->transport_header, skb->network_header,
		     skb->mac_header);
	netdev_debug(dev, "cisco-eth: queue %d bytes\n", skb->len);
	return dev_to_hdlc(dev)->xmit(skb, dev);
drop:
	netdev_debug(dev, "cisco-eth: drop %d bytes\n", skb->len);
	dev_kfree_skb(skb);
	dev->stats.tx_dropped++;
	return 0;
}

static void cisco_ether_setup(struct net_device *dev)
{
	int tx_queue_len = dev->tx_queue_len;

	ether_setup(dev);
	dev->needed_headroom += sizeof (struct cisco_hdlc);
	dev->tx_queue_len = tx_queue_len;
}

static int cisco_eth_rx(struct sk_buff *skb)
{
	struct cisco_hdlc *h = (void *) skb->data;

	if (skb->len < sizeof (*h)) {
		net_err_ratelimited("%s: HDLC packet too short: %u bytes\n",
				    skb->dev->name, skb->len);
		goto error;
	}

	if (h->address != CISCO_UNICAST && h->address != CISCO_MULTICAST)
		net_warn_ratelimited("%s: unexpected HDLC address %02x\n",
				     skb->dev->name, h->address);

	if (h->control != 0)
		net_warn_ratelimited("%s: unexpected HDLC control code %02x\n",
				     skb->dev->name, h->control);

	net_info_ratelimited("%s: unsupported HDLC protocol %04x ignored\n",
			     skb->dev->name, be16_to_cpu(h->protocol));

	skb_pull_inline(skb, sizeof (*h));
	netdev_dump("data: ", skb);
	dev_kfree_skb_any(skb);
	return NET_RX_DROP;
error:
	skb->dev->stats.rx_errors++;
	dev_kfree_skb_any(skb);
	return NET_RX_DROP;
}

static int cisco_eth_ioctl(struct net_device *dev, struct ifreq *ifr);

static struct hdlc_proto proto = {
	.type_trans	= cisco_eth_type_trans,
	.xmit		= cisco_eth_tx,
	.ioctl		= cisco_eth_ioctl,
	.netif_rx	= cisco_eth_rx,
	.module		= THIS_MODULE,
};

static int cisco_eth_ioctl(struct net_device *dev, struct ifreq *ifr)
{
	raw_hdlc_proto __user *req_u = ifr->ifr_settings.ifs_ifsu.raw_hdlc;
	raw_hdlc_proto req;

	hdlc_device *hdlc = dev_to_hdlc(dev);
	int res;

	switch (ifr->ifr_settings.type) {
	case IF_GET_PROTO:
		if (dev_to_hdlc(dev)->proto != &proto)
			return -EINVAL;

		ifr->ifr_settings.type = IF_PROTO_CISCO_ETH;

		if (ifr->ifr_settings.size < sizeof (req)) {
			ifr->ifr_settings.size = sizeof (req);
			return -ENOBUFS;
		}

		return copy_to_user(req_u, hdlc->state, sizeof (req)) ?
			-EFAULT : 0;

	case IF_PROTO_CISCO_ETH:
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;

		if (dev->flags & IFF_UP)
			return -EBUSY;

		if (copy_from_user(&req, req_u, sizeof (req)))
			return -EFAULT;

		if (req.encoding == ENCODING_DEFAULT)
			req.encoding = ENCODING_NRZ;

		if (req.parity == PARITY_DEFAULT)
			req.parity = PARITY_CRC16_PR1_CCITT;

		res = hdlc->attach(dev, req.encoding, req.parity);
		if (res != 0)
			return res;

		res = attach_hdlc_protocol(dev, &proto, sizeof(req));
		if (res)
			return res;

		memcpy(hdlc->state, &req, sizeof (req));

		cisco_ether_setup(dev);
		eth_hw_addr_random(dev);
		netif_dormant_off(dev);
		return 0;
	}

	return -EINVAL;
}

static int __init mod_init(void)
{
	register_hdlc_protocol(&proto);
	return 0;
}

static void __exit mod_exit(void)
{
	unregister_hdlc_protocol(&proto);
}

module_init(mod_init);
module_exit(mod_exit);

MODULE_AUTHOR("Alexei A. Smekalkine <ikle@ikle.ru>");
MODULE_DESCRIPTION("Cisco HDLC Ethernet encapsulation");
MODULE_LICENSE("Dual BSD/GPL");

module_param(debug, bool, 0644);
MODULE_PARM_DESC(debug, "Enable data event debug");
