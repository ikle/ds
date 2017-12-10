/*
 * Simple HDLC tunnel over UDP/IP device
 *
 * Copyright (c) 2017 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/hdlc.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/version.h>

#include "hdlc_lib.h"

#undef netdev_debug
#define netdev_debug(dev, format, args...)				\
do {									\
	if (debug)							\
		netdev_printk(KERN_DEBUG, dev, format, ##args);		\
}									\
while (0)

static bool debug = false;
static char *peer = NULL;

struct port {
	struct sk_buff_head txq;
	atomic_t txq_len;
	struct task_struct *rx, *tx;

	struct net_device *dev;

	struct socket *sock;
	struct sockaddr_in addr;

	sync_serial_settings line;
	unsigned short encoding, parity;
};

static bool hdlc_tun_rx_one(void *cookie)
{
	struct port *port = cookie;
	struct net_device *dev = port->dev;
	char buf[HDLC_MAX_MRU];
	int ret;
	struct sk_buff *skb;

	ret = kernel_recvfrom (port->sock, buf, sizeof (buf),
			       &port->addr, sizeof (port->addr), -1);
	if (ret <= 0)
		return false;

	netdev_debug(dev, "got %d bytes\n", ret);

	skb = netdev_alloc_skb(dev, ret);
	if (skb == NULL) {
		dev->stats.rx_dropped++;
		return true;
	}

	memcpy(skb_put(skb, ret), buf, ret);
	skb->protocol = hdlc_type_trans(skb, dev);
	netif_rx(skb);

	dev->stats.rx_packets++;
	dev->stats.rx_bytes += ret;
	return true;
}

static bool hdlc_tun_tx_one(void *cookie)
{
	struct port *port = cookie;
	struct net_device *dev = port->dev;
	struct sk_buff *skb;
	int ret = 0;

	if ((skb = skb_dequeue(&port->txq)) == NULL)
		return false;

	netdev_debug(dev, "send %d bytes\n", skb->len);
	atomic_inc(&port->txq_len);

	ret = kernel_sendto(port->sock, skb->data, skb->len,
			    &port->addr, sizeof (port->addr), -1);
	if (ret <= 0) {
		dev_kfree_skb_any(skb);
		dev->stats.tx_dropped++;
	}
	else {
		dev_consume_skb_any(skb);
		dev->stats.tx_packets++;
		dev->stats.tx_bytes += ret;
	}

	return true;
}

static inline struct port *dev_to_port(struct net_device *dev)
{
	return dev_to_hdlc(dev)->priv;
}

static int hdlc_tun_attach(struct net_device *dev, unsigned short encoding,
			   unsigned short parity)
{
	struct port *port = dev_to_port(dev);

	if (encoding != ENCODING_NRZ &&
	    encoding != ENCODING_NRZI)
		return -EINVAL;

	if (parity != PARITY_NONE &&
	    parity != PARITY_CRC32_PR1_CCITT &&
	    parity != PARITY_CRC16_PR1_CCITT &&
	    parity != PARITY_CRC32_PR0_CCITT &&
	    parity != PARITY_CRC16_PR0_CCITT)
		return -EINVAL;

	port->encoding = encoding;
	port->parity   = parity;
	return 0;
}

static netdev_tx_t hdlc_tun_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct port *port = dev_to_port(dev);

	if (skb->len > dev->mtu ||
	    atomic_dec_if_positive(&port->txq_len) < 0) {
		netdev_debug(dev, "drop %d bytes\n", skb->len);
		dev_kfree_skb_any(skb);
		dev->stats.tx_dropped++;
		return NETDEV_TX_OK;
	}

	netdev_debug(dev, "queue %d bytes\n", skb->len);
	skb_queue_tail(&port->txq, skb);
	wake_up_process(port->tx);
	return NETDEV_TX_OK;
}

static int hdlc_tun_open(struct net_device *dev)
{
	struct port *port = dev_to_port(dev);
	int ret;

	if (port->sock != NULL) {
		netdev_err(dev, "port open already\n");
		return -EIO;
	}

	if (peer == NULL ||
	    (port->addr.sin_addr.s_addr = in_aton(peer)) == 0) {
		netdev_err(dev, "peer address in not specified\n");
		return -EINVAL;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
	ret = sock_create_kern(dev_net(dev), AF_INET, SOCK_DGRAM, 0, &port->sock);
#else
	ret = sock_create_kern(AF_INET, SOCK_DGRAM, 0, &port->sock);
#endif
	if (ret != 0) {
		netdev_err(dev, "cannot create socket\n");
		goto no_socket;
	}

	if ((ret = hdlc_open(dev)) != 0)
		goto no_hdlc;

	wake_up_process(port->rx);
	netif_carrier_on(dev);
	netif_start_queue(dev);
	return 0;
no_hdlc:
	sock_release(port->sock);
	port->sock = NULL;
no_socket:
	netdev_err(dev, "cannot open port\n");
	return ret;
}

static int hdlc_tun_close(struct net_device *dev)
{
	struct port *port = dev_to_port(dev);
	struct sk_buff *skb;

	if (port->sock == NULL)
		return 0;

	kernel_sock_shutdown(port->sock, SHUT_RDWR);

	netif_stop_queue(dev);
	netif_carrier_off(dev);

	while (port->rx->state == TASK_RUNNING ||
	       port->tx->state == TASK_RUNNING)
		yield();

	while ((skb = skb_dequeue(&port->txq)) != NULL)
		dev_kfree_skb_any(skb);

	hdlc_close(dev);
	sock_release(port->sock);
	port->sock = NULL;
	return 0;
}

static int hdlc_tun_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
	struct port *port = dev_to_port(dev);
	sync_serial_settings line;

	if (cmd != SIOCWANDEV)
		return hdlc_ioctl(dev, ifr, cmd);

	switch (ifr->ifr_settings.type) {
	case IF_GET_IFACE:
		ifr->ifr_settings.type = IF_IFACE_SYNC_SERIAL;

		if (ifr->ifr_settings.size < sizeof (port->line)) {
			ifr->ifr_settings.size = sizeof (port->line);
			return -ENOBUFS;
		}

		return copy_to_user(ifr->ifr_settings.ifs_ifsu.sync,
			&port->line, sizeof (port->line)) != 0 ? -EFAULT : 0;

	case IF_IFACE_SYNC_SERIAL:
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;

		if (dev->flags & IFF_UP)
			return -EBUSY;

		if (copy_from_user(&line, ifr->ifr_settings.ifs_ifsu.sync,
				   sizeof (line)) != 0)
			return -EFAULT;

		if (line.clock_type != CLOCK_EXT &&
		    line.clock_type != CLOCK_INT)
			return -EINVAL;

		if (line.loopback != 0)
			return -EINVAL;

		port->line.clock_rate = line.clock_rate;
		port->line.clock_type = line.clock_type;
		return 0;

	default:
		return hdlc_ioctl(dev, ifr, cmd);
	}
}

static struct net_device_stats *hdlc_tun_get_stats(struct net_device *dev)
{
	dev->stats.rx_over_errors  = 0;
	dev->stats.rx_frame_errors = 0;
	dev->stats.rx_errors = dev->stats.rx_over_errors +
			       dev->stats.rx_frame_errors;
	return &dev->stats;
}

static const struct net_device_ops hdlc_tun_ops = {
	.ndo_open	= hdlc_tun_open,
	.ndo_stop	= hdlc_tun_close,
	.ndo_change_mtu	= hdlc_change_mtu,
	.ndo_start_xmit	= hdlc_start_xmit,
	.ndo_do_ioctl	= hdlc_tun_ioctl,
	.ndo_get_stats	= hdlc_tun_get_stats,
};

static void hdlc_tun_port_fini(struct port *port)
{
	if (port->dev == NULL)
		return;

	kthread_stop(port->tx);
	kthread_stop(port->rx);

	unregister_hdlc_device(port->dev);
	free_netdev(port->dev);
}

static int hdlc_tun_setup_dev(struct port *port)
{
	int ret;

	port->dev = alloc_hdlcdev(port);
	if (port->dev == NULL)
		return -ENOMEM;

	port->dev->tx_queue_len = atomic_read(&port->txq_len);
	port->dev->netdev_ops = &hdlc_tun_ops;

	dev_to_hdlc(port->dev)->attach = hdlc_tun_attach;
	dev_to_hdlc(port->dev)->xmit   = hdlc_tun_xmit;

	ret = register_hdlc_device(port->dev);
	if (ret != 0) {
		free_netdev(port->dev);
		port->dev = NULL;
		return ret;
	}

	return 0;
}

static int hdlc_tun_port_init(struct port *port)
{
	int ret;

	skb_queue_head_init(&port->txq);
	atomic_set(&port->txq_len, 100);

	port->rx = kthread_periodic(hdlc_tun_rx_one, port, "hdlc-tun-rx");
	if (IS_ERR(port->rx)) {
		ret = PTR_ERR(port->rx);
		goto no_rx;
	}

	port->tx = kthread_periodic(hdlc_tun_tx_one, port, "hdlc-tun-tx");
	if (IS_ERR(port->tx)) {
		ret = PTR_ERR(port->tx);
		goto no_tx;
	}

	ret = hdlc_tun_setup_dev(port);
	if (ret != 0)
		goto no_dev;

	port->sock = NULL;
	port->addr.sin_family = AF_INET;
	port->addr.sin_port = htons(5153);
	port->addr.sin_addr.s_addr = 0;  /* will be parsed later */

	port->line.clock_rate = 1000000;
	port->line.clock_type = CLOCK_EXT;
	port->line.loopback   = 0;

	port->encoding = ENCODING_NRZ;
	port->parity = PARITY_NONE;

	return 0;
no_dev:
	kthread_stop(port->tx);
no_tx:
	kthread_stop(port->rx);
no_rx:
	return ret;
}

static struct port port0;

static int __init mod_init(void)
{
	if (peer == NULL) {
		pr_err("no peer specified\n");
		return -EINVAL;
	}

	return hdlc_tun_port_init(&port0);
}

static void __exit mod_exit(void)
{
	hdlc_tun_port_fini(&port0);
}

module_init(mod_init);
module_exit(mod_exit);

MODULE_AUTHOR("Alexei A. Smekalkine <ikle@ikle.ru>");
MODULE_DESCRIPTION("HDLC tunnel over UDP/IP");
MODULE_LICENSE("Dual BSD/GPL");

module_param(debug, bool, 0644);
MODULE_PARM_DESC(debug, "Enable data event debug");

module_param(peer, charp, 0644);
MODULE_PARM_DESC(peer, "Tunel peer IPv4 address");
