/*
 * DAHDI PDS tunnel
 *
 * Copyright (c) 2017 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/hrtimer.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/ratelimit.h>

#include "pds.h"

bool debug = false;
static char *master = NULL;

static int pds_span_config(struct file *file, struct dahdi_span *o,
			  struct dahdi_lineconfig *lc)
{
	struct pds_span *s = container_of(o, struct pds_span, span);
	enum pds_line_code coding;
	enum pds_framing   framing;
	enum pds_signaling sig;
	int ret;

	coding	= lc->lineconfig & DAHDI_CONFIG_HDB3 ?	PDS_LINE_CODE_HDB3 :
							PDS_LINE_CODE_AMI;
	framing	= lc->lineconfig & DAHDI_CONFIG_CRC4 ?	PDS_FRAMING_G704 :
							PDS_FRAMING_G704_NO_CRC;
	sig	= lc->lineconfig & DAHDI_CONFIG_CCS  ?	PDS_SIGNALING_CCS :
							PDS_SIGNALING_CAS;

	ret = pds_ctl_setup(s, lc->sync, coding, framing, sig);
	if (ret == 0) {
		o->syncsrc    = lc->sync;
		o->lineconfig = lc->lineconfig;

		pr_info("%s: span configured\n", o->name);
	}
	else
		pr_err("%s: span configuration failed (%d)\n", o->name, ret);

	return ret;
}

static int pds_span_startup(struct file *file, struct dahdi_span *o)
{
	pr_info("%s: start up span\n", o->name);
	return 0;
}

static int pds_span_shutdown(struct dahdi_span *o)
{
	struct pds_span *s = container_of(o, struct pds_span, span);

	pr_info("%s: shut down span\n", o->name);

	return pds_ctl_reset(s);
}

static int pds_chan_config(struct file *file, struct dahdi_chan *o,
			   int sigtype)
{
	int ret;

	if (o == o->master)
		pds_debug("%s: master channel\n", o->name);
	else
		pds_debug("%s: slave of %s\n", o->name, o->master->name);

	pds_debug("%s: sigtype = %x\n", o->name, sigtype);

	ret = pds_ctl_enslave(o);

	if (ret == 0 && o == o->master && sigtype == DAHDI_SIG_HDLCNET) {
		/* force hard HDLC mode */
		o->flags &= ~(DAHDI_FLAG_FCS | DAHDI_FLAG_HDLC);
		o->flags |= DAHDI_FLAG_NOSTDTXRX;
	}

	return ret;
}

static int pds_chan_open(struct dahdi_chan *o)
{
	struct pds *pds = o->pvt;
	int ret;

	pds_debug("%s: open channel\n", o->name);

	if (o->chanpos < 0 || o->chanpos >= o->span->channels)
		return -EINVAL;

	if ((o->flags & DAHDI_FLAG_NOSTDTXRX) != 0)
		return pds_ctl_hdlc_open(o);

	ret = pds_ctl_tdm_open(o);
	if (ret != 0)
		return ret;

	pds_tdm_open(pds, o);
	return 0;
}

static int pds_chan_close(struct dahdi_chan *o)
{
	struct pds *pds = o->pvt;

	pds_debug("%s: close channel\n", o->name);

	if (o->chanpos < 0 || o->chanpos >= o->span->channels)
		return -EINVAL;

	pds_tdm_close(pds, o);
	return pds_ctl_close(o);
}

static int pds_chan_ioctl(struct dahdi_chan *o,
			  unsigned int cmd, unsigned long data)
{
	pds_debug ("%s: ioctl %u\n", o->name, cmd);
	return -ENOTTY;
}

static int pds_chan_rbsbits(struct dahdi_chan *o, int bits)
{
	pds_debug ("%s: rbsbits %d\n", o->name, bits);
	return 0;
}

static void pds_chan_hdlc_hard_xmit(struct dahdi_chan *o)
{
	struct pds *pds = o->pvt;
	int ret;
	char buf[2000];
	unsigned len;

	do {
		len = sizeof (buf);
		ret = dahdi_hdlc_getbuf(o, buf, &len);

		if (!netif_running(pds->master)) {
			pds_debug("%s: drop %u bytes, no link\n",
				  o->name, len);
			continue;  /* master is down, eat data */
		}

		if (ret == 0) {
			pr_warn("%s: drop %u bytes, overrun\n", o->name, len);
			continue;
		}

		pds_debug("%s: send %u bytes\n", o->name, len);
		pds_hdlc_emit(o, buf, len);
	}
	while (ret >= 0);
}

static const struct dahdi_span_ops pds_span_ops = {
	.owner		= THIS_MODULE,
	.spanconfig	= pds_span_config,
	.startup	= pds_span_startup,
	.shutdown	= pds_span_shutdown,
	.chanconfig	= pds_chan_config,
	.open		= pds_chan_open,
	.close		= pds_chan_close,
	.ioctl		= pds_chan_ioctl,
	.rbsbits	= pds_chan_rbsbits,
	.hdlc_hard_xmit	= pds_chan_hdlc_hard_xmit,
};

static void pds_span_init(struct pds_span *o, struct pds *pds, int index)
{
	const char *device = dev_name(&pds->dev->dev);
	struct dahdi_span *s = &o->span;
	struct dahdi_chan *c;
	size_t i;

	snprintf(s->name, sizeof(s->name), "%s/%d", device, index);
	snprintf(s->desc, sizeof(s->desc), "DAHDI PDS Device %s Port %d",
		 device, index);

	s->spantype	= "E1";  /* 2.11: SPANTYPE_DIGITAL_E1 */
	s->deflaw	= DAHDI_LAW_ALAW;
	s->lineconfig	= DAHDI_CONFIG_HDB3 | DAHDI_CONFIG_CCS;
	s->linecompat	= DAHDI_CONFIG_AMI | DAHDI_CONFIG_HDB3 |
			  DAHDI_CONFIG_CCS | DAHDI_CONFIG_CRC4;

	s->channels	= ARRAY_SIZE(o->chan);
	s->chans	= o->chan_list;

	for (i = 0; i < s->channels; ++i) {
		c = o->chan + i;

		c->chanpos = i;
		snprintf(c->name, sizeof (c->name), "%s/%d/%d",
			 device, index, c->chanpos);
		c->pvt = pds;
		c->sigcap = DAHDI_SIG_HDLCNET | DAHDI_SIG_HARDHDLC;

		s->chans[i] = c;
	}

	s->ops		= &pds_span_ops;
	s->offset	= index;

	atomic_set(&o->hdlc_seq, 0);
	atomic_set(&o->ctl_seq,  0);

	mutex_init(&o->ctl_lock);
	pds_req_init(&o->req);

	pds_tdm_span_init(o);
}

static void pds_span_fini(struct pds_span *o)
{
	pds_req_fini(&o->req);
}

static
int pds_hdlc_rx(struct sk_buff *skb, struct net_device *dev,
		struct packet_type *p, struct net_device *orig_dev)
{
	struct pds_hdlc_header *h = (void *) skb->data;
	struct dahdi_chan *c;

	if (skb_pull(skb, sizeof (*h)) == NULL)
		goto broken;

	c = pds_find_chan(dev, ntohs(h->span) - 1, ntohs(h->channel) - 1);
	if (c == NULL)
		goto broken;

	pds_debug("%s: got %u bytes\n", c->name, skb->len);
	dahdi_hdlc_putbuf(c, skb->data, skb->len);
	dahdi_hdlc_finish(c);

	dev_kfree_skb_any(skb);
	return NET_RX_SUCCESS;
broken:
	skb->dev->stats.rx_errors++;
	dev_kfree_skb_any(skb);
	return NET_RX_DROP;
}

static
int pds_ctl_rx(struct sk_buff *skb, struct net_device *dev,
	       struct packet_type *p, struct net_device *orig_dev)
{
	struct pds_ctl_header *h = (void *) skb->data;
	struct pds_span *s;

	if (skb->len < sizeof (*h) || (h->flags & PDS_MESSAGE_REPLY) == 0)
		goto broken;

	s = pds_find(dev, ntohs(h->span) - 1);
	if (s == NULL)
		goto broken;

	pds_debug("%s: got reply for seq = %u\n", s->span.name, h->seq);
	pds_req_reply(&s->req, h->seq, skb);

	return NET_RX_SUCCESS;
broken:
	skb->dev->stats.rx_errors++;
	dev_kfree_skb_any(skb);
	return NET_RX_DROP;
}

static int pds_init(struct pds *o, int index, const char *master)
{
	size_t i;
	int ret;

	o->dev = dahdi_create_device();
	if (o->dev == NULL)
		return -ENOMEM;

	o->dev->manufacturer = "Ikle";
	o->dev->devicetype   = "DAHDI PDS";

	dev_set_name(&o->dev->dev, "pds%d", index);

	for (i = 0; i < ARRAY_SIZE (o->span); ++i) {
		pds_span_init(o->span + i, o, i);
		list_add_tail(&o->span[i].span.device_node, &o->dev->spans);
	}

	ret = dahdi_register_device(o->dev, NULL);
	if (ret != 0)
		goto no_register;

	o->master = dev_get_by_name(&init_net, master);
	if (o->master == NULL) {
		ret = -ENXIO;
		goto no_master;
	}

	memset(&o->hdlc, 0, sizeof (o->hdlc));

	o->hdlc.type	= cpu_to_be16(ETH_P_PDS_HDLC);
	o->hdlc.dev	= o->master;
	o->hdlc.func	= pds_hdlc_rx;

	dev_add_pack(&o->hdlc);

	o->ctl.type	= cpu_to_be16(ETH_P_PDS_CTL);
	o->ctl.dev	= o->master;
	o->ctl.func	= pds_ctl_rx;

	dev_add_pack(&o->ctl);

	pds_tdm_init(o);

	pr_info("pds: device %s initialized\n", dev_name(&o->dev->dev));
	return 0;
no_master:
no_register:
	dahdi_free_device(o->dev);
	return ret;
}

static void pds_fini(struct pds *o)
{
	size_t i;

	pr_info("pds: unregister %s device\n", dev_name(&o->dev->dev));

	pds_tdm_fini(o);

	dev_remove_pack(&o->ctl);
	dev_remove_pack(&o->hdlc);

	dev_put(o->master);
	dahdi_unregister_device(o->dev);

	for (i = 0; i < ARRAY_SIZE (o->span); ++i)
		pds_span_fini(o->span + i);

	dahdi_free_device(o->dev);
}

static struct pds pds0;

struct pds_span *pds_find(struct net_device *dev, unsigned spanno)
{
	struct pds *o = &pds0;

	if (dev != o->master || spanno >= ARRAY_SIZE (o->span))
		return NULL;

	return o->span + spanno;
}

struct dahdi_chan *pds_find_chan(struct net_device *dev,
				 unsigned spanno, unsigned channo)
{
	struct pds_span *s;

	s = pds_find(dev, spanno);
	if (s == NULL || channo >= s->span.channels)
		return NULL;

	return s->chan + channo;
}

static int __init mod_init(void)
{
	int ret;

	if (master == NULL)
		master = "eth1";

	ret = pds_init(&pds0, 0, master);
	if (ret != 0) {
		pr_err("pds: cannot initialize device\n");
		return ret;
	}

	return 0;
}

static void __exit mod_exit(void)
{
	pds_fini(&pds0);
}

module_init(mod_init);
module_exit(mod_exit);

MODULE_AUTHOR("Alexei A. Smekalkine <ikle@ikle.ru>");
MODULE_DESCRIPTION("HDLC PDS tunnel");
MODULE_LICENSE("Dual BSD/GPL");

module_param(debug, bool, 0644);
MODULE_PARM_DESC(debug, "Enable data event debug");

module_param(master, charp, 0644);
MODULE_PARM_DESC(master, "Master network device name");
