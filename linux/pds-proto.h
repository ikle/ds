/*
 * PDS Protocol
 *
 * Copyright (c) 2017-2018 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef PDS_PROTO_H
#define PDS_PROTO_H  1

#ifdef __KERNEL__

#include <linux/bitops.h>

#else

#include <stdint.h>

typedef uint8_t  __u8;
typedef uint16_t __u16;
typedef __u16    __be16;

#endif

#ifndef BIT
#define BIT(n)  (1UL << (n))
#endif

/*
 * PDS TDM event, EtherType = 0x7a00
 *
 * NOTE: Bit-to-bit compatible with TDMoE except for EtherType (0xd00d).
 */

#define ETH_P_PDS_TDM	0x7a00

struct pds_tdm_header {
	__be16	span;
	__u8	chunk_size;
	__u8	flags;
	__be16	seq;
	__be16	channel_count;	/* all channels opened for TDM for this span */
};

#define PDS_TDM_ALARM		BIT(0)
#define PDS_TDM_SIGNALS		BIT(1)	/* channel signal bits present */
#define PDS_TDM_LOOPBACK	BIT(2)

/*
 * Pseudo code to encode channel signal bits:
 *
 *	__be16	signal[(channel_count + 3) / 4];
 *	__u16	bits;
 *
 *	for (bits = 0; i = 0; i < channel_count; bits <<= 4, ++i) {
 *		bits |= chan[i].txsig;
 *
 *		if ((i % 4) == 3)
 *			signal[i / 4] = htons(bits);
 *	}
 *
 * Pseudo code to encode channel data:
 *
 *	for (i = 0, c = 0; c < channel_count; ++c)
 *		for (j = 0; j < chunk_size; ++i, ++j)
 *			data[i] = chan[c].txbuf[j];
 */

/*
 * PDS HDLC event, EtherType = 0x7a01
 */

#define ETH_P_PDS_HDLC	0x7a01

struct pds_hdlc_header {
	__be16	span;
	__u8	reserved;	/* should be zero */
	__u8	flags;
	__be16	seq;
	__be16	channel;	/* master channel */
};

/*
 * PDS control message, EtherType = 0x7a02
 *
 * The message header is followed by zero or more arguments. If not
 * specified otherwise all argumens are 16-bit big-endian numbers.
 *
 * NOTE: Extra arguments should be ignored: real Ethernet payload
 * padded to 60 by zeroes always.
 */

#define ETH_P_PDS_CTL	0x7a02

struct pds_ctl_header {
	__be16	span;
	__u8	code;
	__u8	flags;
	__be16	seq;
};

enum pds_code {
	PDS_RESET = 0,
	PDS_SETUP,
	PDS_ENSLAVE,
	PDS_OPEN_TDM,
	PDS_OPEN_HDLC,
	PDS_CLOSE,
	PDS_NOTIFY_ALARM = 128,
	PDS_NOTIFY_COUNTS,
};

/*
 * In all requests reply flag MUST be reset, in all replies it MUST be set.
 * The reply sequence number MUST match such from a request. The first
 * argument of a reply MUST be a completion status code.
 */
#define PDS_MESSAGE_REPLY	BIT(0)

/*
 * - NOSYS: The command or mode known but not supported.
 * - INVAL: No enoght arguments given or an unrecognized value specified.
 * - BUSY:  Channel already open or used for signaling.
 */
enum pds_error {
	PDS_STATUS_OK = 0,
	PDS_STATUS_NOSYS,	/* not implemented		*/
	PDS_STATUS_INVAL,	/* invalid argument		*/
	PDS_STATUS_BUSY,	/* device or resource busy	*/
};

struct pds_ctl_status {
	struct pds_ctl_header header;
	__u16 status;  /* one from pds_error */
};

/*
 * Reset: no arguments required
 *
 *   - set span sequence counter to zero;
 *   - sync source: external from own span;
 *   - line code: HDB3;
 *   - framing: G.704;
 *   - signaling: CCS mode, channel not set;
 *   - all channels closed.
 *
 * If span = 0 then reset controller and all spans.
 */

enum pds_line_code {
	PDS_LINE_CODE_HDB3,
	PDS_LINE_CODE_AMI,
};

enum pds_framing {
	PDS_FRAMING_G704,
	PDS_FRAMING_G704_NO_CRC,
	PDS_FRAMING_UNFRAMED,
};

enum pds_signaling {
	PDS_SIGNALING_CCS,
	PDS_SIGNALING_CAS,
};

/*
 * Setup: sync-source-span, line-code, framing, signaling
 *   - if sync-source-span = 0 then use internal clock source;
 *   - if sync-source-span > 0 then use it as reference;
 *   - set up line coding mode;
 *   - set up framing mode;
 *   - set up signaling type.
 *
 * NOTE: CAS reserve channel 16 for signalig on E1 spans.
 */

/*
 * Enslave: channel, master-channel
 *
 *   - remove channel from previous master slave list if any;
 *   - if channel ≠ master-channel then add it to channel slave list.
 *
 * Open TDM: channel
 *
 *   - if channel is slave then return INVAL;
 *   - otherwise map this channel to TDM stream.
 *
 * Open HDLC: channel
 *
 *   - if channel is slave then return INVAL;
 *   - otherwise map this channel to HDLC stream identified by this channel.
 *
 * Close: channel
 *
 *   - unmap channel from any stream if any (should always succeed).
 *
 * Notify Alarm: alarms
 *
 *   - got alarm map from device, do not reply;
 *   - this event should be sent by device periodically (1 per second is
 *     more then needed).
 */

enum pds_alarm {
	PDS_ALARM_RECOVER	= BIT(0),	/* Recovering from alarm */
	PDS_ALARM_LOOPBACK	= BIT(1),	/* In loopback		 */
	PDS_ALARM_YELLOW	= BIT(2),	/* Yellow Alarm		 */
	PDS_ALARM_RED		= BIT(3),	/* Red Alarm		 */
	PDS_ALARM_BLUE		= BIT(4),	/* Blue Alarm		 */
	PDS_ALARM_NOTOPEN	= BIT(5),	/* Span is not open	 */

	PDS_ALARM_LOS		= BIT(8),	/* Loss of Signal	     */
	PDS_ALARM_LFA		= BIT(9),	/* Loss of Frame Alignment   */
	PDS_ALARM_LMFA		= BIT(10),	/* Loss of Multi-Frame Align */
};

/*
 * Notify Counts: counts
 *
 *   - got counts from device, do not reply.
 *   - this event should be sent by device periodically (1 per second is
 *     more then needed).
 */

struct pds_counts {
	__be32 fe;		/* Framing error counter		*/
	__be32 cv;		/* Coding violations counter		*/
	__be32 bpv;		/* Bipolar Violation counter		*/
	__be32 crc4;		/* CRC4 error counter			*/
	__be32 ebit;		/* current E-bit error count		*/
	__be32 fas;		/* current FAS error count		*/
	__be32 be;		/* current bit error count		*/
	__be32 prbs;		/* current PRBS detected pattern	*/
	__be32 errsec;		/* errored seconds			*/
	__be32 timingslips;	/* Clock slips				*/
};

#endif  /* PDS_PROTO_H */
