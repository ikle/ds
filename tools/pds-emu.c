#include <stdio.h>
#include <string.h>

#include <sys/socket.h>

#include <err.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netpacket/packet.h>

#include <pds-proto.h>

static int pds_socket (int proto, const char *dev, struct sockaddr_ll *to)
{
	int s;

	if ((s = socket (AF_PACKET, SOCK_DGRAM, ntohs (proto))) == -1)
		goto no_socket;

	memset (to, 0, sizeof (*to));

	to->sll_family   = AF_PACKET;
	to->sll_protocol = ntohs (proto);
	to->sll_ifindex  = if_nametoindex (dev);
	to->sll_halen    = ETH_ALEN;

	memset (to->sll_addr, 0xff, to->sll_halen);

	if (bind (s, (const void *) to, sizeof (*to)) != 0)
		goto no_bind;

	return s;
no_bind:
	close (s);
no_socket:
	return -1;
}

static int send_status (int s, int status, struct sockaddr_ll *to)
{
	static int seq = 17;
	struct pds_ctl_status p;

	p.header.span	= htons (1);
	p.header.code	= PDS_OPEN_TDM;
	p.header.flags	= PDS_MESSAGE_REPLY;
	p.header.seq	= htons (seq++);

	p.status = htons (status);

	return sendto (s, &p, sizeof (p), 0,
		       (const void *) to, sizeof (*to)) == sizeof (p);
}

static int send_alarms (int s, int alarms, struct sockaddr_ll *to)
{
	static int seq = 13;
	struct pds_ctl_alarms p;

	p.header.span	= htons (1);
	p.header.code	= PDS_NOTIFY_ALARMS;
	p.header.flags	= 0;
	p.header.seq	= htons (seq++);

	p.alarms = htons (alarms);

	return sendto (s, &p, sizeof (p), 0,
		       (const void *) to, sizeof (*to)) == sizeof (p);
}

static int send_counts (int s, int slips, struct sockaddr_ll *to)
{
	static int seq = 37;
	struct pds_ctl_counts p;

	p.header.span	= htons (1);
	p.header.code	= PDS_NOTIFY_COUNTS;
	p.header.flags	= 0;
	p.header.seq	= htons (seq++);

	p.align = 0;

	memset (&p.counts, 0, sizeof (p.counts));

	p.counts.timingslips = htonl (slips);

	return sendto (s, &p, sizeof (p), 0,
		       (const void *) to, sizeof (*to)) == sizeof (p);
}

static void dump (const void *data, size_t len)
{
	const unsigned char *p;
	size_t i;

	for (p = data, i = 0; i < len; ++i) {
		printf ("%02x%s", p[i], i % 16 == 15 ? "\n" :
					i % 4  == 3  ? "  " : " ");
	}

	if (i % 16 != 0)
		putchar ('\n');

	putchar ('\n');
}

int main (int argc, char *argv[])
{
	const char *dev = argc == 2 ? argv[1] : "pds0";
	int s;
	struct sockaddr_ll to;
	char buf[9000];
	ssize_t len;

	if ((s = pds_socket (ETH_P_PDS_CTL, dev, &to)) == -1)
		err (1, "cannot open PDS CTL socket");

	if (!send_status (s, PDS_STATUS_NOSYS, &to))
		err (1, "cannot send status reply");

	if (!send_alarms (s, PDS_ALARM_YELLOW, &to))
		err (1, "cannot send alarms event");

	if (!send_counts (s, 113, &to))
		err (1, "cannot send counts event");

	close (s);

	if ((s = pds_socket (ETH_P_PDS_HDLC, dev, &to)) == -1)
		err (1, "cannot open PDS HDLC socket");

	while ((len = recv (s, buf, sizeof (buf), 0)) >= 0)
		dump (buf, len);

	return 0;
}
