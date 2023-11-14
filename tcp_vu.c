// SPDX-License-Identifier: GPL-2.0-or-later

#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#include <netinet/ip.h>

#include <sys/socket.h>

#include <linux/tcp.h>
#include <linux/virtio_net.h>

#include "util.h"
#include "ip.h"
#include "passt.h"
#include "siphash.h"
#include "inany.h"
#include "vhost_user.h"
#include "tcp.h"
#include "pcap.h"
#include "flow.h"
#include "tcp_conn.h"
#include "flow_table.h"
#include "tcp_vu.h"
#include "tcp_internal.h"
#include "checksum.h"

#define CONN_V4(conn)		(!!inany_v4(&(conn)->faddr))
#define CONN_V6(conn)		(!CONN_V4(conn))

/* vhost-user */
static const struct virtio_net_hdr vu_header = {
	.flags = VIRTIO_NET_HDR_F_DATA_VALID,
	.gso_type = VIRTIO_NET_HDR_GSO_NONE,
};

static unsigned char buffer[65536];
static struct iovec	iov_vu			[VIRTQUEUE_MAX_SIZE];
static unsigned int	indexes			[VIRTQUEUE_MAX_SIZE];

uint16_t tcp_vu_conn_tap_mss(const struct tcp_tap_conn *conn)
{
	(void)conn;
	return USHRT_MAX;
}

int tcp_vu_send_flag(struct ctx *c, struct tcp_tap_conn *conn, int flags)
{
	VuDev *vdev = (VuDev *)&c->vdev;
	VuVirtq *vq = &vdev->vq[VHOST_USER_RX_QUEUE];
	size_t tlen, vnet_hdrlen, ip_len, optlen = 0;
	struct virtio_net_hdr_mrg_rxbuf *vh;
	VuVirtqElement *elem;
	struct ethhdr *eh;
	int nb_ack;
	int ret;

	elem = vu_queue_pop(vdev, vq, sizeof(VuVirtqElement), buffer);
	if (!elem)
		return 0;

	if (elem->in_num < 1) {
		err("virtio-net receive queue contains no in buffers");
		vu_queue_rewind(vdev, vq, 1);
		return 0;
	}

	vh = elem->in_sg[0].iov_base;

	vh->hdr = vu_header;
	if (vu_has_feature(vdev, VIRTIO_NET_F_MRG_RXBUF)) {
		vnet_hdrlen = sizeof(struct virtio_net_hdr_mrg_rxbuf);
		vh->num_buffers = htole16(1);
	} else {
		vnet_hdrlen = sizeof(struct virtio_net_hdr);
	}
	eh = (struct ethhdr *)((char *)elem->in_sg[0].iov_base + vnet_hdrlen);

	memcpy(eh->h_dest, c->mac_guest, sizeof(eh->h_dest));
	memcpy(eh->h_source, c->mac, sizeof(eh->h_source));

	if (CONN_V4(conn)) {
		struct iphdr *iph = (struct iphdr *)(eh + 1);
		struct tcphdr *th = (struct tcphdr *)(iph + 1);
		char *data = (char *)(th + 1);

		eh->h_proto = htons(ETH_P_IP);

		*th = (struct tcphdr){
			.doff = sizeof(struct tcphdr) / 4,
			.ack = 1
		};

		*iph = (struct iphdr)L2_BUF_IP4_INIT(IPPROTO_TCP);

		ret = tcp_fill_flag_header(c, conn, flags, th, data, &optlen);
		if (ret <= 0) {
			vu_queue_rewind(vdev, vq, 1);
			return ret;
		}

		ip_len = tcp_fill_headers4(c, conn, iph,
					   (struct tcphdr *)(iph + 1), optlen,
					   NULL, conn->seq_to_tap);

		tlen =  ip_len + sizeof(struct ethhdr);

		if (*c->pcap) {
			uint32_t sum = proto_ipv4_header_psum(iph->tot_len,
							      IPPROTO_TCP,
				(struct in_addr){ .s_addr = iph->saddr },
				(struct in_addr){ .s_addr = iph->daddr });

			th->check = csum(th, optlen + sizeof(struct tcphdr), sum);
		}
	} else {
		struct ipv6hdr *ip6h = (struct ipv6hdr *)(eh + 1);
		struct tcphdr *th = (struct tcphdr *)(ip6h + 1);
		char *data = (char *)(th + 1);

		eh->h_proto = htons(ETH_P_IPV6);

		*th = (struct tcphdr){
			.doff = sizeof(struct tcphdr) / 4,
			.ack = 1
		};

		*ip6h = (struct ipv6hdr)L2_BUF_IP6_INIT(IPPROTO_TCP);

		ret = tcp_fill_flag_header(c, conn, flags, th, data, &optlen);
		if (ret <= 0) {
			vu_queue_rewind(vdev, vq, 1);
			return ret;
		}

		ip_len = tcp_fill_headers6(c, conn, ip6h,
					   (struct tcphdr *)(ip6h + 1),
					   optlen, conn->seq_to_tap);

		tlen =  ip_len + sizeof(struct ethhdr);

		if (*c->pcap) {
			uint32_t sum = proto_ipv6_header_psum(ip6h->payload_len,
							      IPPROTO_TCP,
							      &ip6h->saddr,
							      &ip6h->daddr);

			th->check = csum(th, optlen + sizeof(struct tcphdr), sum);
		}
	}

	pcap((void *)eh, tlen);

	tlen += vnet_hdrlen;
	vu_queue_fill(vdev, vq, elem, tlen, 0);
	nb_ack = 1;

	if (flags & DUP_ACK) {
		elem = vu_queue_pop(vdev, vq, sizeof(VuVirtqElement), buffer);
		if (elem) {
			if (elem->in_num < 1 || elem->in_sg[0].iov_len < tlen) {
				vu_queue_rewind(vdev, vq, 1);
			} else {
				memcpy(elem->in_sg[0].iov_base, vh, tlen);
				nb_ack++;
			}
		}
	}

	vu_queue_flush(vdev, vq, nb_ack);
	vu_queue_notify(vdev, vq);

	return 0;
}

int tcp_vu_data_from_sock(struct ctx *c, struct tcp_tap_conn *conn)
{
	uint32_t wnd_scaled = conn->wnd_from_tap << conn->ws_from_tap;
	uint32_t already_sent;
	VuDev *vdev = (VuDev *)&c->vdev;
	VuVirtq *vq = &vdev->vq[VHOST_USER_RX_QUEUE];
	int s = conn->sock, v4 = CONN_V4(conn);
	int i, ret = 0, iov_count, iov_used;
	struct msghdr mh_sock = { 0 };
	size_t l2_hdrlen, vnet_hdrlen, fillsize;
	ssize_t len;
	uint16_t *check;
	uint16_t mss = MSS_GET(conn);
	int num_buffers;
	int segment_size;
	struct iovec *first;
	bool has_mrg_rxbuf;

	if (!vu_queue_enabled(vq) || !vu_queue_started(vq)) {
		err("Got packet, but no available descriptors on RX virtq.");
		return 0;
	}

	already_sent = conn->seq_to_tap - conn->seq_ack_from_tap;

	if (SEQ_LT(already_sent, 0)) {
		/* RFC 761, section 2.1. */
		flow_trace(conn, "ACK sequence gap: ACK for %u, sent: %u",
			   conn->seq_ack_from_tap, conn->seq_to_tap);
		conn->seq_to_tap = conn->seq_ack_from_tap;
		already_sent = 0;
	}

	if (!wnd_scaled || already_sent >= wnd_scaled) {
		conn_flag(c, conn, STALLED);
		conn_flag(c, conn, ACK_FROM_TAP_DUE);
		return 0;
	}

	/* Set up buffer descriptors we'll fill completely and partially. */

	fillsize = wnd_scaled;

	iov_vu[0].iov_base = tcp_buf_discard;
	iov_vu[0].iov_len = already_sent;
	fillsize -= already_sent;

	has_mrg_rxbuf = vu_has_feature(vdev, VIRTIO_NET_F_MRG_RXBUF);
	if (has_mrg_rxbuf) {
		vnet_hdrlen = sizeof(struct virtio_net_hdr_mrg_rxbuf);
	} else {
		vnet_hdrlen = sizeof(struct virtio_net_hdr);
	}
	l2_hdrlen = vnet_hdrlen + sizeof(struct ethhdr) + sizeof(struct tcphdr);
	if (v4) {
		l2_hdrlen += sizeof(struct iphdr);
	} else {
		l2_hdrlen += sizeof(struct ipv6hdr);
	}

	iov_count = 0;
	segment_size = 0;
	while (fillsize > 0 && iov_count < VIRTQUEUE_MAX_SIZE - 1) {
		VuVirtqElement *elem;

		elem = vu_queue_pop(vdev, vq, sizeof(VuVirtqElement), buffer);
		if (!elem)
			break;

		if (elem->in_num < 1) {
			err("virtio-net receive queue contains no in buffers");
			goto err;
		}

		ASSERT(elem->in_num == 1);
		ASSERT(elem->in_sg[0].iov_len >= l2_hdrlen);

		indexes[iov_count] = elem->index;

		if (segment_size == 0) {
			iov_vu[iov_count + 1].iov_base =
					(char *)elem->in_sg[0].iov_base + l2_hdrlen;
			iov_vu[iov_count + 1].iov_len =
					elem->in_sg[0].iov_len - l2_hdrlen;
		} else {
			iov_vu[iov_count + 1].iov_base = elem->in_sg[0].iov_base;
			iov_vu[iov_count + 1].iov_len = elem->in_sg[0].iov_len;
		}

		if (iov_vu[iov_count + 1].iov_len > fillsize)
			 iov_vu[iov_count + 1].iov_len = fillsize;

		segment_size += iov_vu[iov_count + 1].iov_len;
		if (!has_mrg_rxbuf) {
			segment_size = 0;
		} else if (segment_size >= mss) {
			iov_vu[iov_count + 1].iov_len -= segment_size - mss;
			segment_size = 0;
		}
		fillsize -= iov_vu[iov_count + 1].iov_len;

		iov_count++;
	}
	if (iov_count == 0)
		return 0;

	mh_sock.msg_iov = iov_vu;
	mh_sock.msg_iovlen = iov_count + 1;

	do
		len = recvmsg(s, &mh_sock, MSG_PEEK);
	while (len < 0 && errno == EINTR);

	if (len < 0)
		goto err;

	if (!len) {
		vu_queue_rewind(vdev, vq, iov_count);
		if ((conn->events & (SOCK_FIN_RCVD | TAP_FIN_SENT)) == SOCK_FIN_RCVD) {
			if ((ret = tcp_vu_send_flag(c, conn, FIN | ACK))) {
				tcp_rst(c, conn);
				return ret;
			}

			conn_event(c, conn, TAP_FIN_SENT);
		}

		return 0;
	}

	len -= already_sent;
	if (len <= 0) {
		conn_flag(c, conn, STALLED);
		vu_queue_rewind(vdev, vq, iov_count);
		return 0;
	}

	conn_flag(c, conn, ~STALLED);

	/* Likely, some new data was acked too. */
	tcp_update_seqack_wnd(c, conn, 0, NULL);

	/* initialize headers */
	iov_used = 0;
	num_buffers = 0;
	check = NULL;
	segment_size = 0;
	for (i = 0; i < iov_count && len; i++) {

		if (segment_size == 0)
			first = &iov_vu[i + 1];

		if (iov_vu[i + 1].iov_len > (size_t)len)
			iov_vu[i + 1].iov_len = len;

		len -= iov_vu[i + 1].iov_len;
		iov_used++;

		segment_size += iov_vu[i + 1].iov_len;
		num_buffers++;

		if (segment_size >= mss || len == 0 ||
		    i + 1 == iov_count || !has_mrg_rxbuf) {

			struct ethhdr *eh;
			struct virtio_net_hdr_mrg_rxbuf *vh;
			char *base = (char *)first->iov_base - l2_hdrlen;
			size_t size = first->iov_len + l2_hdrlen;

			vh = (struct virtio_net_hdr_mrg_rxbuf *)base;

			vh->hdr = vu_header;
			if (has_mrg_rxbuf)
				vh->num_buffers = htole16(num_buffers);

			eh = (struct ethhdr *)((char *)base + vnet_hdrlen);

			memcpy(eh->h_dest, c->mac_guest, sizeof(eh->h_dest));
			memcpy(eh->h_source, c->mac, sizeof(eh->h_source));

			/* initialize header */
			if (v4) {
				struct iphdr *iph = (struct iphdr *)(eh + 1);
				struct tcphdr *th = (struct tcphdr *)(iph + 1);

				eh->h_proto = htons(ETH_P_IP);

				*th = (struct tcphdr){
					.doff = sizeof(struct tcphdr) / 4,
					.ack = 1
				};

				*iph = (struct iphdr)L2_BUF_IP4_INIT(IPPROTO_TCP);

				tcp_fill_headers4(c, conn, iph,
						  (struct tcphdr *)(iph + 1),
						  segment_size, len ? check : NULL,
						  conn->seq_to_tap);

				if (*c->pcap) {
					uint32_t sum = proto_ipv4_header_psum(iph->tot_len,
									      IPPROTO_TCP,
				(struct in_addr){ .s_addr = iph->saddr },
				(struct in_addr){ .s_addr = iph->daddr });

					first->iov_base = th;
					first->iov_len = size - l2_hdrlen + sizeof(*th);

					th->check = csum_iov(first, num_buffers, sum);
				}

				check = &iph->check;
			} else {
				struct ipv6hdr *ip6h = (struct ipv6hdr *)(eh + 1);
				struct tcphdr *th = (struct tcphdr *)(ip6h + 1);

				eh->h_proto = htons(ETH_P_IPV6);

				*th = (struct tcphdr){
					.doff = sizeof(struct tcphdr) / 4,
					.ack = 1
				};

				*ip6h = (struct ipv6hdr)L2_BUF_IP6_INIT(IPPROTO_TCP);

				tcp_fill_headers6(c, conn, ip6h,
						  (struct tcphdr *)(ip6h + 1),
						  segment_size, conn->seq_to_tap);
				if (*c->pcap) {
					uint32_t sum = proto_ipv6_header_psum(ip6h->payload_len,
									      IPPROTO_TCP,
									      &ip6h->saddr,
									      &ip6h->daddr);

					first->iov_base = th;
					first->iov_len = size - l2_hdrlen + sizeof(*th);

					th->check = csum_iov(first, num_buffers, sum);
				}
			}

			/* set iov for pcap logging */
			first->iov_base = eh;
			first->iov_len = size - vnet_hdrlen;

			pcap_iov(first, num_buffers);

			/* set iov_len for vu_queue_fill_by_index(); */

			first->iov_base = base;
			first->iov_len = size;

			conn->seq_to_tap += segment_size;

			segment_size = 0;
			num_buffers = 0;
		}
	}

	/* release unused buffers */
	vu_queue_rewind(vdev, vq, iov_count - iov_used);

	/* send packets */
	for (i = 0; i < iov_used; i++) {
		vu_queue_fill_by_index(vdev, vq, indexes[i],
				       iov_vu[i + 1].iov_len, i);
	}

	vu_queue_flush(vdev, vq, iov_used);
	vu_queue_notify(vdev, vq);

	conn_flag(c, conn, ACK_FROM_TAP_DUE);

	return 0;
err:
	vu_queue_rewind(vdev, vq, iov_count);

	if (errno != EAGAIN && errno != EWOULDBLOCK) {
		ret = -errno;
		tcp_rst(c, conn);
	}

	return ret;
}
