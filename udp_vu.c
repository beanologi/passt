// SPDX-License-Identifier: GPL-2.0-or-later

#include <unistd.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/uio.h>
#include <linux/virtio_net.h>

#include "checksum.h"
#include "util.h"
#include "ip.h"
#include "passt.h"
#include "pcap.h"
#include "log.h"
#include "vhost_user.h"
#include "udp_internal.h"
#include "udp_vu.h"

/* vhost-user */
static const struct virtio_net_hdr vu_header = {
	.flags = VIRTIO_NET_HDR_F_DATA_VALID,
	.gso_type = VIRTIO_NET_HDR_GSO_NONE,
};

static unsigned char buffer[65536];
static struct iovec     iov_vu		[VIRTQUEUE_MAX_SIZE];
static unsigned int     indexes		[VIRTQUEUE_MAX_SIZE];

void udp_vu_sock_handler(const struct ctx *c, union epoll_ref ref, uint32_t events,
			 const struct timespec *now)
{
	VuDev *vdev = (VuDev *)&c->vdev;
	VuVirtq *vq = &vdev->vq[VHOST_USER_RX_QUEUE];
	size_t l2_hdrlen, vnet_hdrlen, fillsize;
	ssize_t data_len;
	in_port_t dstport = ref.udp.port;
	bool has_mrg_rxbuf, v6 = ref.udp.v6;
	struct msghdr msg;
	int i, iov_count, iov_used, virtqueue_max;

	if (c->no_udp || !(events & EPOLLIN))
		return;

	has_mrg_rxbuf = vu_has_feature(vdev, VIRTIO_NET_F_MRG_RXBUF);
	if (has_mrg_rxbuf) {
		vnet_hdrlen = sizeof(struct virtio_net_hdr_mrg_rxbuf);
		virtqueue_max = VIRTQUEUE_MAX_SIZE;
	} else {
		vnet_hdrlen = sizeof(struct virtio_net_hdr);
		virtqueue_max = 1;
	}
	l2_hdrlen = vnet_hdrlen + sizeof(struct ethhdr) + sizeof(struct udphdr);

	if (v6) {
		l2_hdrlen += sizeof(struct ipv6hdr);

		udp6_localname.sin6_port = htons(dstport);
		msg.msg_name = &udp6_localname;
		msg.msg_namelen = sizeof(udp6_localname);
	} else {
		l2_hdrlen += sizeof(struct iphdr);

		udp4_localname.sin_port = htons(dstport);
		msg.msg_name = &udp4_localname;
		msg.msg_namelen = sizeof(udp4_localname);
	}

	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;

	for (i = 0; i < UDP_MAX_FRAMES; i++) {
		struct virtio_net_hdr_mrg_rxbuf *vh;
		struct ethhdr *eh;
		char *base;
		size_t size;

		fillsize = USHRT_MAX;
		iov_count = 0;
		while (fillsize && iov_count < virtqueue_max) {
			VuVirtqElement *elem;

			elem = vu_queue_pop(vdev, vq, sizeof(VuVirtqElement), buffer);
			if (!elem)
				break;

			if (elem->in_num < 1) {
				err("virtio-net receive queue contains no in buffers");
				vu_queue_rewind(vdev, vq, iov_count);
				return;
			}
			ASSERT(elem->in_num == 1);
			ASSERT(elem->in_sg[0].iov_len >= l2_hdrlen);

			indexes[iov_count] = elem->index;
			if (iov_count == 0) {
				iov_vu[0].iov_base = (char *)elem->in_sg[0].iov_base + l2_hdrlen;
				iov_vu[0].iov_len = elem->in_sg[0].iov_len - l2_hdrlen;
			} else {
				iov_vu[iov_count].iov_base = elem->in_sg[0].iov_base;
				iov_vu[iov_count].iov_len = elem->in_sg[0].iov_len;
			}

			if (iov_vu[iov_count].iov_len > fillsize)
				iov_vu[iov_count].iov_len = fillsize;

			fillsize -= iov_vu[iov_count].iov_len;

			iov_count++;
		}
		if (iov_count == 0)
			break;

		msg.msg_iov = iov_vu;
		msg.msg_iovlen = iov_count;

		data_len = recvmsg(ref.fd, &msg, 0);
		if (data_len < 0) {
			vu_queue_rewind(vdev, vq, iov_count);
			return;
		}

		iov_used = 0;
		size = data_len;
		while (size) {
			if (iov_vu[iov_used].iov_len > size)
				iov_vu[iov_used].iov_len = size;

			size -= iov_vu[iov_used].iov_len;
			iov_used++;
		}

		base = (char *)iov_vu[0].iov_base - l2_hdrlen;
		size = iov_vu[0].iov_len + l2_hdrlen;

		/* release unused buffers */
		vu_queue_rewind(vdev, vq, iov_count - iov_used);

		/* vnet_header */
		vh = (struct virtio_net_hdr_mrg_rxbuf *)base;
		vh->hdr = vu_header;
		if (has_mrg_rxbuf)
			vh->num_buffers = htole16(iov_used);

		/* ethernet header */
		eh = (struct ethhdr *)(base + vnet_hdrlen);

		memcpy(eh->h_dest, c->mac_guest, sizeof(eh->h_dest));
		memcpy(eh->h_source, c->mac, sizeof(eh->h_source));

		/* initialize header */
		if (v6) {
			struct ipv6hdr *ip6h = (struct ipv6hdr *)(eh + 1);
			struct udphdr *uh = (struct udphdr *)(ip6h + 1);
			uint32_t sum;

			eh->h_proto = htons(ETH_P_IPV6);

			*ip6h = (struct ipv6hdr)L2_BUF_IP6_INIT(IPPROTO_UDP);

			udp_update_hdr6(c, ip6h, data_len, &udp6_localname,
					dstport, now);
			if (*c->pcap) {
				sum = proto_ipv6_header_psum(ip6h->payload_len,
							     IPPROTO_UDP,
							     &ip6h->saddr,
							     &ip6h->daddr);

				iov_vu[0].iov_base = uh;
				iov_vu[0].iov_len = size - l2_hdrlen + sizeof(*uh);
				uh->check = csum_iov(iov_vu, iov_used, sum);
			}
		} else {
			struct iphdr *iph = (struct iphdr *)(eh + 1);
			struct udphdr *uh = (struct udphdr *)(iph + 1);
			uint32_t sum;

			eh->h_proto = htons(ETH_P_IP);

			*iph = (struct iphdr)L2_BUF_IP4_INIT(IPPROTO_UDP);

			udp_update_hdr4(c, iph, data_len, &udp4_localname,
					dstport, now);
			if (*c->pcap) {
				sum = proto_ipv4_header_psum(iph->tot_len,
							     IPPROTO_UDP,
				(struct in_addr){ .s_addr = iph->saddr },
				(struct in_addr){ .s_addr = iph->daddr });

				iov_vu[0].iov_base = uh;
				iov_vu[0].iov_len = size - l2_hdrlen + sizeof(*uh);
				uh->check = csum_iov(iov_vu, iov_used, sum);
			}
		}

		/* set iov for pcap logging */
		iov_vu[0].iov_base = base + vnet_hdrlen;
		iov_vu[0].iov_len = size - vnet_hdrlen;
		pcap_iov(iov_vu, iov_used);

		/* set iov_len for vu_queue_fill_by_index(); */
		iov_vu[0].iov_base = base;
		iov_vu[0].iov_len = size;

		/* send packets */
		for (i = 0; i < iov_used; i++)
			vu_queue_fill_by_index(vdev, vq, indexes[i],
					       iov_vu[i].iov_len, i);

		vu_queue_flush(vdev, vq, iov_used);
		vu_queue_notify(vdev, vq);
	}
}
