// SPDX-License-Identifier: GPL-2.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * tcp_buf.c - TCP L2-L4 translation state machine
 *
 * Copyright (c) 2020-2022 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#include <stddef.h>
#include <stdint.h>
#include <limits.h>
#include <string.h>
#include <errno.h>

#include <netinet/ip.h>

#include <linux/tcp.h>

#include "util.h"
#include "ip.h"
#include "passt.h"
#include "tap.h"
#include "siphash.h"
#include "inany.h"
#include "tcp_conn.h"
#include "tcp_internal.h"
#include "tcp_buf.h"

#define TCP_FRAMES_MEM			128
#define TCP_FRAMES							\
	(c->mode == MODE_PASTA ? 1 : TCP_FRAMES_MEM)

/**
 * tcp_buf_seq_update - Sequences to update with length of frames once sent
 * @seq:	Pointer to sequence number sent to tap-side, to be updated
 * @len:	TCP payload length
 */
struct tcp_buf_seq_update {
	uint32_t *seq;
	uint16_t len;
};

/* Static buffers */
/**
 * tcp_l2_flags_t - TCP header and data to send option flags
 * @th:		TCP header
 * @opts	TCP option flags
 */
struct tcp_l2_flags_t {
	struct tcphdr th;
	char opts[OPT_MSS_LEN + OPT_WS_LEN + 1];
};
/**
 * tcp_l2_payload_t - TCP header and data to send data
 * 		32 bytes aligned to be able to use AVX2 checksum
 * @th:		TCP header
 * @data:	TCP data
 */
struct tcp_l2_payload_t {
	struct tcphdr th;	/*    20 bytes */
	uint8_t data[MSS];	/* 65516 bytes */
#ifdef __AVX2__
} __attribute__ ((packed, aligned(32)));
#else
} __attribute__ ((packed, aligned(__alignof__(unsigned int))));
#endif

/* Ethernet header for IPv4 frames */
static struct ethhdr		tcp4_eth_src;

/* IPv4 headers */
static struct iphdr		tcp4_l2_ip[TCP_FRAMES_MEM];
/* TCP headers and data for IPv4 frames */
static struct tcp_l2_payload_t	tcp4_l2_payload[TCP_FRAMES_MEM];

static struct tcp_buf_seq_update tcp4_l2_buf_seq_update[TCP_FRAMES_MEM];
static unsigned int tcp4_l2_buf_used;

/* IPv4 headers for TCP option flags frames */
static struct iphdr		tcp4_l2_flags_ip[TCP_FRAMES_MEM];
/* TCP headers and option flags for IPv4 frames */
static struct tcp_l2_flags_t	tcp4_l2_flags[TCP_FRAMES_MEM];

static unsigned int tcp4_l2_flags_buf_used;

/* Ethernet header for IPv6 frames */
static struct ethhdr		tcp6_eth_src;

/* IPv6 headers */
static struct ipv6hdr		tcp6_l2_ip[TCP_FRAMES_MEM];
/* TCP headers and data for IPv6 frames */
static struct tcp_l2_payload_t	tcp6_l2_payload[TCP_FRAMES_MEM];

static struct tcp_buf_seq_update tcp6_l2_buf_seq_update[TCP_FRAMES_MEM];
static unsigned int tcp6_l2_buf_used;

/* IPv6 headers for TCP option flags frames */
static struct ipv6hdr		tcp6_l2_flags_ip[TCP_FRAMES_MEM];
/* TCP headers and option flags for IPv6 frames */
static struct tcp_l2_flags_t	tcp6_l2_flags[TCP_FRAMES_MEM];

static unsigned int tcp6_l2_flags_buf_used;

/* recvmsg()/sendmsg() data for tap */
static char 		tcp_buf_discard		[MAX_WINDOW];
static struct iovec	iov_sock		[TCP_FRAMES_MEM + 1];

static struct iovec	tcp4_l2_iov		[TCP_FRAMES_MEM][TCP_IOV_NUM];
static struct iovec	tcp6_l2_iov		[TCP_FRAMES_MEM][TCP_IOV_NUM];
static struct iovec	tcp4_l2_flags_iov	[TCP_FRAMES_MEM][TCP_IOV_NUM];
static struct iovec	tcp6_l2_flags_iov	[TCP_FRAMES_MEM][TCP_IOV_NUM];

/**
 * tcp_buf_update_l2() - Update L2 buffers with Ethernet and IPv4 addresses
 * @eth_d:	Ethernet destination address, NULL if unchanged
 * @eth_s:	Ethernet source address, NULL if unchanged
 */
void tcp_buf_update_l2(const unsigned char *eth_d, const unsigned char *eth_s)
{
	eth_update_mac(&tcp4_eth_src, eth_d, eth_s);
	eth_update_mac(&tcp6_eth_src, eth_d, eth_s);
}

/**
 * tcp_buf_sock4_iov_init() - Initialise scatter-gather L2 buffers for IPv4 sockets
 * @c:		Execution context
 */
void tcp_buf_sock4_iov_init(const struct ctx *c)
{
	struct iphdr iph = L2_BUF_IP4_INIT(IPPROTO_TCP);
	int i;

	(void)c;

	tcp4_eth_src.h_proto = htons_constant(ETH_P_IP);
	for (i = 0; i < TCP_FRAMES_MEM; i++) {
		struct iovec *iov;

		/* headers */
		tcp4_l2_ip[i] = iph;
		tcp4_l2_payload[i].th = (struct tcphdr){
					.doff = sizeof(struct tcphdr) / 4,
					.ack = 1
				};

		tcp4_l2_flags_ip[i] = iph;
		tcp4_l2_flags[i].th = (struct tcphdr){
					.doff = sizeof(struct tcphdr) / 4,
					.ack = 1
				};

		/* iovecs */
		iov = tcp4_l2_iov[i];
		iov[TCP_IOV_ETH].iov_base = &tcp4_eth_src;
		iov[TCP_IOV_ETH].iov_len = sizeof(struct ethhdr);
		iov[TCP_IOV_IP].iov_base = &tcp4_l2_ip[i];
		iov[TCP_IOV_IP].iov_len = sizeof(struct iphdr);
		iov[TCP_IOV_PAYLOAD].iov_base = &tcp4_l2_payload[i];

		iov = tcp4_l2_flags_iov[i];
		iov[TCP_IOV_ETH].iov_base = &tcp4_eth_src;
		iov[TCP_IOV_ETH].iov_len = sizeof(struct ethhdr);
		iov[TCP_IOV_IP].iov_base = &tcp4_l2_flags_ip[i];
		iov[TCP_IOV_IP].iov_len = sizeof(struct iphdr);
		iov[TCP_IOV_PAYLOAD].iov_base = &tcp4_l2_flags[i];
	}
}

/**
 * tcp_buf_sock6_iov_init() - Initialise scatter-gather L2 buffers for IPv6 sockets
 * @c:		Execution context
 */
void tcp_buf_sock6_iov_init(const struct ctx *c)
{
	struct ipv6hdr ip6 = L2_BUF_IP6_INIT(IPPROTO_TCP);
	int i;

	(void)c;

	tcp6_eth_src.h_proto = htons_constant(ETH_P_IPV6);
	for (i = 0; i < TCP_FRAMES_MEM; i++) {
		struct iovec *iov;

		/* headers */
		tcp6_l2_ip[i] = ip6;
		tcp6_l2_payload[i].th = (struct tcphdr){
					.doff = sizeof(struct tcphdr) / 4,
					.ack = 1
				};

		tcp6_l2_flags_ip[i] = ip6;
		tcp6_l2_flags[i].th = (struct tcphdr){
					.doff = sizeof(struct tcphdr) / 4,
					.ack = 1
				};

		/* iovecs */
		iov = tcp6_l2_iov[i];
		iov[TCP_IOV_ETH].iov_base = &tcp6_eth_src;
		iov[TCP_IOV_ETH].iov_len = sizeof(struct ethhdr);
		iov[TCP_IOV_IP].iov_base = &tcp6_l2_ip[i];
		iov[TCP_IOV_IP].iov_len = sizeof(struct ipv6hdr);
		iov[TCP_IOV_PAYLOAD].iov_base = &tcp6_l2_payload[i];

		iov = tcp6_l2_flags_iov[i];
		iov[TCP_IOV_ETH].iov_base = &tcp6_eth_src;
		iov[TCP_IOV_ETH].iov_len = sizeof(struct ethhdr);
		iov[TCP_IOV_IP].iov_base = &tcp6_l2_flags_ip[i];
		iov[TCP_IOV_IP].iov_len = sizeof(struct ipv6hdr);
		iov[TCP_IOV_PAYLOAD].iov_base = &tcp6_l2_flags[i];
	}
}

/**
 * tcp_buf_l2_flags_flush() - Send out buffers for segments with no data (flags)
 * @c:		Execution context
 */
void tcp_buf_l2_flags_flush(const struct ctx *c)
{
	tap_send_iov(c, tcp6_l2_flags_iov, tcp6_l2_flags_buf_used);
	tcp6_l2_flags_buf_used = 0;

	tap_send_iov(c, tcp4_l2_flags_iov, tcp4_l2_flags_buf_used);
	tcp4_l2_flags_buf_used = 0;
}

/**
 * tcp_buf_l2_data_flush() - Send out buffers for segments with data
 * @c:		Execution context
 */
void tcp_buf_l2_data_flush(const struct ctx *c)
{
	unsigned i;
	size_t m;

	m = tap_send_iov(c, tcp6_l2_iov, tcp6_l2_buf_used);
	for (i = 0; i < m; i++)
		*tcp6_l2_buf_seq_update[i].seq += tcp6_l2_buf_seq_update[i].len;
	tcp6_l2_buf_used = 0;

	m = tap_send_iov(c, tcp4_l2_iov, tcp4_l2_buf_used);
	for (i = 0; i < m; i++)
		*tcp4_l2_buf_seq_update[i].seq += tcp4_l2_buf_seq_update[i].len;
	tcp4_l2_buf_used = 0;
}

int tcp_buf_send_flag(struct ctx *c, struct tcp_tap_conn *conn, int flags)
{
	struct tcp_l2_flags_t *payload;
	struct iovec *dup_iov;
	struct iovec *iov;
	struct tcphdr *th;
	size_t optlen = 0;
	size_t ip_len;
	char *data;
	int ret;

	if (CONN_V4(conn)) {
		iov = tcp4_l2_flags_iov[tcp4_l2_flags_buf_used++];
		dup_iov = tcp4_l2_flags_iov[tcp4_l2_flags_buf_used];
	} else {
		iov = tcp6_l2_flags_iov[tcp6_l2_flags_buf_used++];
		dup_iov = tcp6_l2_flags_iov[tcp6_l2_flags_buf_used];
	}
	payload = iov[TCP_IOV_PAYLOAD].iov_base;
	th = &payload->th;
	data = payload->opts;

	ret = tcp_fill_flag_header(c, conn, flags, th, data, &optlen);
	if (ret <= 0)
		return ret;

	if (CONN_V4(conn)) {
		struct iphdr *iph = iov[TCP_IOV_IP].iov_base;

		ip_len = tcp_fill_headers4(c, conn, iph, th, optlen, NULL,
					   conn->seq_to_tap);
	} else {
		struct ipv6hdr *ip6h = iov[TCP_IOV_IP].iov_base;

		ip_len = tcp_fill_headers6(c, conn, ip6h, th, optlen,
					   conn->seq_to_tap);
	}
	iov[TCP_IOV_PAYLOAD].iov_len = ip_len;

	if (flags & DUP_ACK) {
		int i;
		for (i = 0; i < TCP_IOV_NUM; i++) {
			memcpy(dup_iov[i].iov_base, iov[i].iov_base,
			       iov[i].iov_len);
			dup_iov[i].iov_len = iov[i].iov_len;
		}
	}

	if (CONN_V4(conn)) {
		if (flags & DUP_ACK)
			tcp4_l2_flags_buf_used++;

		if (tcp4_l2_flags_buf_used > TCP_FRAMES_MEM - 2)
			tcp_buf_l2_flags_flush(c);
	} else {
		if (flags & DUP_ACK)
			tcp6_l2_flags_buf_used++;

		if (tcp6_l2_flags_buf_used > TCP_FRAMES_MEM - 2)
			tcp_buf_l2_flags_flush(c);
	}

	return 0;
}

/**
 * tcp_data_to_tap() - Finalise (queue) highest-numbered scatter-gather buffer
 * @c:		Execution context
 * @conn:	Connection pointer
 * @plen:	Payload length at L4
 * @no_csum:	Don't compute IPv4 checksum, use the one from previous buffer
 * @seq:	Sequence number to be sent
 */
static void tcp_data_to_tap(const struct ctx *c, struct tcp_tap_conn *conn,
			    ssize_t plen, int no_csum, uint32_t seq)
{
	uint32_t *seq_update = &conn->seq_to_tap;
	struct iovec *iov;

	if (CONN_V4(conn)) {
		struct iovec *iov_prev = tcp4_l2_iov[tcp4_l2_buf_used - 1];
		const uint16_t *check = NULL;

		if (no_csum) {
			struct iphdr *iph = iov_prev[TCP_IOV_IP].iov_base;
			check = &iph->check;
		}

		tcp4_l2_buf_seq_update[tcp4_l2_buf_used].seq = seq_update;
		tcp4_l2_buf_seq_update[tcp4_l2_buf_used].len = plen;

		iov = tcp4_l2_iov[tcp4_l2_buf_used++];
		iov[TCP_IOV_PAYLOAD].iov_len = tcp_fill_headers4(c, conn,
						iov[TCP_IOV_IP].iov_base,
						iov[TCP_IOV_PAYLOAD].iov_base,
						plen, check, seq);

		if (tcp4_l2_buf_used > TCP_FRAMES_MEM - 1)
			tcp_buf_l2_data_flush(c);
	} else if (CONN_V6(conn)) {
		tcp6_l2_buf_seq_update[tcp6_l2_buf_used].seq = seq_update;
		tcp6_l2_buf_seq_update[tcp6_l2_buf_used].len = plen;

		iov = tcp6_l2_iov[tcp6_l2_buf_used++];
		iov[TCP_IOV_PAYLOAD].iov_len = tcp_fill_headers6(c, conn,
						iov[TCP_IOV_IP].iov_base,
						iov[TCP_IOV_PAYLOAD].iov_base,
						plen, seq);

		if (tcp6_l2_buf_used > TCP_FRAMES_MEM - 1)
			tcp_buf_l2_data_flush(c);
	}
}

/**
 * tcp_buf_data_from_sock() - Handle new data from socket, queue to tap, in window
 * @c:		Execution context
 * @conn:	Connection pointer
 *
 * Return: negative on connection reset, 0 otherwise
 *
 * #syscalls recvmsg
 */
int tcp_buf_data_from_sock(struct ctx *c, struct tcp_tap_conn *conn)
{
	uint32_t wnd_scaled = conn->wnd_from_tap << conn->ws_from_tap;
	int fill_bufs, send_bufs = 0, last_len, iov_rem = 0;
	int sendlen, len, plen, v4 = CONN_V4(conn);
	int s = conn->sock, i, ret = 0;
	struct msghdr mh_sock = { 0 };
	uint16_t mss = MSS_GET(conn);
	uint32_t already_sent, seq;
	struct iovec *iov;

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
	fill_bufs = DIV_ROUND_UP(wnd_scaled - already_sent, mss);
	if (fill_bufs > TCP_FRAMES) {
		fill_bufs = TCP_FRAMES;
		iov_rem = 0;
	} else {
		iov_rem = (wnd_scaled - already_sent) % mss;
	}

	mh_sock.msg_iov = iov_sock;
	mh_sock.msg_iovlen = fill_bufs + 1;

	iov_sock[0].iov_base = tcp_buf_discard;
	iov_sock[0].iov_len = already_sent;

	if (( v4 && tcp4_l2_buf_used + fill_bufs > TCP_FRAMES_MEM) ||
	    (!v4 && tcp6_l2_buf_used + fill_bufs > TCP_FRAMES_MEM)) {
		tcp_buf_l2_data_flush(c);

		/* Silence Coverity CWE-125 false positive */
		tcp4_l2_buf_used = tcp6_l2_buf_used = 0;
	}

	for (i = 0, iov = iov_sock + 1; i < fill_bufs; i++, iov++) {
		if (v4)
			iov->iov_base = &tcp4_l2_payload[tcp4_l2_buf_used + i].data;
		else
			iov->iov_base = &tcp6_l2_payload[tcp6_l2_buf_used + i].data;
		iov->iov_len = mss;
	}
	if (iov_rem)
		iov_sock[fill_bufs].iov_len = iov_rem;

	/* Receive into buffers, don't dequeue until acknowledged by guest. */
	do
		len = recvmsg(s, &mh_sock, MSG_PEEK);
	while (len < 0 && errno == EINTR);

	if (len < 0)
		goto err;

	if (!len) {
		if ((conn->events & (SOCK_FIN_RCVD | TAP_FIN_SENT)) == SOCK_FIN_RCVD) {
			if ((ret = tcp_buf_send_flag(c, conn, FIN | ACK))) {
				tcp_rst(c, conn);
				return ret;
			}

			conn_event(c, conn, TAP_FIN_SENT);
		}

		return 0;
	}

	sendlen = len - already_sent;
	if (sendlen <= 0) {
		conn_flag(c, conn, STALLED);
		return 0;
	}

	conn_flag(c, conn, ~STALLED);

	send_bufs = DIV_ROUND_UP(sendlen, mss);
	last_len = sendlen - (send_bufs - 1) * mss;

	/* Likely, some new data was acked too. */
	tcp_update_seqack_wnd(c, conn, 0, NULL);

	/* Finally, queue to tap */
	plen = mss;
	seq = conn->seq_to_tap;
	for (i = 0; i < send_bufs; i++) {
		int no_csum = i && i != send_bufs - 1 && tcp4_l2_buf_used;

		if (i == send_bufs - 1)
			plen = last_len;

		tcp_data_to_tap(c, conn, plen, no_csum, seq);
		seq += plen;
	}

	conn_flag(c, conn, ACK_FROM_TAP_DUE);

	return 0;

err:
	if (errno != EAGAIN && errno != EWOULDBLOCK) {
		ret = -errno;
		tcp_rst(c, conn);
	}

	return ret;
}
