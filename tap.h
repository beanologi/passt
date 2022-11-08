/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef TAP_H
#define TAP_H

/*
 * TCP frame iovec array:
 * TCP_IOV_VNET		vnet length
 * TCP_IOV_ETH		ethernet header
 * TCP_IOV_IP		IP (v4/v6) header
 * TCP_IOV_PAYLOAD	IP payload (TCP header + data)
 * TCP_IOV_NUM is the number of entries in the iovec array
 */
#define TCP_IOV_VNET	0
#define TCP_IOV_ETH	1
#define TCP_IOV_IP	2
#define TCP_IOV_PAYLOAD	3
#define TCP_IOV_NUM	4

/**
 * struct tap_hdr - L2 and tap specific headers
 * @vnet_len:	Frame length (for qemu socket transport)
 * @eh:		Ethernet header
 */
struct tap_hdr {
	uint32_t vnet_len;
	struct ethhdr eh;
} __attribute__((packed));

#define TAP_HDR_INIT(proto) { .eh.h_proto = htons_constant(proto) }

static inline size_t tap_hdr_len_(const struct ctx *c)
{
	if (c->mode == MODE_PASST)
		return sizeof(struct tap_hdr);
	else
		return sizeof(struct ethhdr);
}

/**
 * tap_iov_base() - Find start of tap frame
 * @c:		Execution context
 * @taph:	Pointer to L2 header buffer
 *
 * Returns: pointer to the start of tap frame - suitable for an
 *          iov_base to be passed to tap_send_frames())
 */
static inline void *tap_iov_base(const struct ctx *c, struct tap_hdr *taph)
{
	return (char *)(taph + 1) - tap_hdr_len_(c);
}

/**
 * tap_iov_len() - Finalize tap frame and return total length
 * @c:		Execution context
 * @taph:	Tap header to finalize
 * @plen:	L2 payload length (excludes L2 and tap specific headers)
 *
 * Returns: length of the tap frame including L2 and tap specific
 *          headers - suitable for an iov_len to be passed to
 *          tap_send_frames()
 */
static inline size_t tap_iov_len(const struct ctx *c, struct tap_hdr *taph,
				 size_t plen)
{
	if (c->mode == MODE_PASST)
		taph->vnet_len = htonl(plen + sizeof(taph->eh));
	return plen + tap_hdr_len_(c);
}

struct in_addr tap_ip4_daddr(const struct ctx *c);
void tap_udp4_send(const struct ctx *c, struct in_addr src, in_port_t sport,
		   struct in_addr dst, in_port_t dport,
		   const void *in, size_t len);
void tap_icmp4_send(const struct ctx *c, struct in_addr src, struct in_addr dst,
		    const void *in, size_t len);
const struct in6_addr *tap_ip6_daddr(const struct ctx *c,
				     const struct in6_addr *src);
void tap_udp6_send(const struct ctx *c,
		   const struct in6_addr *src, in_port_t sport,
		   const struct in6_addr *dst, in_port_t dport,
		   uint32_t flow, const void *in, size_t len);
void tap_icmp6_send(const struct ctx *c,
		    const struct in6_addr *src, const struct in6_addr *dst,
		    const void *in, size_t len);
int tap_send(const struct ctx *c, const void *data, size_t len);
size_t tap_send_frames(const struct ctx *c, const struct iovec *iov, size_t n);
size_t tap_send_iov(const struct ctx *c, struct iovec iov[][TCP_IOV_NUM],
		    size_t n);
void eth_update_mac(struct ethhdr *eh,
		    const unsigned char *eth_d, const unsigned char *eth_s);
void tap_listen_handler(struct ctx *c, uint32_t events);
void tap_handler_pasta(struct ctx *c, uint32_t events,
		       const struct timespec *now);
void tap_handler_passt(struct ctx *c, uint32_t events,
		       const struct timespec *now);
void tap_sock_reset(struct ctx *c);
void tap_sock_init(struct ctx *c);
void pool_flush_all(void);
void tap_handler_all(struct ctx *c, const struct timespec *now);

void packet_add_do(struct pool *p, size_t len, const char *start,
		   const char *func, int line);
void packet_add_all_do(struct ctx *c, ssize_t len, char *p,
		       const char *func, int line);
#define packet_add_all(p, len, start)					\
	packet_add_all_do(p, len, start, __func__, __LINE__)

#endif /* TAP_H */
