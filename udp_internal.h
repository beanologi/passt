/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef UDP_INTERNAL_H
#define UDP_INTERNAL_H

#define UDP_CONN_TIMEOUT	180 /* s, timeout for ephemeral or local bind */
#define UDP_MAX_FRAMES		32  /* max # of frames to receive at once */

extern struct sockaddr_in udp4_localname;
extern struct sockaddr_in6 udp6_localname;

size_t udp_update_hdr4(const struct ctx *c, struct iphdr *iph,
		       size_t data_len, struct sockaddr_in *s_in,
		       in_port_t dstport, const struct timespec *now);
size_t udp_update_hdr6(const struct ctx *c, struct ipv6hdr *ip6h,
		       size_t data_len, struct sockaddr_in6 *s_in6,
		       in_port_t dstport, const struct timespec *now);
#endif /* UDP_INTERNAL_H */
