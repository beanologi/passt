// SPDX-License-Identifier: GPL-2.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * netlink.c - rtnetlink routines: interfaces, addresses, routes
 *
 * Copyright (c) 2020-2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#include <sched.h>
#include <string.h>
#include <stddef.h>
#include <errno.h>
#include <sys/types.h>
#include <limits.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "util.h"
#include "passt.h"
#include "log.h"
#include "netlink.h"

#define NLBUFSIZ	(8192 * sizeof(struct nlmsghdr)) /* See netlink(7) */

/* Socket in init, in target namespace, sequence (just needs to be monotonic) */
int nl_sock	= -1;
int nl_sock_ns	= -1;
static int nl_seq = 1;

/**
 * nl_sock_init_do() - Set up netlink sockets in init or target namespace
 * @arg:	Execution context, if running from namespace, NULL otherwise
 *
 * Return: 0
 */
static int nl_sock_init_do(void *arg)
{
	struct sockaddr_nl addr = { .nl_family = AF_NETLINK, };
	int *s = arg ? &nl_sock_ns : &nl_sock;
#ifdef NETLINK_GET_STRICT_CHK
	int y = 1;
#endif

	if (arg)
		ns_enter((struct ctx *)arg);

	*s = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (*s < 0 || bind(*s, (struct sockaddr *)&addr, sizeof(addr))) {
		*s = -1;
		return 0;
	}

#ifdef NETLINK_GET_STRICT_CHK
	if (setsockopt(*s, SOL_NETLINK, NETLINK_GET_STRICT_CHK, &y, sizeof(y)))
		debug("netlink: cannot set NETLINK_GET_STRICT_CHK on %i", *s);
#endif
	return 0;
}

/**
 * nl_sock_init() - Call nl_sock_init_do(), won't return on failure
 * @c:		Execution context
 * @ns:		Get socket in namespace, not in init
 */
void nl_sock_init(const struct ctx *c, bool ns)
{
	if (ns) {
		NS_CALL(nl_sock_init_do, c);
		if (nl_sock_ns == -1)
			goto fail;
	} else {
		nl_sock_init_do(NULL);
	}

	if (nl_sock == -1)
		goto fail;

	return;

fail:
	die("Failed to get netlink socket");
}

/**
 * nl_req() - Send netlink request and read response
 * @s:		Netlink socket
 * @buf:	Buffer for response (at least NLBUFSIZ long)
 * @req:	Request with netlink header
 * @len:	Request length
 *
 * Return: received length on success, negative error code on failure
 */
static int nl_req(int s, char *buf, const void *req, ssize_t len)
{
	char flush[NLBUFSIZ];
	int done = 0;
	ssize_t n;

	while (!done && (n = recv(s, flush, sizeof(flush), MSG_DONTWAIT)) > 0) {
		struct nlmsghdr *nh = (struct nlmsghdr *)flush;
		size_t nm = n;

		for ( ; NLMSG_OK(nh, nm); nh = NLMSG_NEXT(nh, nm)) {
			if (nh->nlmsg_type == NLMSG_DONE ||
			    nh->nlmsg_type == NLMSG_ERROR) {
				done = 1;
				break;
			}
		}
	}

	if ((send(s, req, len, 0) < len) ||
	    (len = recv(s, buf, NLBUFSIZ, 0)) < 0)
		return -errno;

	return len;
}

/**
 * nl_get_ext_if() - Get interface index supporting IP version being probed
 * @s:	Netlink socket
 * @af:	Address family (AF_INET or AF_INET6) to look for connectivity
 *      for.
 *
 * Return: interface index, 0 if not found
 */
unsigned int nl_get_ext_if(int s, sa_family_t af)
{
	struct { struct nlmsghdr nlh; struct rtmsg rtm; } req = {
		.nlh.nlmsg_type	 = RTM_GETROUTE,
		.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
		.nlh.nlmsg_len	 = NLMSG_LENGTH(sizeof(struct rtmsg)),
		.nlh.nlmsg_seq	 = nl_seq++,

		.rtm.rtm_table	 = RT_TABLE_MAIN,
		.rtm.rtm_scope	 = RT_SCOPE_UNIVERSE,
		.rtm.rtm_type	 = RTN_UNICAST,
		.rtm.rtm_family	 = af,
	};
	struct nlmsghdr *nh;
	struct rtattr *rta;
	char buf[NLBUFSIZ];
	ssize_t n;
	size_t na;

	if ((n = nl_req(s, buf, &req, sizeof(req))) < 0)
		return 0;

	nh = (struct nlmsghdr *)buf;

	for ( ; NLMSG_OK(nh, n); nh = NLMSG_NEXT(nh, n)) {
		struct rtmsg *rtm = (struct rtmsg *)NLMSG_DATA(nh);

		if (rtm->rtm_dst_len || rtm->rtm_family != af)
			continue;

		for (rta = RTM_RTA(rtm), na = RTM_PAYLOAD(nh); RTA_OK(rta, na);
		     rta = RTA_NEXT(rta, na)) {
			unsigned int ifi;

			if (rta->rta_type != RTA_OIF)
				continue;

			ifi = *(unsigned int *)RTA_DATA(rta);

			return ifi;
		}
	}

	return 0;
}

/**
 * nl_route_get_def() - Get default route for given interface and address family
 * @s:		Netlink socket
 * @ifi:	Interface index
 * @af:		Address family
 * @gw:		Default gateway to fill on NL_GET
 */
void nl_route_get_def(int s, unsigned int ifi, sa_family_t af, void *gw)
{
	struct req_t {
		struct nlmsghdr nlh;
		struct rtmsg rtm;
		struct rtattr rta;
		unsigned int ifi;
	} req = {
		.nlh.nlmsg_type	  = RTM_GETROUTE,
		.nlh.nlmsg_len	  = sizeof(req),
		.nlh.nlmsg_flags  = NLM_F_REQUEST | NLM_F_DUMP,
		.nlh.nlmsg_seq	  = nl_seq++,

		.rtm.rtm_family	  = af,
		.rtm.rtm_table	  = RT_TABLE_MAIN,
		.rtm.rtm_scope	  = RT_SCOPE_UNIVERSE,
		.rtm.rtm_type	  = RTN_UNICAST,

		.rta.rta_type	  = RTA_OIF,
		.rta.rta_len	  = RTA_LENGTH(sizeof(unsigned int)),
		.ifi		  = ifi,
	};
	struct nlmsghdr *nh;
	char buf[NLBUFSIZ];
	ssize_t n;

	if ((n = nl_req(s, buf, &req, req.nlh.nlmsg_len)) < 0)
		return;

	for (nh = (struct nlmsghdr *)buf;
	     NLMSG_OK(nh, n) && nh->nlmsg_type != NLMSG_DONE;
	     nh = NLMSG_NEXT(nh, n)) {
		struct rtmsg *rtm = (struct rtmsg *)NLMSG_DATA(nh);
		struct rtattr *rta;
		size_t na;

		if (nh->nlmsg_type != RTM_NEWROUTE)
			continue;

		if (rtm->rtm_dst_len)
			continue;

		for (rta = RTM_RTA(rtm), na = RTM_PAYLOAD(nh); RTA_OK(rta, na);
		     rta = RTA_NEXT(rta, na)) {
			if (rta->rta_type != RTA_GATEWAY)
				continue;

			memcpy(gw, RTA_DATA(rta), RTA_PAYLOAD(rta));
			return;
		}
	}
}

/**
 * nl_route_set_def() - Set default route for given interface and address family
 * @s:		Netlink socket
 * @ifi:	Interface index in target namespace
 * @af:		Address family
 * @gw:		Default gateway to set
 */
void nl_route_set_def(int s, unsigned int ifi, sa_family_t af, void *gw)
{
	struct req_t {
		struct nlmsghdr nlh;
		struct rtmsg rtm;
		struct rtattr rta;
		unsigned int ifi;
		union {
			struct {
				struct rtattr rta_dst;
				struct in6_addr d;
				struct rtattr rta_gw;
				struct in6_addr a;
			} r6;
			struct {
				struct rtattr rta_dst;
				struct in_addr d;
				struct rtattr rta_gw;
				struct in_addr a;
			} r4;
		} set;
	} req = {
		.nlh.nlmsg_type	  = RTM_NEWROUTE,
		.nlh.nlmsg_flags  = NLM_F_REQUEST | NLM_F_ACK |
				    NLM_F_CREATE | NLM_F_EXCL,
		.nlh.nlmsg_seq	  = nl_seq++,

		.rtm.rtm_family	  = af,
		.rtm.rtm_table	  = RT_TABLE_MAIN,
		.rtm.rtm_scope	  = RT_SCOPE_UNIVERSE,
		.rtm.rtm_type	  = RTN_UNICAST,
		.rtm.rtm_protocol = RTPROT_BOOT,

		.rta.rta_type	  = RTA_OIF,
		.rta.rta_len	  = RTA_LENGTH(sizeof(unsigned int)),
		.ifi		  = ifi,
	};
	char buf[NLBUFSIZ];

	if (af == AF_INET6) {
		size_t rta_len = RTA_LENGTH(sizeof(req.set.r6.d));

		req.nlh.nlmsg_len = offsetof(struct req_t, set.r6)
			+ sizeof(req.set.r6);

		req.set.r6.rta_dst.rta_type = RTA_DST;
		req.set.r6.rta_dst.rta_len = rta_len;

		memcpy(&req.set.r6.a, gw, sizeof(req.set.r6.a));
		req.set.r6.rta_gw.rta_type = RTA_GATEWAY;
		req.set.r6.rta_gw.rta_len = rta_len;
	} else {
		size_t rta_len = RTA_LENGTH(sizeof(req.set.r4.d));

		req.nlh.nlmsg_len = offsetof(struct req_t, set.r4)
			+ sizeof(req.set.r4);

		req.set.r4.rta_dst.rta_type = RTA_DST;
		req.set.r4.rta_dst.rta_len = rta_len;

		memcpy(&req.set.r4.a, gw, sizeof(req.set.r4.a));
		req.set.r4.rta_gw.rta_type = RTA_GATEWAY;
		req.set.r4.rta_gw.rta_len = rta_len;
	}

	nl_req(s, buf, &req, req.nlh.nlmsg_len);
}

/**
 * nl_route_dup() - Copy routes for given interface and address family
 * @s_src:	Netlink socket in source namespace
 * @ifi_src:	Source interface index
 * @s_dst:	Netlink socket in destination namespace
 * @ifi_dst:	Interface index in destination namespace
 * @af:		Address family
 */
void nl_route_dup(int s_src, unsigned int ifi_src,
		  int s_dst, unsigned int ifi_dst, sa_family_t af)
{
	struct req_t {
		struct nlmsghdr nlh;
		struct rtmsg rtm;
		struct rtattr rta;
		unsigned int ifi;
	} req = {
		.nlh.nlmsg_type	  = RTM_GETROUTE,
		.nlh.nlmsg_len	  = sizeof(req),
		.nlh.nlmsg_flags  = NLM_F_REQUEST | NLM_F_DUMP,
		.nlh.nlmsg_seq	  = nl_seq++,

		.rtm.rtm_family	  = af,
		.rtm.rtm_table	  = RT_TABLE_MAIN,
		.rtm.rtm_scope	  = RT_SCOPE_UNIVERSE,
		.rtm.rtm_type	  = RTN_UNICAST,

		.rta.rta_type	  = RTA_OIF,
		.rta.rta_len	  = RTA_LENGTH(sizeof(unsigned int)),
		.ifi		  = ifi_src,
	};
	unsigned dup_routes = 0;
	ssize_t n, nlmsgs_size;
	struct nlmsghdr *nh;
	char buf[NLBUFSIZ];
	unsigned i;

	if ((nlmsgs_size = nl_req(s_src, buf, &req, req.nlh.nlmsg_len)) < 0)
		return;

	for (nh = (struct nlmsghdr *)buf, n = nlmsgs_size;
	     NLMSG_OK(nh, n) && nh->nlmsg_type != NLMSG_DONE;
	     nh = NLMSG_NEXT(nh, n)) {
		struct rtmsg *rtm = (struct rtmsg *)NLMSG_DATA(nh);
		struct rtattr *rta;
		size_t na;

		if (nh->nlmsg_type != RTM_NEWROUTE)
			continue;

		nh->nlmsg_pid = 0;
		nh->nlmsg_flags &= ~NLM_F_DUMP_FILTERED;
		nh->nlmsg_flags |= NLM_F_REQUEST | NLM_F_ACK |
			NLM_F_CREATE;
		dup_routes++;

		for (rta = RTM_RTA(rtm), na = RTM_PAYLOAD(nh); RTA_OK(rta, na);
		     rta = RTA_NEXT(rta, na)) {
			if (rta->rta_type == RTA_OIF)
				*(unsigned int *)RTA_DATA(rta) = ifi_dst;
		}
	}

	/* Routes might have dependencies between each other, and the kernel
	 * processes RTM_NEWROUTE messages sequentially. For n routes, we might
	 * need to send the requests up to n times to get all of them inserted.
	 * Routes that have been already inserted will return -EEXIST, but we
	 * can safely ignore that and repeat the requests. This avoids the need
	 * to calculate dependencies: let the kernel do that.
	 */
	for (i = 0; i < dup_routes; i++) {
		for (nh = (struct nlmsghdr *)buf, n = nlmsgs_size;
		     NLMSG_OK(nh, n) && nh->nlmsg_type != NLMSG_DONE;
		     nh = NLMSG_NEXT(nh, n)) {
			char resp[NLBUFSIZ];

			if (nh->nlmsg_type != RTM_NEWROUTE)
				continue;

			nh->nlmsg_seq = nl_seq++;
			nl_req(s_dst, resp, nh, nh->nlmsg_len);
		}
	}
}

/**
 * nl_addr_get() - Get IP address for given interface and address family
 * @s:		Netlink socket
 * @ifi:	Interface index in outer network namespace
 * @af:		Address family
 * @addr:	Global address to fill
 * @prefix_len:	Mask or prefix length, to fill (for IPv4)
 * @addr_l:	Link-scoped address to fill (for IPv6)
 */
void nl_addr_get(int s, unsigned int ifi, sa_family_t af,
		 void *addr, int *prefix_len, void *addr_l)
{
	struct req_t {
		struct nlmsghdr nlh;
		struct ifaddrmsg ifa;
	} req = {
		.nlh.nlmsg_type    = RTM_GETADDR,
		.nlh.nlmsg_flags   = NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP,
		.nlh.nlmsg_len     = sizeof(req),
		.nlh.nlmsg_seq     = nl_seq++,

		.ifa.ifa_family    = af,
		.ifa.ifa_index     = ifi,
	};
	struct nlmsghdr *nh;
	char buf[NLBUFSIZ];
	ssize_t n;

	if ((n = nl_req(s, buf, &req, req.nlh.nlmsg_len)) < 0)
		return;

	for (nh = (struct nlmsghdr *)buf;
	     NLMSG_OK(nh, n) && nh->nlmsg_type != NLMSG_DONE;
	     nh = NLMSG_NEXT(nh, n)) {
		struct ifaddrmsg *ifa = (struct ifaddrmsg *)NLMSG_DATA(nh);
		struct rtattr *rta;
		size_t na;

		if (nh->nlmsg_type != RTM_NEWADDR)
			continue;

		if (ifa->ifa_index != ifi)
			continue;

		for (rta = IFA_RTA(ifa), na = RTM_PAYLOAD(nh); RTA_OK(rta, na);
		     rta = RTA_NEXT(rta, na)) {
			if (rta->rta_type != IFA_ADDRESS)
				continue;

			if (af == AF_INET) {
				memcpy(addr, RTA_DATA(rta), RTA_PAYLOAD(rta));
				*prefix_len = ifa->ifa_prefixlen;
			} else if (af == AF_INET6 && addr &&
				   ifa->ifa_scope == RT_SCOPE_UNIVERSE) {
				memcpy(addr, RTA_DATA(rta), RTA_PAYLOAD(rta));
			}

			if (addr_l &&
			    af == AF_INET6 && ifa->ifa_scope == RT_SCOPE_LINK)
				memcpy(addr_l, RTA_DATA(rta), RTA_PAYLOAD(rta));
		}
	}
}

/**
 * nl_add_set() - Set IP addresses for given interface and address family
 * @s:		Netlink socket
 * @ifi:	Interface index
 * @af:		Address family
 * @addr:	Global address to set
 * @prefix_len:	Mask or prefix length to set
 */
void nl_addr_set(int s, unsigned int ifi, sa_family_t af,
		 void *addr, int prefix_len)
{
	struct req_t {
		struct nlmsghdr nlh;
		struct ifaddrmsg ifa;
		union {
			struct {
				struct rtattr rta_l;
				struct in_addr l;
				struct rtattr rta_a;
				struct in_addr a;
			} a4;
			struct {
				struct rtattr rta_l;
				struct in6_addr l;
				struct rtattr rta_a;
				struct in6_addr a;
			} a6;
		} set;
	} req = {
		.nlh.nlmsg_type    = RTM_NEWADDR,
		.nlh.nlmsg_flags   = NLM_F_REQUEST | NLM_F_ACK |
				     NLM_F_CREATE | NLM_F_EXCL,
		.nlh.nlmsg_len     = NLMSG_LENGTH(sizeof(struct ifaddrmsg)),
		.nlh.nlmsg_seq     = nl_seq++,

		.ifa.ifa_family    = af,
		.ifa.ifa_index     = ifi,
		.ifa.ifa_prefixlen = prefix_len,
		.ifa.ifa_scope	   = RT_SCOPE_UNIVERSE,
	};
	char buf[NLBUFSIZ];

	if (af == AF_INET6) {
		size_t rta_len = RTA_LENGTH(sizeof(req.set.a6.l));

		/* By default, strictly speaking, it's duplicated */
		req.ifa.ifa_flags = IFA_F_NODAD;

		req.nlh.nlmsg_len = offsetof(struct req_t, set.a6)
			+ sizeof(req.set.a6);

		memcpy(&req.set.a6.l, addr, sizeof(req.set.a6.l));
		req.set.a6.rta_l.rta_len = rta_len;
		req.set.a4.rta_l.rta_type = IFA_LOCAL;
		memcpy(&req.set.a6.a, addr, sizeof(req.set.a6.a));
		req.set.a6.rta_a.rta_len = rta_len;
		req.set.a6.rta_a.rta_type = IFA_ADDRESS;
	} else {
		size_t rta_len = RTA_LENGTH(sizeof(req.set.a4.l));

		req.nlh.nlmsg_len = offsetof(struct req_t, set.a4)
			+ sizeof(req.set.a4);

		memcpy(&req.set.a4.l, addr, sizeof(req.set.a4.l));
		req.set.a4.rta_l.rta_len = rta_len;
		req.set.a4.rta_l.rta_type = IFA_LOCAL;
		req.set.a4.rta_a.rta_len = rta_len;
		req.set.a4.rta_a.rta_type = IFA_ADDRESS;
	}

	nl_req(s, buf, &req, req.nlh.nlmsg_len);
}

/**
 * nl_addr_dup() - Copy IP addresses for given interface and address family
 * @s_src:	Netlink socket in source network namespace
 * @ifi_src:	Interface index in source network namespace
 * @s_dst:	Netlink socket in destination network namespace
 * @ifi_dst:	Interface index in destination namespace
 * @af:		Address family
 */
void nl_addr_dup(int s_src, unsigned int ifi_src,
		 int s_dst, unsigned int ifi_dst, sa_family_t af)
{
	struct req_t {
		struct nlmsghdr nlh;
		struct ifaddrmsg ifa;
	} req = {
		.nlh.nlmsg_type    = RTM_GETADDR,
		.nlh.nlmsg_flags   = NLM_F_REQUEST | NLM_F_DUMP,
		.nlh.nlmsg_len     = sizeof(req),
		.nlh.nlmsg_seq     = nl_seq++,

		.ifa.ifa_family    = af,
		.ifa.ifa_index     = ifi_src,
		.ifa.ifa_prefixlen = 0,
	};
	char buf[NLBUFSIZ];
	struct nlmsghdr *nh;
	ssize_t n;

	if ((n = nl_req(s_src, buf, &req, sizeof(req))) < 0)
		return;

	for (nh = (struct nlmsghdr *)buf;
	     NLMSG_OK(nh, n) && nh->nlmsg_type != NLMSG_DONE;
	     nh = NLMSG_NEXT(nh, n)) {
		struct ifaddrmsg *ifa;
		char resp[NLBUFSIZ];
		struct rtattr *rta;
		size_t na;

		if (nh->nlmsg_type != RTM_NEWADDR)
			continue;

		nh->nlmsg_seq = nl_seq++;
		nh->nlmsg_pid = 0;
		nh->nlmsg_flags &= ~NLM_F_DUMP_FILTERED;
		nh->nlmsg_flags |= NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE;

		ifa = (struct ifaddrmsg *)NLMSG_DATA(nh);

		if (ifa->ifa_scope == RT_SCOPE_LINK ||
		    ifa->ifa_index != ifi_src)
			continue;

		ifa->ifa_index = ifi_dst;

		for (rta = IFA_RTA(ifa), na = RTM_PAYLOAD(nh); RTA_OK(rta, na);
		     rta = RTA_NEXT(rta, na)) {
			if (rta->rta_type == IFA_LABEL)
				rta->rta_type = IFA_UNSPEC;
		}

		nl_req(s_dst, resp, nh, nh->nlmsg_len);
	}
}

/**
 * nl_link_get_mac() - Get link MAC address
 * @s:		Netlink socket
 * @ifi:	Interface index
 * @mac:	Fill with current MAC address
 */
void nl_link_get_mac(int s, unsigned int ifi, void *mac)
{
	struct req_t {
		struct nlmsghdr nlh;
		struct ifinfomsg ifm;
	} req = {
		.nlh.nlmsg_type	  = RTM_GETLINK,
		.nlh.nlmsg_len	  = sizeof(req),
		.nlh.nlmsg_flags  = NLM_F_REQUEST | NLM_F_ACK,
		.nlh.nlmsg_seq	  = nl_seq++,
		.ifm.ifi_family	  = AF_UNSPEC,
		.ifm.ifi_index	  = ifi,
	};
	struct nlmsghdr *nh;
	char buf[NLBUFSIZ];
	ssize_t n;

	n = nl_req(s, buf, &req, sizeof(req));
	if (n < 0)
		return;

	for (nh = (struct nlmsghdr *)buf;
	     NLMSG_OK(nh, n) && nh->nlmsg_type != NLMSG_DONE;
	     nh = NLMSG_NEXT(nh, n)) {
		struct ifinfomsg *ifm = (struct ifinfomsg *)NLMSG_DATA(nh);
		struct rtattr *rta;
		size_t na;

		if (nh->nlmsg_type != RTM_NEWLINK)
			continue;

		for (rta = IFLA_RTA(ifm), na = RTM_PAYLOAD(nh);
		     RTA_OK(rta, na);
		     rta = RTA_NEXT(rta, na)) {
			if (rta->rta_type != IFLA_ADDRESS)
				continue;

			memcpy(mac, RTA_DATA(rta), ETH_ALEN);
			break;
		}
	}
}

/**
 * nl_link_set_mac() - Set link MAC address
 * @s:		Netlink socket
 * @ns:		Use netlink socket in namespace
 * @ifi:	Interface index
 * @mac:	MAC address to set
 */
void nl_link_set_mac(int s, unsigned int ifi, void *mac)
{
	struct req_t {
		struct nlmsghdr nlh;
		struct ifinfomsg ifm;
		struct rtattr rta;
		unsigned char mac[ETH_ALEN];
	} req = {
		.nlh.nlmsg_type	  = RTM_NEWLINK,
		.nlh.nlmsg_len	  = sizeof(req),
		.nlh.nlmsg_flags  = NLM_F_REQUEST | NLM_F_ACK,
		.nlh.nlmsg_seq	  = nl_seq++,
		.ifm.ifi_family	  = AF_UNSPEC,
		.ifm.ifi_index	  = ifi,
		.rta.rta_type	  = IFLA_ADDRESS,
		.rta.rta_len	  = RTA_LENGTH(ETH_ALEN),
	};
	char buf[NLBUFSIZ];

	memcpy(req.mac, mac, ETH_ALEN);

	nl_req(s, buf, &req, sizeof(req));
}

/**
 * nl_link_up() - Bring link up
 * @s:		Netlink socket
 * @ifi:	Interface index
 * @mtu:	If non-zero, set interface MTU
 */
void nl_link_up(int s, unsigned int ifi, int mtu)
{
	struct req_t {
		struct nlmsghdr nlh;
		struct ifinfomsg ifm;
		struct rtattr rta;
		unsigned int mtu;
	} req = {
		.nlh.nlmsg_type   = RTM_NEWLINK,
		.nlh.nlmsg_len    = sizeof(req),
		.nlh.nlmsg_flags  = NLM_F_REQUEST | NLM_F_ACK,
		.nlh.nlmsg_seq	  = nl_seq++,
		.ifm.ifi_family	  = AF_UNSPEC,
		.ifm.ifi_index	  = ifi,
		.ifm.ifi_flags	  = IFF_UP,
		.ifm.ifi_change	  = IFF_UP,
		.rta.rta_type	  = IFLA_MTU,
		.rta.rta_len	  = RTA_LENGTH(sizeof(unsigned int)),
		.mtu		  = mtu,
	};
	char buf[NLBUFSIZ];

	if (!mtu)
		/* Shorten request to drop MTU attribute */
		req.nlh.nlmsg_len = offsetof(struct req_t, rta);

	nl_req(s, buf, &req, req.nlh.nlmsg_len);
}
