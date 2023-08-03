/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef NETLINK_H
#define NETLINK_H

void nl_sock_init(const struct ctx *c, bool ns);
unsigned int nl_get_ext_if(sa_family_t af);
void nl_route_get_def(unsigned int ifi, sa_family_t af, void *gw);
void nl_route_set_def(unsigned int ifi, sa_family_t af, void *gw);
void nl_route_dup(unsigned int ifi, unsigned int ifi_ns, sa_family_t af);
void nl_addr_get(unsigned int ifi, sa_family_t af, void *addr,
		 int *prefix_len, void *addr_l);
void nl_addr_set(unsigned int ifi, sa_family_t af, void *addr, int prefix_len);
void nl_addr_dup(unsigned int ifi, unsigned int ifi_ns, sa_family_t af);
void nl_link_get_mac(int ns, unsigned int ifi, void *mac);
void nl_link_set_mac(int ns, unsigned int ifi, void *mac);
void nl_link_up(int ns, unsigned int ifi, int mtu);

#endif /* NETLINK_H */
