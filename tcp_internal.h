/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef TCP_INTERNAL_H
#define TCP_INTERNAL_H

#define MAX_WS				8
#define MAX_WINDOW			(1 << (16 + (MAX_WS)))
#define MSS				(USHRT_MAX - sizeof(struct tcphdr))

#define SEQ_LE(a, b)			((b) - (a) < MAX_WINDOW)
#define SEQ_LT(a, b)			((b) - (a) - 1 < MAX_WINDOW)
#define SEQ_GE(a, b)			((a) - (b) < MAX_WINDOW)
#define SEQ_GT(a, b)			((a) - (b) - 1 < MAX_WINDOW)

#define FIN		(1 << 0)
#define SYN		(1 << 1)
#define RST		(1 << 2)
#define ACK		(1 << 4)

/* Flags for internal usage */
#define DUP_ACK		(1 << 5)
#define OPT_EOL		0
#define OPT_NOP		1
#define OPT_MSS		2
#define OPT_MSS_LEN	4
#define OPT_WS		3
#define OPT_WS_LEN	3
#define OPT_SACKP	4
#define OPT_SACK	5
#define OPT_TS		8

#define CONN_V4(conn)		(!!inany_v4(&(conn)->faddr))
#define CONN_V6(conn)		(!CONN_V4(conn))

void conn_flag_do(const struct ctx *c, struct tcp_tap_conn *conn,
		  unsigned long flag);
#define conn_flag(c, conn, flag)					\
	do {								\
		flow_trace(conn, "flag at %s:%i", __func__, __LINE__);	\
		conn_flag_do(c, conn, flag);				\
	} while (0)


void conn_event_do(const struct ctx *c, struct tcp_tap_conn *conn,
		   unsigned long event);
#define conn_event(c, conn, event)					\
	do {								\
		flow_trace(conn, "event at %s:%i", __func__, __LINE__);	\
		conn_event_do(c, conn, event);				\
	} while (0)

void tcp_rst_do(struct ctx *c, struct tcp_tap_conn *conn);
#define tcp_rst(c, conn)						\
	do {								\
		flow_dbg((conn), "TCP reset at %s:%i", __func__, __LINE__); \
		tcp_rst_do(c, conn);					\
	} while (0)



size_t tcp_fill_headers4(const struct ctx *c,
			 const struct tcp_tap_conn *conn,
			 struct iphdr *iph, struct tcphdr *th,
			 size_t plen, const uint16_t *check,
			 uint32_t seq);
size_t tcp_fill_headers6(const struct ctx *c,
			 const struct tcp_tap_conn *conn,
			 struct ipv6hdr *ip6h, struct tcphdr *th,
			 size_t plen, uint32_t seq);

int tcp_update_seqack_wnd(const struct ctx *c, struct tcp_tap_conn *conn,
			  int force_seq, struct tcp_info *tinfo);
int tcp_fill_flag_header(struct ctx *c, struct tcp_tap_conn *conn, int flags,
			 struct tcphdr *th, char *opts, size_t *optlen);

#endif /* TCP_INTERNAL_H */
