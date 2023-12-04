/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef TCP_BUF_H
#define TCP_BUF_H

void tcp_buf_sock4_iov_init(const struct ctx *c);
void tcp_buf_sock6_iov_init(const struct ctx *c);
void tcp_buf_l2_flags_flush(const struct ctx *c);
void tcp_buf_l2_data_flush(const struct ctx *c);
uint16_t tcp_buf_conn_tap_mss(const struct tcp_tap_conn *conn);
int tcp_buf_data_from_sock(struct ctx *c, struct tcp_tap_conn *conn);
int tcp_buf_send_flag(struct ctx *c, struct tcp_tap_conn *conn, int flags);

#endif  /*TCP_BUF_H */
