// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef TCP_VU_H
#define TCP_VU_H

int tcp_vu_send_flag(struct ctx *c, struct tcp_tap_conn *conn, int flags);
int tcp_vu_data_from_sock(struct ctx *c, struct tcp_tap_conn *conn);

#endif  /*TCP_VU_H */
