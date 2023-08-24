// SPDX-License-Identifier: GPL-2.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * packet.c - Packet abstraction: add packets to pool, flush, get packet data
 *
 * Copyright (c) 2020-2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#include <netinet/ip6.h>

#include "packet.h"
#include "util.h"
#include "log.h"

static int packet_check_range(const struct pool *p, size_t offset, size_t len,
			      const char *start, const char *func, int line)
{
	ASSERT(p->buf);

	if (p->buf_size == 0)
		return vu_packet_check_range((void *)p->buf, offset, len, start,
					     func, line);

	if (start < p->buf) {
		if (func) {
			trace("add packet start %p before buffer start %p, "
			      "%s:%i", (void *)start, (void *)p->buf, func, line);
		}
		return -1;
	}

	if (start + len + offset > p->buf + p->buf_size) {
		if (func) {
			trace("packet offset plus length %lu from size %lu, "
			      "%s:%i", start - p->buf + len + offset,
			      p->buf_size, func, line);
		}
		return -1;
	}

#if UINTPTR_MAX == UINT64_MAX
	if ((uintptr_t)start - (uintptr_t)p->buf > UINT32_MAX) {
		trace("add packet start %p, buffer start %p, %s:%i",
		      (void *)start, (void *)p->buf, func, line);
		return -1;
	}
#endif

	return 0;
}
/**
 * packet_add_do() - Add data as packet descriptor to given pool
 * @p:		Existing pool
 * @len:	Length of new descriptor
 * @start:	Start of data
 * @func:	For tracing: name of calling function, NULL means no trace()
 * @line:	For tracing: caller line of function call
 */
void packet_add_do(struct pool *p, size_t len, const char *start,
		   const char *func, int line)
{
	size_t idx = p->count;

	if (idx >= p->size) {
		trace("add packet index %zu to pool with size %zu, %s:%i",
		      idx, p->size, func, line);
		return;
	}

	if (packet_check_range(p, 0, len, start, func, line))
		return;

	if (len > UINT16_MAX) {
		trace("add packet length %zu, %s:%i", len, func, line);
		return;
	}

	p->pkt[idx].iov_base = (void *)start;
	p->pkt[idx].iov_len = len;

	p->count++;
}

/**
 * packet_get_do() - Get data range from packet descriptor from given pool
 * @p:		Packet pool
 * @idx:	Index of packet descriptor in pool
 * @offset:	Offset of data range in packet descriptor
 * @len:	Length of desired data range
 * @left:	Length of available data after range, set on return, can be NULL
 * @func:	For tracing: name of calling function, NULL means no trace()
 * @line:	For tracing: caller line of function call
 *
 * Return: pointer to start of data range, NULL on invalid range or descriptor
 */
void *packet_get_do(const struct pool *p, size_t idx, size_t offset,
		    size_t len, size_t *left, const char *func, int line)
{
	if (idx >= p->size || idx >= p->count) {
		if (func) {
			trace("packet %zu from pool size: %zu, count: %zu, "
			      "%s:%i", idx, p->size, p->count, func, line);
		}
		return NULL;
	}

	if (len > UINT16_MAX || len + offset > UINT32_MAX) {
		if (func) {
			trace("packet data length %zu, offset %zu, %s:%i",
			      len, offset, func, line);
		}
		return NULL;
	}

	if (len + offset > p->pkt[idx].iov_len) {
		if (func) {
			trace("data length %zu, offset %zu from length %zu, "
			      "%s:%i", len, offset, p->pkt[idx].iov_len,
			      func, line);
		}
		return NULL;
	}

	if (packet_check_range(p, offset, len, p->pkt[idx].iov_base,
			       func, line))
		return NULL;

	if (left)
		*left = p->pkt[idx].iov_len - offset - len;

	return (char *)p->pkt[idx].iov_base + offset;
}

/**
 * pool_flush() - Flush a packet pool
 * @p:		Pointer to packet pool
 */
void pool_flush(struct pool *p)
{
	p->count = 0;
}
