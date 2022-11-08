// SPDX-License-Identifier: GPL-2.0-or-later

/* some parts from subprojects/libvhost-user/libvhost-user.h */

#ifndef VHOST_USER_H
#define VHOST_USER_H

#include "virtio.h"
#include "iov.h"

#define VHOST_USER_F_PROTOCOL_FEATURES 30

#define VHOST_MEMORY_BASELINE_NREGIONS 8

enum vhost_user_protocol_feature {
	VHOST_USER_PROTOCOL_F_MQ = 0,
	VHOST_USER_PROTOCOL_F_LOG_SHMFD = 1,
	VHOST_USER_PROTOCOL_F_RARP = 2,
	VHOST_USER_PROTOCOL_F_REPLY_ACK = 3,
	VHOST_USER_PROTOCOL_F_NET_MTU = 4,
	VHOST_USER_PROTOCOL_F_BACKEND_REQ = 5,
	VHOST_USER_PROTOCOL_F_CROSS_ENDIAN = 6,
	VHOST_USER_PROTOCOL_F_CRYPTO_SESSION = 7,
	VHOST_USER_PROTOCOL_F_PAGEFAULT = 8,
	VHOST_USER_PROTOCOL_F_CONFIG = 9,
	VHOST_USER_PROTOCOL_F_SLAVE_SEND_FD = 10,
	VHOST_USER_PROTOCOL_F_HOST_NOTIFIER = 11,
	VHOST_USER_PROTOCOL_F_INFLIGHT_SHMFD = 12,
	VHOST_USER_PROTOCOL_F_INBAND_NOTIFICATIONS = 14,
	VHOST_USER_PROTOCOL_F_CONFIGURE_MEM_SLOTS = 15,

	VHOST_USER_PROTOCOL_F_MAX
};

enum vhost_user_request {
	VHOST_USER_NONE = 0,
	VHOST_USER_GET_FEATURES = 1,
	VHOST_USER_SET_FEATURES = 2,
	VHOST_USER_SET_OWNER = 3,
	VHOST_USER_RESET_OWNER = 4,
	VHOST_USER_SET_MEM_TABLE = 5,
	VHOST_USER_SET_LOG_BASE = 6,
	VHOST_USER_SET_LOG_FD = 7,
	VHOST_USER_SET_VRING_NUM = 8,
	VHOST_USER_SET_VRING_ADDR = 9,
	VHOST_USER_SET_VRING_BASE = 10,
	VHOST_USER_GET_VRING_BASE = 11,
	VHOST_USER_SET_VRING_KICK = 12,
	VHOST_USER_SET_VRING_CALL = 13,
	VHOST_USER_SET_VRING_ERR = 14,
	VHOST_USER_GET_PROTOCOL_FEATURES = 15,
	VHOST_USER_SET_PROTOCOL_FEATURES = 16,
	VHOST_USER_GET_QUEUE_NUM = 17,
	VHOST_USER_SET_VRING_ENABLE = 18,
	VHOST_USER_SEND_RARP = 19,
	VHOST_USER_NET_SET_MTU = 20,
	VHOST_USER_SET_BACKEND_REQ_FD = 21,
	VHOST_USER_IOTLB_MSG = 22,
	VHOST_USER_SET_VRING_ENDIAN = 23,
	VHOST_USER_GET_CONFIG = 24,
	VHOST_USER_SET_CONFIG = 25,
	VHOST_USER_CREATE_CRYPTO_SESSION = 26,
	VHOST_USER_CLOSE_CRYPTO_SESSION = 27,
	VHOST_USER_POSTCOPY_ADVISE  = 28,
	VHOST_USER_POSTCOPY_LISTEN  = 29,
	VHOST_USER_POSTCOPY_END     = 30,
	VHOST_USER_GET_INFLIGHT_FD = 31,
	VHOST_USER_SET_INFLIGHT_FD = 32,
	VHOST_USER_GPU_SET_SOCKET = 33,
	VHOST_USER_VRING_KICK = 35,
	VHOST_USER_GET_MAX_MEM_SLOTS = 36,
	VHOST_USER_ADD_MEM_REG = 37,
	VHOST_USER_REM_MEM_REG = 38,
	VHOST_USER_MAX
};

typedef struct {
	enum vhost_user_request request;

#define VHOST_USER_VERSION_MASK     0x3
#define VHOST_USER_REPLY_MASK       (0x1 << 2)
#define VHOST_USER_NEED_REPLY_MASK  (0x1 << 3)
	uint32_t flags;
	uint32_t size; /* the following payload size */
} __attribute__ ((__packed__)) vhost_user_header;

typedef struct VhostUserMemory_region {
	uint64_t guest_phys_addr;
	uint64_t memory_size;
	uint64_t userspace_addr;
	uint64_t mmap_offset;
} VhostUserMemory_region;

struct VhostUserMemory {
	uint32_t nregions;
	uint32_t padding;
	struct VhostUserMemory_region regions[VHOST_MEMORY_BASELINE_NREGIONS];
};

typedef union {
#define VHOST_USER_VRING_IDX_MASK   0xff
#define VHOST_USER_VRING_NOFD_MASK  (0x1 << 8)
	uint64_t u64;
	struct vhost_vring_state state;
	struct vhost_vring_addr addr;
	struct VhostUserMemory memory;
} vhost_user_payload;

typedef struct VhostUserMsg {
	vhost_user_header hdr;
	vhost_user_payload payload;

	int fds[VHOST_MEMORY_BASELINE_NREGIONS];
	int fd_num;
	uint8_t *data;
} __attribute__ ((__packed__)) VhostUserMsg;
#define VHOST_USER_HDR_SIZE sizeof(vhost_user_header)

#define VHOST_USER_RX_QUEUE 0
#define VHOST_USER_TX_QUEUE 1

static inline bool vu_queue_enabled(VuVirtq *vq)
{
	return vq->enable;
}

static inline bool vu_queue_started(const VuVirtq *vq)
{
	return vq->started;
}

size_t tap_send_frames_vu(const struct ctx *c, const struct iovec *iov,
			  size_t n);
int vu_send(const struct ctx *c, const void *data, size_t len);
void vu_print_capabilities(void);
void vu_init(struct ctx *c);
void vu_kick_cb(struct ctx *c, union epoll_ref ref);
void tap_handler_vu(struct ctx *c, uint32_t events);
#endif /* VHOST_USER_H */
