// SPDX-License-Identifier: GPL-2.0-or-later
//
/* come parts copied from QEMU subprojects/libvhost-user/libvhost-user.h */

#ifndef VIRTIO_H
#define VIRTIO_H

#include <stdbool.h>
#include <linux/vhost_types.h>

#define VIRTQUEUE_MAX_SIZE 1024

#define vu_panic(vdev, ...)		\
	do {				\
		(vdev)->broken = true;	\
		err( __VA_ARGS__ );	\
	} while (0)

typedef struct VuRing {
	unsigned int num;
	struct vring_desc *desc;
	struct vring_avail *avail;
	struct vring_used *used;
	uint64_t log_guest_addr;
	uint32_t flags;
} VuRing;

typedef struct VuVirtq {
	VuRing vring;

	/* Next head to pop */
	uint16_t last_avail_idx;

	/* Last avail_idx read from VQ. */
	uint16_t shadow_avail_idx;

	uint16_t used_idx;

	/* Last used index value we have signalled on */
	uint16_t signalled_used;

	/* Last used index value we have signalled on */
	bool signalled_used_valid;

	bool notification;

	unsigned int inuse;

	int call_fd;
	int kick_fd;
	int err_fd;
	unsigned int enable;
	bool started;

	/* Guest addresses of our ring */
	struct vhost_vring_addr vra;
} VuVirtq;

typedef struct VuDevRegion {
	uint64_t gpa;
	uint64_t size;
	uint64_t qva;
	uint64_t mmap_offset;
	uint64_t mmap_addr;
} VuDevRegion;

#define VHOST_USER_MAX_QUEUES 2

/*
 * Set a reasonable maximum number of ram slots, which will be supported by
 * any architecture.
 */
#define VHOST_USER_MAX_RAM_SLOTS 32

typedef struct VuDev {
	uint32_t nregions;
	VuDevRegion regions[VHOST_USER_MAX_RAM_SLOTS];
	VuVirtq vq[VHOST_USER_MAX_QUEUES];
	uint64_t features;
	uint64_t protocol_features;
	bool broken;
	int hdrlen;
} VuDev;

typedef struct VuVirtqElement {
	unsigned int index;
	unsigned int out_num;
	unsigned int in_num;
	struct iovec *in_sg;
	struct iovec *out_sg;
} VuVirtqElement;

static inline bool has_feature(uint64_t features, unsigned int fbit)
{
	return !!(features & (1ULL << fbit));
}

static inline bool vu_has_feature(VuDev *vdev, unsigned int fbit)
{
	return has_feature(vdev->features, fbit);
}

static inline bool vu_has_protocol_feature(VuDev *vdev, unsigned int fbit)
{
	return has_feature(vdev->protocol_features, fbit);
}

bool vu_queue_empty(VuDev *dev, VuVirtq *vq);
void vu_queue_notify(VuDev *dev, VuVirtq *vq);
void *vu_queue_pop(VuDev *dev, VuVirtq *vq, size_t sz, unsigned char *buffer);
void vu_queue_detach_element(VuDev *dev, VuVirtq *vq, unsigned int index, size_t len);
void vu_queue_unpop(VuDev *dev, VuVirtq *vq, unsigned int index, size_t len);
bool vu_queue_rewind(VuDev *dev, VuVirtq *vq, unsigned int num);

void vu_queue_fill_by_index(VuDev *dev, VuVirtq *vq, unsigned int index,
			    unsigned int len, unsigned int idx);
void vu_queue_fill(VuDev *dev, VuVirtq *vq, VuVirtqElement *elem, unsigned int len,
		   unsigned int idx);
void vu_queue_flush(VuDev *dev, VuVirtq *vq, unsigned int count);
void vu_queue_push(VuDev *dev, VuVirtq *vq, VuVirtqElement *elem, unsigned int len);
#endif /* VIRTIO_H */
