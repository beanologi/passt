// SPDX-License-Identifier: GPL-2.0-or-later

/* some parts copied from QEMU subprojects/libvhost-user/libvhost-user.c */

#include <stddef.h>
#include <endian.h>
#include <string.h>
#include <errno.h>
#include <sys/eventfd.h>
#include <sys/socket.h>

#include "util.h"
#include "virtio.h"

#define VIRTQUEUE_MAX_SIZE 1024

/* Translate guest physical address to our virtual address.  */
static void *vu_gpa_to_va(VuDev *dev, uint64_t *plen, uint64_t guest_addr)
{
	unsigned int i;

	if (*plen == 0) {
		return NULL;
	}

	/* Find matching memory region.  */
	for (i = 0; i < dev->nregions; i++) {
		VuDevRegion *r = &dev->regions[i];

		if ((guest_addr >= r->gpa) && (guest_addr < (r->gpa + r->size))) {
			if ((guest_addr + *plen) > (r->gpa + r->size)) {
				*plen = r->gpa + r->size - guest_addr;
			}
			return (void *)(guest_addr - (uintptr_t)r->gpa +
					(uintptr_t)r->mmap_addr + r->mmap_offset);
		}
	}

	return NULL;
}

static inline uint16_t vring_avail_flags(VuVirtq *vq)
{
	return le16toh(vq->vring.avail->flags);
}

static inline uint16_t vring_avail_idx(VuVirtq *vq)
{
	vq->shadow_avail_idx = le16toh(vq->vring.avail->idx);

	return vq->shadow_avail_idx;
}

static inline uint16_t vring_avail_ring(VuVirtq *vq, int i)
{
	return le16toh(vq->vring.avail->ring[i]);
}

static inline uint16_t vring_get_used_event(VuVirtq *vq)
{
	return vring_avail_ring(vq, vq->vring.num);
}

static bool virtqueue_get_head(VuDev *dev, VuVirtq *vq,
		   unsigned int idx, unsigned int *head)
{
	/* Grab the next descriptor number they're advertising, and increment
	 * the index we've seen. */
	*head = vring_avail_ring(vq, idx % vq->vring.num);

	/* If their number is silly, that's a fatal mistake. */
	if (*head >= vq->vring.num) {
		vu_panic(dev, "Guest says index %u is available", *head);
		return false;
	}

	return true;
}

static int
virtqueue_read_indirect_desc(VuDev *dev, struct vring_desc *desc,
			     uint64_t addr, size_t len)
{
	struct vring_desc *ori_desc;
	uint64_t read_len;

	if (len > (VIRTQUEUE_MAX_SIZE * sizeof(struct vring_desc))) {
		return -1;
	}

	if (len == 0) {
		return -1;
	}

	while (len) {
		read_len = len;
		ori_desc = vu_gpa_to_va(dev, &read_len, addr);
		if (!ori_desc) {
			return -1;
		}

		memcpy(desc, ori_desc, read_len);
		len -= read_len;
		addr += read_len;
		desc += read_len;
	}

	return 0;
}

enum {
	VIRTQUEUE_READ_DESC_ERROR = -1,
	VIRTQUEUE_READ_DESC_DONE = 0,   /* end of chain */
	VIRTQUEUE_READ_DESC_MORE = 1,   /* more buffers in chain */
};

static int
virtqueue_read_next_desc(VuDev *dev, struct vring_desc *desc,
			 int i, unsigned int max, unsigned int *next)
{
	/* If this descriptor says it doesn't chain, we're done. */
	if (!(le16toh(desc[i].flags) & VRING_DESC_F_NEXT)) {
		return VIRTQUEUE_READ_DESC_DONE;
	}

	/* Check they're not leading us off end of descriptors. */
	*next = le16toh(desc[i].next);
	/* Make sure compiler knows to grab that: we don't want it changing! */
	smp_wmb();

	if (*next >= max) {
		vu_panic(dev, "Desc next is %u", *next);
		return VIRTQUEUE_READ_DESC_ERROR;
	}

	return VIRTQUEUE_READ_DESC_MORE;
}

bool vu_queue_empty(VuDev *dev, VuVirtq *vq)
{
	if (dev->broken ||
		!vq->vring.avail) {
		return true;
	}

	if (vq->shadow_avail_idx != vq->last_avail_idx) {
		return false;
	}

	return vring_avail_idx(vq) == vq->last_avail_idx;
}

static bool vring_notify(VuDev *dev, VuVirtq *vq)
{
	uint16_t old, new;
	bool v;

	/* We need to expose used array entries before checking used event. */
	smp_mb();

	/* Always notify when queue is empty (when feature acknowledge) */
	if (vu_has_feature(dev, VIRTIO_F_NOTIFY_ON_EMPTY) &&
		!vq->inuse && vu_queue_empty(dev, vq)) {
		return true;
	}

	if (!vu_has_feature(dev, VIRTIO_RING_F_EVENT_IDX)) {
		return !(vring_avail_flags(vq) & VRING_AVAIL_F_NO_INTERRUPT);
	}

	v = vq->signalled_used_valid;
	vq->signalled_used_valid = true;
	old = vq->signalled_used;
	new = vq->signalled_used = vq->used_idx;
	return !v || vring_need_event(vring_get_used_event(vq), new, old);
}

void vu_queue_notify(VuDev *dev, VuVirtq *vq)
{
	if (dev->broken || !vq->vring.avail) {
		return;
	}

	if (!vring_notify(dev, vq)) {
		debug("skipped notify...");
		return;
	}

	if (eventfd_write(vq->call_fd, 1) < 0) {
		vu_panic(dev, "Error writing eventfd: %s", strerror(errno));
	}
}

static inline void vring_set_avail_event(VuVirtq *vq, uint16_t val)
{
	uint16_t val_le = htole16(val);

	if (!vq->notification) {
		return;
	}

	memcpy(&vq->vring.used->ring[vq->vring.num], &val_le, sizeof(uint16_t));
}

static bool virtqueue_map_desc(VuDev *dev,
			       unsigned int *p_num_sg, struct iovec *iov,
			       unsigned int max_num_sg,
			       uint64_t pa, size_t sz)
{
	unsigned num_sg = *p_num_sg;

	ASSERT(num_sg <= max_num_sg);

	if (!sz) {
		vu_panic(dev, "virtio: zero sized buffers are not allowed");
		return false;
	}

	while (sz) {
		uint64_t len = sz;

		if (num_sg == max_num_sg) {
			vu_panic(dev, "virtio: too many descriptors in indirect table");
			return false;
		}

		iov[num_sg].iov_base = vu_gpa_to_va(dev, &len, pa);
		if (iov[num_sg].iov_base == NULL) {
			vu_panic(dev, "virtio: invalid address for buffers");
			return false;
		}
		iov[num_sg].iov_len = len;
		num_sg++;
		sz -= len;
		pa += len;
	}

	*p_num_sg = num_sg;
	return true;
}

static void * virtqueue_alloc_element(size_t sz, unsigned out_num, unsigned in_num, unsigned char *buffer)
{
	VuVirtqElement *elem;
	size_t in_sg_ofs = ALIGN_UP(sz, __alignof__(elem->in_sg[0]));
	size_t out_sg_ofs = in_sg_ofs + in_num * sizeof(elem->in_sg[0]);
	size_t out_sg_end = out_sg_ofs + out_num * sizeof(elem->out_sg[0]);

	if (out_sg_end > 65536)
		return NULL;

	elem = (void *)buffer;
	elem->out_num = out_num;
	elem->in_num = in_num;
	elem->in_sg = (struct iovec *)((uintptr_t)elem + in_sg_ofs);
	elem->out_sg = (struct iovec *)((uintptr_t)elem + out_sg_ofs);
	return elem;
}

static void *
vu_queue_map_desc(VuDev *dev, VuVirtq *vq, unsigned int idx, size_t sz, unsigned char *buffer)
{
	struct vring_desc *desc = vq->vring.desc;
	uint64_t desc_addr, read_len;
	unsigned int desc_len;
	unsigned int max = vq->vring.num;
	unsigned int i = idx;
	VuVirtqElement *elem;
	unsigned int out_num = 0, in_num = 0;
	struct iovec iov[VIRTQUEUE_MAX_SIZE];
	struct vring_desc desc_buf[VIRTQUEUE_MAX_SIZE];
	int rc;

	if (le16toh(desc[i].flags) & VRING_DESC_F_INDIRECT) {
		if (le32toh(desc[i].len) % sizeof(struct vring_desc)) {
			vu_panic(dev, "Invalid size for indirect buffer table");
			return NULL;
		}

		/* loop over the indirect descriptor table */
		desc_addr = le64toh(desc[i].addr);
		desc_len = le32toh(desc[i].len);
		max = desc_len / sizeof(struct vring_desc);
		read_len = desc_len;
		desc = vu_gpa_to_va(dev, &read_len, desc_addr);
		if (desc && read_len != desc_len) {
			/* Failed to use zero copy */
			desc = NULL;
			if (!virtqueue_read_indirect_desc(dev, desc_buf, desc_addr, desc_len)) {
				desc = desc_buf;
			}
		}
		if (!desc) {
			vu_panic(dev, "Invalid indirect buffer table");
			return NULL;
		}
		i = 0;
	}

	/* Collect all the descriptors */
	do {
		if (le16toh(desc[i].flags) & VRING_DESC_F_WRITE) {
			if (!virtqueue_map_desc(dev, &in_num, iov + out_num,
						VIRTQUEUE_MAX_SIZE - out_num,
						le64toh(desc[i].addr),
						le32toh(desc[i].len))) {
				return NULL;
			}
		} else {
			if (in_num) {
				vu_panic(dev, "Incorrect order for descriptors");
				return NULL;
			}
			if (!virtqueue_map_desc(dev, &out_num, iov,
						VIRTQUEUE_MAX_SIZE,
						le64toh(desc[i].addr),
						le32toh(desc[i].len))) {
				return NULL;
			}
		}

		/* If we've got too many, that implies a descriptor loop. */
		if ((in_num + out_num) > max) {
			vu_panic(dev, "Looped descriptor");
			return NULL;
		}
		rc = virtqueue_read_next_desc(dev, desc, i, max, &i);
	} while (rc == VIRTQUEUE_READ_DESC_MORE);

	if (rc == VIRTQUEUE_READ_DESC_ERROR) {
		vu_panic(dev, "read descriptor error");
		return NULL;
	}

	/* Now copy what we have collected and mapped */
	elem = virtqueue_alloc_element(sz, out_num, in_num, buffer);
	if (!elem) {
		return NULL;
	}
	elem->index = idx;
	for (i = 0; i < out_num; i++) {
		elem->out_sg[i] = iov[i];
	}
	for (i = 0; i < in_num; i++) {
		elem->in_sg[i] = iov[out_num + i];
	}

	return elem;
}

void *vu_queue_pop(VuDev *dev, VuVirtq *vq, size_t sz, unsigned char *buffer)
{
	unsigned int head;
	VuVirtqElement *elem;

	if (dev->broken || !vq->vring.avail) {
	return NULL;
	}

	if (vu_queue_empty(dev, vq)) {
	return NULL;
	}
	/*
	 * Needed after virtio_queue_empty(), see comment in
	 * virtqueue_num_heads().
	 */
	smp_rmb();

	if (vq->inuse >= vq->vring.num) {
	vu_panic(dev, "Virtqueue size exceeded");
	return NULL;
	}

	if (!virtqueue_get_head(dev, vq, vq->last_avail_idx++, &head)) {
	return NULL;
	}

	if (vu_has_feature(dev, VIRTIO_RING_F_EVENT_IDX)) {
		vring_set_avail_event(vq, vq->last_avail_idx);
	}

	elem = vu_queue_map_desc(dev, vq, head, sz, buffer);

	if (!elem) {
	return NULL;
	}

	vq->inuse++;

	return elem;
}

void vu_queue_detach_element(VuDev *dev, VuVirtq *vq,
			     unsigned int index, size_t len)
{
	(void)dev;
	(void)index;
	(void)len;

	vq->inuse--;
	/* unmap, when DMA support is added */
}

void vu_queue_unpop(VuDev *dev, VuVirtq *vq, unsigned int index, size_t len)
{
	vq->last_avail_idx--;
	vu_queue_detach_element(dev, vq, index, len);
}

bool vu_queue_rewind(VuDev *dev, VuVirtq *vq, unsigned int num)
{
	(void)dev;
	if (num > vq->inuse) {
		return false;
	}
	vq->last_avail_idx -= num;
	vq->inuse -= num;
	return true;
}

static inline void vring_used_write(VuVirtq *vq,
				    struct vring_used_elem *uelem, int i)
{
	struct vring_used *used = vq->vring.used;

	used->ring[i] = *uelem;
}

void vu_queue_fill_by_index(VuDev *dev, VuVirtq *vq, unsigned int index,
			  unsigned int len, unsigned int idx)
{
	struct vring_used_elem uelem;

	if (dev->broken || !vq->vring.avail)
		return;

	idx = (idx + vq->used_idx) % vq->vring.num;

	uelem.id = htole32(index);
	uelem.len = htole32(len);
	vring_used_write(vq, &uelem, idx);
}

void vu_queue_fill(VuDev *dev, VuVirtq *vq, VuVirtqElement *elem,
		   unsigned int len, unsigned int idx)
{
	vu_queue_fill_by_index(dev, vq, elem->index, len, idx);
}

static inline void vring_used_idx_set(VuVirtq *vq, uint16_t val)
{
	vq->vring.used->idx = htole16(val);

	vq->used_idx = val;
}

void vu_queue_flush(VuDev *dev, VuVirtq *vq, unsigned int count)
{
	uint16_t old, new;

	if (dev->broken ||
		!vq->vring.avail) {
		return;
	}

	/* Make sure buffer is written before we update index. */
	smp_wmb();

	old = vq->used_idx;
	new = old + count;
	vring_used_idx_set(vq, new);
	vq->inuse -= count;
	if ((int16_t)(new - vq->signalled_used) < (uint16_t)(new - old)) {
		vq->signalled_used_valid = false;
	}
}

void vu_queue_push(VuDev *dev, VuVirtq *vq,
		   VuVirtqElement *elem, unsigned int len)
{
	vu_queue_fill(dev, vq, elem, len, 0);
	vu_queue_flush(dev, vq, 1);
}

