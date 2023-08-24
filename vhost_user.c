// SPDX-License-Identifier: GPL-2.0-or-later

/* some parts from QEMU subprojects/libvhost-user/libvhost-user.c */

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <inttypes.h>
#include <time.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <linux/vhost_types.h>
#include <linux/virtio_net.h>

#include "util.h"
#include "passt.h"
#include "tap.h"
#include "vhost_user.h"

#define VHOST_USER_VERSION 1

static unsigned char buffer[65536][VHOST_USER_MAX_QUEUES];

void vu_print_capabilities(void)
{
	printf("{\n");
	printf("  \"type\": \"net\"\n");
	printf("}\n");
	exit(EXIT_SUCCESS);
}

static const char *
vu_request_to_string(unsigned int req)
{
#define REQ(req) [req] = #req
	static const char *vu_request_str[] = {
		REQ(VHOST_USER_NONE),
		REQ(VHOST_USER_GET_FEATURES),
		REQ(VHOST_USER_SET_FEATURES),
		REQ(VHOST_USER_SET_OWNER),
		REQ(VHOST_USER_RESET_OWNER),
		REQ(VHOST_USER_SET_MEM_TABLE),
		REQ(VHOST_USER_SET_LOG_BASE),
		REQ(VHOST_USER_SET_LOG_FD),
		REQ(VHOST_USER_SET_VRING_NUM),
		REQ(VHOST_USER_SET_VRING_ADDR),
		REQ(VHOST_USER_SET_VRING_BASE),
		REQ(VHOST_USER_GET_VRING_BASE),
		REQ(VHOST_USER_SET_VRING_KICK),
		REQ(VHOST_USER_SET_VRING_CALL),
		REQ(VHOST_USER_SET_VRING_ERR),
		REQ(VHOST_USER_GET_PROTOCOL_FEATURES),
		REQ(VHOST_USER_SET_PROTOCOL_FEATURES),
		REQ(VHOST_USER_GET_QUEUE_NUM),
		REQ(VHOST_USER_SET_VRING_ENABLE),
		REQ(VHOST_USER_SEND_RARP),
		REQ(VHOST_USER_NET_SET_MTU),
		REQ(VHOST_USER_SET_BACKEND_REQ_FD),
		REQ(VHOST_USER_IOTLB_MSG),
		REQ(VHOST_USER_SET_VRING_ENDIAN),
		REQ(VHOST_USER_GET_CONFIG),
		REQ(VHOST_USER_SET_CONFIG),
		REQ(VHOST_USER_POSTCOPY_ADVISE),
		REQ(VHOST_USER_POSTCOPY_LISTEN),
		REQ(VHOST_USER_POSTCOPY_END),
		REQ(VHOST_USER_GET_INFLIGHT_FD),
		REQ(VHOST_USER_SET_INFLIGHT_FD),
		REQ(VHOST_USER_GPU_SET_SOCKET),
		REQ(VHOST_USER_VRING_KICK),
		REQ(VHOST_USER_GET_MAX_MEM_SLOTS),
		REQ(VHOST_USER_ADD_MEM_REG),
		REQ(VHOST_USER_REM_MEM_REG),
		REQ(VHOST_USER_MAX),
	};
#undef REQ

	if (req < VHOST_USER_MAX) {
		return vu_request_str[req];
	} else {
		return "unknown";
	}
}

/* Translate qemu virtual address to our virtual address.  */
static void *qva_to_va(VuDev *dev, uint64_t qemu_addr)
{
	unsigned int i;

	/* Find matching memory region.  */
	for (i = 0; i < dev->nregions; i++) {
		VuDevRegion *r = &dev->regions[i];

		if ((qemu_addr >= r->qva) && (qemu_addr < (r->qva + r->size))) {
			return (void *)(uintptr_t)
			(qemu_addr - r->qva + r->mmap_addr + r->mmap_offset);
		}
	}

	return NULL;
}

static void
vmsg_close_fds(VhostUserMsg *vmsg)
{
	int i;

	for (i = 0; i < vmsg->fd_num; i++)
		close(vmsg->fds[i]);
}

static void vu_remove_watch(VuDev *vdev, int fd)
{
	struct ctx *c = (struct ctx *) ((char *)vdev - offsetof(struct ctx, vdev));

	epoll_ctl(c->epollfd, EPOLL_CTL_DEL, fd, NULL);
}

/* Set reply payload.u64 and clear request flags and fd_num */
static void vmsg_set_reply_u64(struct VhostUserMsg *vmsg, uint64_t val)
{
	vmsg->hdr.flags = 0; /* defaults will be set by vu_send_reply() */
	vmsg->hdr.size = sizeof(vmsg->payload.u64);
	vmsg->payload.u64 = val;
	vmsg->fd_num = 0;
}

static ssize_t vu_message_read_default(VuDev *dev, int conn_fd, struct VhostUserMsg *vmsg)
{
	char control[CMSG_SPACE(VHOST_MEMORY_BASELINE_NREGIONS *
		     sizeof(int))] = { 0 };
	struct iovec iov = {
		.iov_base = (char *)vmsg,
		.iov_len = VHOST_USER_HDR_SIZE,
	};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = control,
		.msg_controllen = sizeof(control),
	};
	size_t fd_size;
	struct cmsghdr *cmsg;
	ssize_t ret, sz_payload;

	ret = recvmsg(conn_fd, &msg, MSG_DONTWAIT);
	if (ret < 0) {
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
			return 0;
		vu_panic(dev, "Error while recvmsg: %s", strerror(errno));
		goto out;
	}

	vmsg->fd_num = 0;
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
	     cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET &&
		    cmsg->cmsg_type == SCM_RIGHTS) {
			fd_size = cmsg->cmsg_len - CMSG_LEN(0);
			vmsg->fd_num = fd_size / sizeof(int);
			memcpy(vmsg->fds, CMSG_DATA(cmsg), fd_size);
			break;
		}
	}

	sz_payload = vmsg->hdr.size;
	if ((size_t)sz_payload > sizeof(vmsg->payload)) {
		vu_panic(dev,
			 "Error: too big message request: %d, size: vmsg->size: %zd, "
			 "while sizeof(vmsg->payload) = %zu",
			 vmsg->hdr.request, sz_payload, sizeof(vmsg->payload));
		goto out;
	}

	if (sz_payload) {
		do {
			ret = recv(conn_fd, &vmsg->payload, sz_payload, 0);
		} while (ret < 0 && (errno == EINTR || errno == EAGAIN));

		if (ret < sz_payload) {
			vu_panic(dev, "Error while reading: %s", strerror(errno));
			goto out;
		}
	}

	return 1;
out:
	vmsg_close_fds(vmsg);

	return -ECONNRESET;
}

static int vu_message_write(VuDev *dev, int conn_fd, struct VhostUserMsg *vmsg)
{
	int rc;
	uint8_t *p = (uint8_t *)vmsg;
	char control[CMSG_SPACE(VHOST_MEMORY_BASELINE_NREGIONS * sizeof(int))] = { 0 };
	struct iovec iov = {
		.iov_base = (char *)vmsg,
		.iov_len = VHOST_USER_HDR_SIZE,
	};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = control,
	};
	struct cmsghdr *cmsg;

	memset(control, 0, sizeof(control));
	assert(vmsg->fd_num <= VHOST_MEMORY_BASELINE_NREGIONS);
	if (vmsg->fd_num > 0) {
		size_t fdsize = vmsg->fd_num * sizeof(int);
		msg.msg_controllen = CMSG_SPACE(fdsize);
		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_len = CMSG_LEN(fdsize);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		memcpy(CMSG_DATA(cmsg), vmsg->fds, fdsize);
	} else {
		msg.msg_controllen = 0;
	}

	do {
		rc = sendmsg(conn_fd, &msg, 0);
	} while (rc < 0 && (errno == EINTR || errno == EAGAIN));

	if (vmsg->hdr.size) {
		do {
			if (vmsg->data) {
				rc = write(conn_fd, vmsg->data, vmsg->hdr.size);
			} else {
				rc = write(conn_fd, p + VHOST_USER_HDR_SIZE, vmsg->hdr.size);
			}
		} while (rc < 0 && (errno == EINTR || errno == EAGAIN));
	}

	if (rc <= 0) {
		vu_panic(dev, "Error while writing: %s", strerror(errno));
		return false;
	}

	return true;
}

static int vu_send_reply(VuDev *dev, int conn_fd, struct VhostUserMsg *msg)
{
	msg->hdr.flags &= ~VHOST_USER_VERSION_MASK;
	msg->hdr.flags |= VHOST_USER_VERSION;
	msg->hdr.flags |= VHOST_USER_REPLY_MASK;

	return vu_message_write(dev, conn_fd, msg);
}

static bool vu_get_features_exec(struct VhostUserMsg *msg)
{
	uint64_t features =
		1ULL << VIRTIO_F_VERSION_1 |
		1ULL << VIRTIO_NET_F_MRG_RXBUF |
		1ULL << VHOST_USER_F_PROTOCOL_FEATURES;

	vmsg_set_reply_u64(msg, features);

	debug("Sending back to guest u64: 0x%016"PRIx64, msg->payload.u64);

	return true;
}

static void
vu_set_enable_all_rings(VuDev *vdev, bool enabled)
{
	uint16_t i;

	for (i = 0; i < VHOST_USER_MAX_QUEUES; i++) {
		vdev->vq[i].enable = enabled;
	}
}

static bool
vu_set_features_exec(VuDev *vdev, struct VhostUserMsg *msg)
{
	debug("u64: 0x%016"PRIx64, msg->payload.u64);

	vdev->features = msg->payload.u64;
	if (!vu_has_feature(vdev, VIRTIO_F_VERSION_1)) {
		/*
		 * We only support devices conforming to VIRTIO 1.0 or
		 * later
		 */
		vu_panic(vdev, "virtio legacy devices aren't supported by passt");
		return false;
	}

	if (!vu_has_feature(vdev, VHOST_USER_F_PROTOCOL_FEATURES)) {
		vu_set_enable_all_rings(vdev, true);
	}

	/* virtio-net features */

	if (vu_has_feature(vdev, VIRTIO_F_VERSION_1) ||
	    vu_has_feature(vdev, VIRTIO_NET_F_MRG_RXBUF)) {
		vdev->hdrlen = sizeof(struct virtio_net_hdr_mrg_rxbuf);
	} else {
		vdev->hdrlen = sizeof(struct virtio_net_hdr);
	}

	return false;
}

static bool
vu_set_owner_exec(void)
{
	return false;
}

static bool map_ring(VuDev *vdev, VuVirtq *vq)
{
	vq->vring.desc = qva_to_va(vdev, vq->vra.desc_user_addr);
	vq->vring.used = qva_to_va(vdev, vq->vra.used_user_addr);
	vq->vring.avail = qva_to_va(vdev, vq->vra.avail_user_addr);

	debug("Setting virtq addresses:");
	debug("    vring_desc  at %p", (void *)vq->vring.desc);
	debug("    vring_used  at %p", (void *)vq->vring.used);
	debug("    vring_avail at %p", (void *)vq->vring.avail);

	return !(vq->vring.desc && vq->vring.used && vq->vring.avail);
}

int vu_packet_check_range(void *buf, size_t offset, size_t len, const char *start,
			  const char *func, int line)
{
	VuDevRegion *dev_region;

	for (dev_region = buf; dev_region->mmap_addr; dev_region++) {
		if ((char *)dev_region->mmap_addr <= start &&
		    start + offset + len < (char *)dev_region->mmap_addr +
					   dev_region->mmap_offset +
					   dev_region->size)
			return 0;
	}
	if (func) {
		trace("cannot find region, %s:%i", func, line);
	}

	return -1;
}

/*
 * #syscalls:passt mmap munmap
 */

static bool vu_set_mem_table_exec(VuDev *vdev,
				  struct VhostUserMsg *msg)
{
	unsigned int i;
	struct VhostUserMemory m = msg->payload.memory, *memory = &m;

	for (i = 0; i < vdev->nregions; i++) {
		VuDevRegion *r = &vdev->regions[i];
		void *m = (void *) (uintptr_t) r->mmap_addr;

		if (m)
			munmap(m, r->size + r->mmap_offset);
	}
	vdev->nregions = memory->nregions;

	debug("Nregions: %u", memory->nregions);
	for (i = 0; i < vdev->nregions; i++) {
		void *mmap_addr;
		VhostUserMemory_region *msg_region = &memory->regions[i];
		VuDevRegion *dev_region = &vdev->regions[i];

		debug("Region %d", i);
		debug("    guest_phys_addr: 0x%016"PRIx64,
		      msg_region->guest_phys_addr);
		debug("    memory_size:     0x%016"PRIx64,
		      msg_region->memory_size);
		debug("    userspace_addr   0x%016"PRIx64,
		      msg_region->userspace_addr);
		debug("    mmap_offset      0x%016"PRIx64,
		      msg_region->mmap_offset);

		dev_region->gpa = msg_region->guest_phys_addr;
		dev_region->size = msg_region->memory_size;
		dev_region->qva = msg_region->userspace_addr;
		dev_region->mmap_offset = msg_region->mmap_offset;

		/* We don't use offset argument of mmap() since the
		 * mapped address has to be page aligned, and we use huge
		 * pages.  */
		mmap_addr = mmap(0, dev_region->size + dev_region->mmap_offset,
				 PROT_READ | PROT_WRITE, MAP_SHARED | MAP_NORESERVE,
				 msg->fds[i], 0);

		if (mmap_addr == MAP_FAILED) {
			vu_panic(vdev, "region mmap error: %s", strerror(errno));
		} else {
			dev_region->mmap_addr = (uint64_t)(uintptr_t)mmap_addr;
			debug("    mmap_addr:       0x%016"PRIx64,
			      dev_region->mmap_addr);
		}

		close(msg->fds[i]);
	}

	for (i = 0; i < VHOST_USER_MAX_QUEUES; i++) {
		if (vdev->vq[i].vring.desc) {
			if (map_ring(vdev, &vdev->vq[i])) {
				vu_panic(vdev, "remapping queue %d during setmemtable", i);
			}
		}
	}

	/* XXX */
	ASSERT(vdev->nregions < VHOST_USER_MAX_RAM_SLOTS - 1);
	vdev->regions[vdev->nregions].mmap_addr = 0; /* mark EOF for vu_packet_check_range() */

	tap_sock_update_buf(vdev->regions, 0);

	return false;
}

static bool vu_set_vring_num_exec(VuDev *vdev,
				  struct VhostUserMsg *msg)
{
	unsigned int index = msg->payload.state.index;
	unsigned int num = msg->payload.state.num;

	debug("State.index: %u", index);
	debug("State.num:   %u", num);
	vdev->vq[index].vring.num = num;

	return false;
}

static bool vu_set_vring_addr_exec(VuDev *vdev,
				   struct VhostUserMsg *msg)
{
	struct vhost_vring_addr addr = msg->payload.addr, *vra = &addr;
	unsigned int index = vra->index;
	VuVirtq *vq = &vdev->vq[index];

	debug("vhost_vring_addr:");
	debug("    index:  %d", vra->index);
	debug("    flags:  %d", vra->flags);
	debug("    desc_user_addr:   0x%016" PRIx64, (uint64_t)vra->desc_user_addr);
	debug("    used_user_addr:   0x%016" PRIx64, (uint64_t)vra->used_user_addr);
	debug("    avail_user_addr:  0x%016" PRIx64, (uint64_t)vra->avail_user_addr);
	debug("    log_guest_addr:   0x%016" PRIx64, (uint64_t)vra->log_guest_addr);

	vq->vra = *vra;
	vq->vring.flags = vra->flags;
	vq->vring.log_guest_addr = vra->log_guest_addr;

	if (map_ring(vdev, vq)) {
		vu_panic(vdev, "Invalid vring_addr message");
		return false;
	}

	vq->used_idx = le16toh(vq->vring.used->idx);

	if (vq->last_avail_idx != vq->used_idx) {
		debug("Last avail index != used index: %u != %u",
		      vq->last_avail_idx, vq->used_idx);
	}

	return false;
}

static bool vu_set_vring_base_exec(VuDev *vdev,
				   struct VhostUserMsg *msg)
{
	unsigned int index = msg->payload.state.index;
	unsigned int num = msg->payload.state.num;

	debug("State.index: %u", index);
	debug("State.num:   %u", num);
	vdev->vq[index].shadow_avail_idx = vdev->vq[index].last_avail_idx = num;

	return false;
}

static bool vu_get_vring_base_exec(VuDev *vdev,
				   struct VhostUserMsg *msg)
{
	unsigned int index = msg->payload.state.index;

	debug("State.index: %u", index);
	msg->payload.state.num = vdev->vq[index].last_avail_idx;
	msg->hdr.size = sizeof(msg->payload.state);

	vdev->vq[index].started = false;

	if (vdev->vq[index].call_fd != -1) {
		close(vdev->vq[index].call_fd);
		vdev->vq[index].call_fd = -1;
	}
	if (vdev->vq[index].kick_fd != -1) {
		vu_remove_watch(vdev,  vdev->vq[index].kick_fd);
		close(vdev->vq[index].kick_fd);
		vdev->vq[index].kick_fd = -1;
	}

	return true;
}

static void vu_set_watch(VuDev *vdev, int fd)
{
	struct ctx *c = (struct ctx *) ((char *)vdev - offsetof(struct ctx, vdev));
	union epoll_ref ref = { .type = EPOLL_TYPE_VHOST_KICK, .fd = fd };
	struct epoll_event ev = { 0 };

	ev.data.u64 = ref.u64;
	ev.events = EPOLLIN;
	epoll_ctl(c->epollfd, EPOLL_CTL_ADD, fd, &ev);
}

int vu_send(const struct ctx *c, const void *buf, size_t size)
{
	VuDev *vdev = (VuDev *)&c->vdev;
	size_t hdrlen = vdev->hdrlen;
	VuVirtq *vq = &vdev->vq[VHOST_USER_RX_QUEUE];
	unsigned int indexes[VIRTQUEUE_MAX_SIZE];
	size_t lens[VIRTQUEUE_MAX_SIZE];
	size_t offset;
	int i, j;
	__virtio16 *num_buffers_ptr;

	debug("vu_send size %zu hdrlen %zu", size, hdrlen);

	if (!vu_queue_enabled(vq) || !vu_queue_started(vq)) {
		err("Got packet, but no available descriptors on RX virtq.");
		return 0;
	}

	offset = 0;
	i = 0;
	num_buffers_ptr = NULL;
	while (offset < size) {
		VuVirtqElement *elem;
		size_t len;
		int total;

		total = 0;

		if (i == VIRTQUEUE_MAX_SIZE) {
			err("virtio-net unexpected long buffer chain");
			goto err;
		}

		elem = vu_queue_pop(vdev, vq, sizeof(VuVirtqElement),
				    buffer[VHOST_USER_RX_QUEUE]);
		if (!elem) {
			if (!vdev->broken) {
				eventfd_t kick_data;
				ssize_t rc;
				int status;

				/* wait the kernel to put new entries in the queue */

				status = fcntl(vq->kick_fd, F_GETFL);
				if (status != -1) {
					fcntl(vq->kick_fd, F_SETFL, status & ~O_NONBLOCK);
					rc =  eventfd_read(vq->kick_fd, &kick_data);
					fcntl(vq->kick_fd, F_SETFL, status);
					if (rc != -1)
						continue;
				}
			}
			if (i) {
				err("virtio-net unexpected empty queue: "
				    "i %d mergeable %d offset %zd, size %zd, "
				    "features 0x%" PRIx64,
				    i, vu_has_feature(vdev, VIRTIO_NET_F_MRG_RXBUF),
				    offset, size, vdev->features);
			}
			offset = -1;
			goto err;
		}

		if (elem->in_num < 1) {
			err("virtio-net receive queue contains no in buffers");
			vu_queue_detach_element(vdev, vq, elem->index, 0);
			offset = -1;
			goto err;
		}

		if (i == 0) {
			struct virtio_net_hdr hdr = {
				.flags = VIRTIO_NET_HDR_F_DATA_VALID,
				.gso_type = VIRTIO_NET_HDR_GSO_NONE,
			};

			ASSERT(offset == 0);
			ASSERT(elem->in_sg[0].iov_len >= hdrlen);

			len = iov_from_buf(elem->in_sg, elem->in_num, 0, &hdr, sizeof hdr);

			num_buffers_ptr = (__virtio16 *)((char *)elem->in_sg[0].iov_base +
							 len);

			total += hdrlen;
		}

		len = iov_from_buf(elem->in_sg, elem->in_num, total, (char *)buf + offset,
				   size - offset);

		total += len;
		offset += len;

		/* If buffers can't be merged, at this point we
		 * must have consumed the complete packet.
		 * Otherwise, drop it.
		 */
		if (!vu_has_feature(vdev, VIRTIO_NET_F_MRG_RXBUF) && offset < size) {
			vu_queue_unpop(vdev, vq, elem->index, total);
			goto err;
		}

		indexes[i] = elem->index;
		lens[i] = total;
		i++;
	}

	if (num_buffers_ptr && vu_has_feature(vdev, VIRTIO_NET_F_MRG_RXBUF)) {
		*num_buffers_ptr = htole16(i);
	}

	for (j = 0; j < i; j++) {
		debug("filling total %zd idx %d", lens[j], j);
		vu_queue_fill_by_index(vdev, vq, indexes[j], lens[j], j);
	}

	vu_queue_flush(vdev, vq, i);
	vu_queue_notify(vdev, vq);

	debug("sent %zu", offset);

	return offset;
err:
	for (j = 0; j < i; j++) {
		vu_queue_detach_element(vdev, vq, indexes[j], lens[j]);
	}

	return offset;
}

size_t tap_send_frames_vu(const struct ctx *c, const struct iovec *iov, size_t n)
{
	size_t i;
	int ret;

	debug("tap_send_frames_vu n %zd", n);

	for (i = 0; i < n; i++) {
		ret = vu_send(c, iov[i].iov_base, iov[i].iov_len);
		if (ret < 0)
			break;
	}
	debug("count %zd", i);
	return i;
}

static void vu_handle_tx(VuDev *vdev, int index)
{
	struct ctx *c = (struct ctx *) ((char *)vdev - offsetof(struct ctx, vdev));
	VuVirtq *vq = &vdev->vq[index];
	int hdrlen = vdev->hdrlen;
	struct timespec now;
	unsigned int indexes[VIRTQUEUE_MAX_SIZE];
	int count;

	if (index % 2 != VHOST_USER_TX_QUEUE) {
		debug("index %d is not an TX queue", index);
		return;
	}

	clock_gettime(CLOCK_MONOTONIC, &now);

	pool_flush_all();

	count = 0;
	while (1) {
		VuVirtqElement *elem;

		ASSERT(index == VHOST_USER_TX_QUEUE);
		elem = vu_queue_pop(vdev, vq, sizeof(VuVirtqElement), buffer[index]);
		if (!elem) {
			break;
		}

		if (elem->out_num < 1) {
			debug("virtio-net header not in first element");
			break;
		}
		ASSERT(elem->out_num == 1);

		packet_add_all(c, elem->out_sg[0].iov_len - hdrlen,
			       (char *)elem->out_sg[0].iov_base + hdrlen);
		indexes[count] = elem->index;
		count++;
	}
	tap_handler_all(c, &now);

	if (count) {
		int i;
		for (i = 0; i < count; i++)
			vu_queue_fill_by_index(vdev, vq, indexes[i], 0, i);
		vu_queue_flush(vdev, vq, count);
		vu_queue_notify(vdev, vq);
	}
}

void vu_kick_cb(struct ctx *c, union epoll_ref ref)
{
	VuDev *vdev = &c->vdev;
	eventfd_t kick_data;
	ssize_t rc;
	int index;

	for (index = 0; index < VHOST_USER_MAX_QUEUES; index++)
		if (c->vdev.vq[index].kick_fd == ref.fd)
			break;

	if (index == VHOST_USER_MAX_QUEUES)
		return;

	rc =  eventfd_read(ref.fd, &kick_data);
	if (rc == -1) {
		vu_panic(vdev, "kick eventfd_read(): %s", strerror(errno));
		vu_remove_watch(vdev, ref.fd);
	} else {
		debug("Got kick_data: %016"PRIx64" idx:%d",
		      kick_data, index);
		if (index % 2 == VHOST_USER_TX_QUEUE)
			vu_handle_tx(vdev, index);
	}
}

static bool vu_check_queue_msg_file(VuDev *vdev, struct VhostUserMsg *msg)
{
	int index = msg->payload.u64 & VHOST_USER_VRING_IDX_MASK;
	bool nofd = msg->payload.u64 & VHOST_USER_VRING_NOFD_MASK;

	if (index >= VHOST_USER_MAX_QUEUES) {
		vmsg_close_fds(msg);
		vu_panic(vdev, "Invalid queue index: %u", index);
		return false;
	}

	if (nofd) {
		vmsg_close_fds(msg);
		return true;
	}

	if (msg->fd_num != 1) {
		vmsg_close_fds(msg);
		vu_panic(vdev, "Invalid fds in request: %d", msg->hdr.request);
		return false;
	}

	return true;
}

static bool vu_set_vring_kick_exec(VuDev *vdev,
				   struct VhostUserMsg *msg)
{
	int index = msg->payload.u64 & VHOST_USER_VRING_IDX_MASK;
	bool nofd = msg->payload.u64 & VHOST_USER_VRING_NOFD_MASK;

	debug("u64: 0x%016"PRIx64, msg->payload.u64);

	if (!vu_check_queue_msg_file(vdev, msg))
		return false;

	if (vdev->vq[index].kick_fd != -1) {
		vu_remove_watch(vdev, vdev->vq[index].kick_fd);
		close(vdev->vq[index].kick_fd);
		vdev->vq[index].kick_fd = -1;
	}

	vdev->vq[index].kick_fd = nofd ? -1 : msg->fds[0];
	debug("Got kick_fd: %d for vq: %d", vdev->vq[index].kick_fd, index);

	vdev->vq[index].started = true;

	if (vdev->vq[index].kick_fd != -1 && index % 2 == VHOST_USER_TX_QUEUE) {
		vu_set_watch(vdev, vdev->vq[index].kick_fd);
		debug("Waiting for kicks on fd: %d for vq: %d",
		      vdev->vq[index].kick_fd, index);
	}

	return false;
}

static bool vu_set_vring_call_exec(VuDev *vdev,
				   struct VhostUserMsg *msg)
{
	int index = msg->payload.u64 & VHOST_USER_VRING_IDX_MASK;
	bool nofd = msg->payload.u64 & VHOST_USER_VRING_NOFD_MASK;

	debug("u64: 0x%016"PRIx64, msg->payload.u64);

	if (!vu_check_queue_msg_file(vdev, msg))
		return false;

	if (vdev->vq[index].call_fd != -1) {
		close(vdev->vq[index].call_fd);
		vdev->vq[index].call_fd = -1;
	}

	vdev->vq[index].call_fd = nofd ? -1 : msg->fds[0];

	/* in case of I/O hang after reconnecting */
	if (vdev->vq[index].call_fd != -1) {
		eventfd_write(msg->fds[0], 1);
	}

	debug("Got call_fd: %d for vq: %d", vdev->vq[index].call_fd, index);

	return false;
}

static bool vu_set_vring_err_exec(VuDev *vdev,
				  struct VhostUserMsg *msg)
{
	int index = msg->payload.u64 & VHOST_USER_VRING_IDX_MASK;
	bool nofd = msg->payload.u64 & VHOST_USER_VRING_NOFD_MASK;

	debug("u64: 0x%016"PRIx64, msg->payload.u64);

	if (!vu_check_queue_msg_file(vdev, msg))
		return false;

	if (vdev->vq[index].err_fd != -1) {
		close(vdev->vq[index].err_fd);
		vdev->vq[index].err_fd = -1;
	}

	vdev->vq[index].err_fd = nofd ? -1 : msg->fds[0];

	return false;
}

static bool vu_get_protocol_features_exec(struct VhostUserMsg *msg)
{
	uint64_t features = 1ULL << VHOST_USER_PROTOCOL_F_REPLY_ACK;

	vmsg_set_reply_u64(msg, features);

	return true;
}

static bool vu_set_protocol_features_exec(VuDev *vdev, struct VhostUserMsg *msg)
{
	uint64_t features = msg->payload.u64;

	debug("u64: 0x%016"PRIx64, features);

	vdev->protocol_features = msg->payload.u64;

	if (vu_has_protocol_feature(vdev,
				    VHOST_USER_PROTOCOL_F_INBAND_NOTIFICATIONS) &&
	    (!vu_has_protocol_feature(vdev, VHOST_USER_PROTOCOL_F_BACKEND_REQ) ||
	     !vu_has_protocol_feature(vdev, VHOST_USER_PROTOCOL_F_REPLY_ACK))) {
		/*
		 * The use case for using messages for kick/call is simulation, to make
		 * the kick and call synchronous. To actually get that behaviour, both
		 * of the other features are required.
		 * Theoretically, one could use only kick messages, or do them without
		 * having F_REPLY_ACK, but too many (possibly pending) messages on the
		 * socket will eventually cause the master to hang, to avoid this in
		 * scenarios where not desired enforce that the settings are in a way
		 * that actually enables the simulation case.
		 */
		vu_panic(vdev,
			 "F_IN_BAND_NOTIFICATIONS requires F_BACKEND_REQ && F_REPLY_ACK");
		return false;
	}

	return false;
}


static bool vu_get_queue_num_exec(struct VhostUserMsg *msg)
{
	vmsg_set_reply_u64(msg, VHOST_USER_MAX_QUEUES);
	return true;
}

static bool vu_set_vring_enable_exec(VuDev *vdev, struct VhostUserMsg *msg)
{
	unsigned int index = msg->payload.state.index;
	unsigned int enable = msg->payload.state.num;

	debug("State.index:  %u", index);
	debug("State.enable: %u", enable);

	if (index >= VHOST_USER_MAX_QUEUES) {
		vu_panic(vdev, "Invalid vring_enable index: %u", index);
		return false;
	}

	vdev->vq[index].enable = enable;
	return false;
}

void vu_init(struct ctx *c)
{
	int i;

	c->vdev.hdrlen = 0;
	for (i = 0; i < VHOST_USER_MAX_QUEUES; i++)
		c->vdev.vq[i] = (VuVirtq){
			.call_fd = -1,
			.kick_fd = -1,
			.err_fd = -1,
			.notification = true,
		};
}

static void vu_cleanup(VuDev *vdev)
{
	unsigned int i;

	for (i = 0; i < VHOST_USER_MAX_QUEUES; i++) {
		VuVirtq *vq = &vdev->vq[i];

		vq->started = false;
		vq->notification = true;

		if (vq->call_fd != -1) {
			close(vq->call_fd);
			vq->call_fd = -1;
		}
		if (vq->err_fd != -1) {
			close(vq->err_fd);
			vq->err_fd = -1;
		}
		if (vq->kick_fd != -1) {
			vu_remove_watch(vdev,  vq->kick_fd);
			close(vq->kick_fd);
			vq->kick_fd = -1;
		}

		vq->vring.desc = 0;
		vq->vring.used = 0;
		vq->vring.avail = 0;
	}
	vdev->hdrlen = 0;

	for (i = 0; i < vdev->nregions; i++) {
		VuDevRegion *r = &vdev->regions[i];
		void *m = (void *) (uintptr_t) r->mmap_addr;

		if (m)
			munmap(m, r->size + r->mmap_offset);
	}
	vdev->nregions = 0;
}

/**
 * tap_handler_vu() - Packet handler for vhost-user
 * @c:		Execution context
 * @events:	epoll events
 */
void tap_handler_vu(struct ctx *c, uint32_t events)
{
	VuDev *dev = &c->vdev;
	struct VhostUserMsg msg = { 0 };
	bool need_reply, reply_requested;
	int ret;

	if (events & (EPOLLRDHUP | EPOLLHUP | EPOLLERR)) {
		tap_sock_reset(c);
		return;
	}


	ret = vu_message_read_default(dev, c->fd_tap, &msg);
	if (ret <= 0) {
		if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)
			tap_sock_reset(c);
		return;
	}
	debug("================ Vhost user message ================");
	debug("Request: %s (%d)", vu_request_to_string(msg.hdr.request),
		msg.hdr.request);
	debug("Flags:   0x%x", msg.hdr.flags);
	debug("Size:    %u", msg.hdr.size);

	need_reply = msg.hdr.flags & VHOST_USER_NEED_REPLY_MASK;
	switch (msg.hdr.request) {
	case VHOST_USER_GET_FEATURES:
		reply_requested = vu_get_features_exec(&msg);
		break;
	case VHOST_USER_SET_FEATURES:
		reply_requested = vu_set_features_exec(dev, &msg);
		break;
	case VHOST_USER_GET_PROTOCOL_FEATURES:
		reply_requested = vu_get_protocol_features_exec(&msg);
		break;
	case VHOST_USER_SET_PROTOCOL_FEATURES:
		reply_requested = vu_set_protocol_features_exec(dev, &msg);
		break;
	case VHOST_USER_GET_QUEUE_NUM:
		reply_requested = vu_get_queue_num_exec(&msg);
		break;
	case VHOST_USER_SET_OWNER:
		reply_requested = vu_set_owner_exec();
		break;
	case VHOST_USER_SET_MEM_TABLE:
		reply_requested = vu_set_mem_table_exec(dev, &msg);
		break;
	case VHOST_USER_SET_VRING_NUM:
		reply_requested = vu_set_vring_num_exec(dev, &msg);
		break;
	case VHOST_USER_SET_VRING_ADDR:
		reply_requested = vu_set_vring_addr_exec(dev, &msg);
		break;
	case VHOST_USER_SET_VRING_BASE:
		reply_requested = vu_set_vring_base_exec(dev, &msg);
		break;
	case VHOST_USER_GET_VRING_BASE:
		reply_requested = vu_get_vring_base_exec(dev, &msg);
		break;
	case VHOST_USER_SET_VRING_KICK:
		reply_requested = vu_set_vring_kick_exec(dev, &msg);
		break;
	case VHOST_USER_SET_VRING_CALL:
		reply_requested = vu_set_vring_call_exec(dev, &msg);
		break;
	case VHOST_USER_SET_VRING_ERR:
		reply_requested = vu_set_vring_err_exec(dev, &msg);
		break;
	case VHOST_USER_SET_VRING_ENABLE:
		reply_requested = vu_set_vring_enable_exec(dev, &msg);
		break;
	case VHOST_USER_NONE:
		vu_cleanup(dev);
		return;
	default:
		vu_panic(dev, "Unhandled request: %d", msg.hdr.request);
		return;
	}

	if (!reply_requested && need_reply) {
		msg.payload.u64 = 0;
		msg.hdr.flags = 0;
		msg.hdr.size = sizeof(msg.payload.u64);
		msg.fd_num = 0;
		reply_requested = true;
	}

	if (reply_requested)
		ret = vu_send_reply(dev, c->fd_tap, &msg);
	free(msg.data);
}
