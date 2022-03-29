// SPDX-License-Identifier: GPL-2.0-only
/*
 * virtio transport for vsock
 *
 * Copyright (C) 2013-2015 Red Hat, Inc.
 * Author: Asias He <asias@redhat.com>
 *         Stefan Hajnoczi <stefanha@redhat.com>
 *
 * Some of the code is take from Gerd Hoffmann <kraxel@redhat.com>'s
 * early virtio-vsock proof-of-concept bits.
 */
#include <linux/spinlock.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/atomic.h>
#include <linux/ethtool.h>
#include <linux/virtio.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_config.h>
#include <linux/virtio_vsock.h>
#include <net/sock.h>
#include <net/pkt_sched.h>
#include <linux/mutex.h>
#include <net/af_vsock.h>

#define TRACE() trace_printk("%s:%d\n", __func__, __LINE__)
#define NUM_OF_SGS (MAX_SKB_FRAGS + 2)

static struct workqueue_struct *virtio_vsock_workqueue;
static struct virtio_vsock __rcu *the_virtio_vsock;
static DEFINE_MUTEX(the_virtio_vsock_mutex); /* protects the_virtio_vsock */
static struct virtio_transport virtio_transport; /* forward declaration */

struct virtio_vsock {
	struct virtio_device *vdev;
	struct net_device *dev;
	struct virtqueue *vqs[VSOCK_VQ_MAX];

	/* Virtqueue processing is deferred to a workqueue */
	struct work_struct tx_work;
	struct work_struct rx_work;
	struct work_struct event_work;

	/* The following fields are protected by tx_lock.  vqs[VSOCK_VQ_TX]
	 * must be accessed with tx_lock held.
	 */
	spinlock_t tx_spin_lock;
	/* TX: fragments + linear part of skb + vsock header */
	struct scatterlist sg[NUM_OF_SGS];
	struct mutex tx_lock;
	bool tx_run;


	struct work_struct send_pkt_work;
	spinlock_t send_pkt_list_lock;
	struct list_head send_pkt_list;

	atomic_t queued_replies;

	/* The following fields are protected by rx_lock.  vqs[VSOCK_VQ_RX]
	 * must be accessed with rx_lock held.
	 */
	struct mutex rx_lock;
	bool rx_run;
	int rx_buf_nr;
	int rx_buf_max_nr;

	/* The following fields are protected by event_lock.
	 * vqs[VSOCK_VQ_EVENT] must be accessed with event_lock held.
	 */
	struct mutex event_lock;
	bool event_run;
	struct virtio_vsock_event event_list[8];

	u32 guest_cid;
	bool seqpacket_allow;
};


/**
 * Must be called when tx_spin_lock is held.
 */
static void free_xmit_skbs(struct virtqueue *vq)
{
	void *ptr;
	unsigned int len;

	while ((ptr = virtqueue_get_buf(vq, &len)) != NULL) {
		struct sk_buff *skb = ptr;
		consume_skb(skb);
	}
}

static netdev_tx_t virtio_vsock_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	int num_sg;
	bool restart_rx = false;
	int qnum = skb_get_queue_mapping(skb);
	struct virtio_vsock *vsock;
	struct virtqueue *vq;
	int err;

	rcu_read_lock();
	vsock = rcu_dereference(the_virtio_vsock);

	spin_lock_bh(&vsock->tx_spin_lock);

	if (!vsock->tx_run)
		goto out;

	vq = vsock->vqs[VSOCK_VQ_TX];
	sg_init_table(vsock->sg, skb_shinfo(skb)->nr_frags + 1);
	num_sg = skb_to_sgvec(skb, vsock->sg, 0, skb->len);
	if (unlikely(num_sg < 0))
		goto out;

	err = virtqueue_add_outbuf(vq, vsock->sg, num_sg, skb, GFP_ATOMIC);
	if (unlikely(err)) {
		printk(KERN_ERR "%s: err=%d\n", __func__, err);
		/*
		 * This should never happen because we should be stopping the
		 * queue before reaching the vq limit.
		 */
		dev_kfree_skb_any(skb);
		goto out;
	}

	TRACE();

	skb_orphan(skb);
	nf_reset_ct(skb);
	TRACE();

	/* Stop the queue if running low on space, to avoid dropping future packets. */
	if (vq->num_free < NUM_OF_SGS) {
		netif_stop_subqueue(dev, qnum);
		free_xmit_skbs(vq);
		if (vq->num_free >= NUM_OF_SGS) {
			netif_start_subqueue(dev, qnum);
			virtqueue_disable_cb(vq);
		}
	}
	TRACE();

	/* Handle enqueuing replies */
	virtqueue_kick(vq);
	TRACE();

out:
	rcu_read_unlock();
	spin_unlock_bh(&vsock->tx_spin_lock);
	TRACE();

	if (restart_rx)
		queue_work(virtio_vsock_workqueue, &vsock->rx_work);

	return NETDEV_TX_OK;
}

static u32 always_on(struct net_device *dev)
{
	return 1;
}

static const struct ethtool_ops virtio_vsock_ethtool_ops = {
	.get_link		= always_on,
};

const struct net_device_ops virtio_vsock_netdev_ops = {
	.ndo_start_xmit = virtio_vsock_start_xmit,
};

static void virtio_vsock_setup(struct net_device *dev)
{
	dev->netdev_ops = &virtio_vsock_netdev_ops;
	dev->ethtool_ops = &virtio_vsock_ethtool_ops;

	dev->needs_free_netdev = true;
	/* TODO: add flags (like IFF_VLAN_CHALLENGED, etc... */
	dev->flags = IFF_NOARP;

	dev->mtu = VIRTIO_VSOCK_MAX_PKT_BUF_SIZE;
	dev->tx_queue_len = DEFAULT_TX_QUEUE_LEN;
}

static u32 virtio_transport_get_local_cid(void)
{
	struct virtio_vsock *vsock;
	u32 ret;

	rcu_read_lock();
	vsock = rcu_dereference(the_virtio_vsock);
	if (!vsock) {
		ret = VMADDR_CID_ANY;
		goto out_rcu;
	}

	ret = vsock->guest_cid;
out_rcu:
	rcu_read_unlock();
	return ret;
}

static void
virtio_transport_send_pkt_work(struct work_struct *work)
{
	struct virtio_vsock *vsock =
		container_of(work, struct virtio_vsock, send_pkt_work);
	struct virtqueue *vq;
	bool added = false;
	bool restart_rx = false;

	mutex_lock(&vsock->tx_lock);

	if (!vsock->tx_run)
		goto out;

	vq = vsock->vqs[VSOCK_VQ_TX];

	for (;;) {
		struct virtio_vsock_pkt *pkt;
		struct scatterlist hdr, buf, *sgs[2];
		int ret, in_sg = 0, out_sg = 0;
		bool reply;

		spin_lock_bh(&vsock->send_pkt_list_lock);
		if (list_empty(&vsock->send_pkt_list)) {
			spin_unlock_bh(&vsock->send_pkt_list_lock);
			break;
		}

		pkt = list_first_entry(&vsock->send_pkt_list,
				       struct virtio_vsock_pkt, list);
		list_del_init(&pkt->list);
		spin_unlock_bh(&vsock->send_pkt_list_lock);

		virtio_transport_deliver_tap_pkt(pkt);

		reply = pkt->reply;

		sg_init_one(&hdr, &pkt->hdr, sizeof(pkt->hdr));
		sgs[out_sg++] = &hdr;
		if (pkt->buf) {
			sg_init_one(&buf, pkt->buf, pkt->len);
			sgs[out_sg++] = &buf;
		}

		ret = virtqueue_add_sgs(vq, sgs, out_sg, in_sg, pkt, GFP_KERNEL);
		/* Usually this means that there is no more space available in
		 * the vq
		 */
		if (ret < 0) {
			spin_lock_bh(&vsock->send_pkt_list_lock);
			list_add(&pkt->list, &vsock->send_pkt_list);
			spin_unlock_bh(&vsock->send_pkt_list_lock);
			break;
		}

		if (reply) {
			struct virtqueue *rx_vq = vsock->vqs[VSOCK_VQ_RX];
			int val;

			val = atomic_dec_return(&vsock->queued_replies);

			/* Do we now have resources to resume rx processing? */
			if (val + 1 == virtqueue_get_vring_size(rx_vq))
				restart_rx = true;
		}

		added = true;
	}

	if (added)
		virtqueue_kick(vq);

out:
	mutex_unlock(&vsock->tx_lock);

	if (restart_rx)
		queue_work(virtio_vsock_workqueue, &vsock->rx_work);
}

static int
virtio_transport_send_pkt(void *opaque)
{
	struct sk_buff *pkt = opaque;
	struct virtio_vsock *vsock;
	struct virtio_vsock_hdr *hdr = (struct virtio_vsock_hdr *)pkt->data;
	struct virtio_vsock_skb_cb *cb;
	int len = hdr->len;
	int err;

	rcu_read_lock();
	vsock = rcu_dereference(the_virtio_vsock);
	if (!vsock) {
		kfree_skb(pkt);
		len = -ENODEV;
		goto out_rcu;
	}

	if (le64_to_cpu(hdr->dst_cid) == vsock->guest_cid) {
		kfree_skb(pkt);
		len = -ENODEV;
		goto out_rcu;
	}

	cb = (struct virtio_vsock_skb_cb *)pkt->cb;
	if (cb->reply)
		atomic_inc(&vsock->queued_replies);

	dev_hold(vsock->dev);
	pkt->dev = vsock->dev;
	if (!pkt->dev) {
		kfree_skb(pkt);
		len = -ENODEV;
		goto out_dev_put;
	}

	err = dev_queue_xmit(pkt);
	if (err > 0)
		err = net_xmit_errno(err);

	if (err) {
		kfree_skb(pkt);
		len = -ENODEV;
	}

out_dev_put:
	dev_put(vsock->dev);

out_rcu:
	rcu_read_unlock();
	return len;
}

static int
virtio_transport_cancel_pkt(struct vsock_sock *vsk)
{
	struct virtio_vsock *vsock;
	struct virtio_vsock_pkt *pkt, *n;
	int cnt = 0, ret;
	LIST_HEAD(freeme);

	rcu_read_lock();
	vsock = rcu_dereference(the_virtio_vsock);
	if (!vsock) {
		ret = -ENODEV;
		goto out_rcu;
	}

	spin_lock_bh(&vsock->send_pkt_list_lock);
	list_for_each_entry_safe(pkt, n, &vsock->send_pkt_list, list) {
		if (pkt->vsk != vsk)
			continue;
		list_move(&pkt->list, &freeme);
	}
	spin_unlock_bh(&vsock->send_pkt_list_lock);

	list_for_each_entry_safe(pkt, n, &freeme, list) {
		if (pkt->reply)
			cnt++;
		list_del(&pkt->list);
		virtio_transport_free_pkt(pkt);
	}

	if (cnt) {
		struct virtqueue *rx_vq = vsock->vqs[VSOCK_VQ_RX];
		int new_cnt;

		new_cnt = atomic_sub_return(cnt, &vsock->queued_replies);
		if (new_cnt + cnt >= virtqueue_get_vring_size(rx_vq) &&
		    new_cnt < virtqueue_get_vring_size(rx_vq))
			queue_work(virtio_vsock_workqueue, &vsock->rx_work);
	}

	ret = 0;

out_rcu:
	rcu_read_unlock();
	return ret;
}

static void virtio_vsock_rx_fill(struct virtio_vsock *vsock)
{
	int buf_len = VIRTIO_VSOCK_DEFAULT_RX_BUF_SIZE;
	struct virtio_vsock_pkt *pkt;
	struct scatterlist hdr, buf, *sgs[2];
	struct virtqueue *vq;
	int ret;

	vq = vsock->vqs[VSOCK_VQ_RX];

	do {
		pkt = kzalloc(sizeof(*pkt), GFP_KERNEL);
		if (!pkt)
			break;

		pkt->buf = kmalloc(buf_len, GFP_KERNEL);
		if (!pkt->buf) {
			virtio_transport_free_pkt(pkt);
			break;
		}

		pkt->buf_len = buf_len;
		pkt->len = buf_len;

		sg_init_one(&hdr, &pkt->hdr, sizeof(pkt->hdr));
		sgs[0] = &hdr;

		sg_init_one(&buf, pkt->buf, buf_len);
		sgs[1] = &buf;
		ret = virtqueue_add_sgs(vq, sgs, 0, 2, pkt, GFP_KERNEL);
		if (ret) {
			virtio_transport_free_pkt(pkt);
			break;
		}
		vsock->rx_buf_nr++;
	} while (vq->num_free);
	if (vsock->rx_buf_nr > vsock->rx_buf_max_nr)
		vsock->rx_buf_max_nr = vsock->rx_buf_nr;
	virtqueue_kick(vq);
}

static void virtio_transport_tx_work(struct work_struct *work)
{
	struct virtio_vsock *vsock =
		container_of(work, struct virtio_vsock, tx_work);
	struct virtqueue *vq;
	bool added = false;

	vq = vsock->vqs[VSOCK_VQ_TX];
	mutex_lock(&vsock->tx_lock);

	if (!vsock->tx_run)
		goto out;

	do {
		struct virtio_vsock_pkt *pkt;
		unsigned int len;

		virtqueue_disable_cb(vq);
		while ((pkt = virtqueue_get_buf(vq, &len)) != NULL) {
			virtio_transport_free_pkt(pkt);
			added = true;
		}
	} while (!virtqueue_enable_cb(vq));

out:
	mutex_unlock(&vsock->tx_lock);

	if (added)
		queue_work(virtio_vsock_workqueue, &vsock->send_pkt_work);
}

/* Is there space left for replies to rx packets? */
static bool virtio_transport_more_replies(struct virtio_vsock *vsock)
{
	struct virtqueue *vq = vsock->vqs[VSOCK_VQ_RX];
	int val;

	smp_rmb(); /* paired with atomic_inc() and atomic_dec_return() */
	val = atomic_read(&vsock->queued_replies);

	return val < virtqueue_get_vring_size(vq);
}

/* event_lock must be held */
static int virtio_vsock_event_fill_one(struct virtio_vsock *vsock,
				       struct virtio_vsock_event *event)
{
	struct scatterlist sg;
	struct virtqueue *vq;

	vq = vsock->vqs[VSOCK_VQ_EVENT];

	sg_init_one(&sg, event, sizeof(*event));

	return virtqueue_add_inbuf(vq, &sg, 1, event, GFP_KERNEL);
}

/* event_lock must be held */
static void virtio_vsock_event_fill(struct virtio_vsock *vsock)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(vsock->event_list); i++) {
		struct virtio_vsock_event *event = &vsock->event_list[i];

		virtio_vsock_event_fill_one(vsock, event);
	}

	virtqueue_kick(vsock->vqs[VSOCK_VQ_EVENT]);
}

static void virtio_vsock_reset_sock(struct sock *sk)
{
	/* vmci_transport.c doesn't take sk_lock here either.  At least we're
	 * under vsock_table_lock so the sock cannot disappear while we're
	 * executing.
	 */

	sk->sk_state = TCP_CLOSE;
	sk->sk_err = ECONNRESET;
	sk_error_report(sk);
}

static void virtio_vsock_update_guest_cid(struct virtio_vsock *vsock)
{
	struct virtio_device *vdev = vsock->vdev;
	__le64 guest_cid;

	vdev->config->get(vdev, offsetof(struct virtio_vsock_config, guest_cid),
			  &guest_cid, sizeof(guest_cid));
	vsock->guest_cid = le64_to_cpu(guest_cid);
}

/* event_lock must be held */
static void virtio_vsock_event_handle(struct virtio_vsock *vsock,
				      struct virtio_vsock_event *event)
{
	switch (le32_to_cpu(event->id)) {
	case VIRTIO_VSOCK_EVENT_TRANSPORT_RESET:
		virtio_vsock_update_guest_cid(vsock);
		vsock_for_each_connected_socket(&virtio_transport.transport,
						virtio_vsock_reset_sock);
		break;
	}
}

static void virtio_transport_event_work(struct work_struct *work)
{
	struct virtio_vsock *vsock =
		container_of(work, struct virtio_vsock, event_work);
	struct virtqueue *vq;

	vq = vsock->vqs[VSOCK_VQ_EVENT];

	mutex_lock(&vsock->event_lock);

	if (!vsock->event_run)
		goto out;

	do {
		struct virtio_vsock_event *event;
		unsigned int len;

		virtqueue_disable_cb(vq);
		while ((event = virtqueue_get_buf(vq, &len)) != NULL) {
			if (len == sizeof(*event))
				virtio_vsock_event_handle(vsock, event);

			virtio_vsock_event_fill_one(vsock, event);
		}
	} while (!virtqueue_enable_cb(vq));

	virtqueue_kick(vsock->vqs[VSOCK_VQ_EVENT]);
out:
	mutex_unlock(&vsock->event_lock);
}

static void virtio_vsock_event_done(struct virtqueue *vq)
{
	struct virtio_vsock *vsock = vq->vdev->priv;

	if (!vsock)
		return;
	queue_work(virtio_vsock_workqueue, &vsock->event_work);
}

static void virtio_vsock_tx_done(struct virtqueue *vq)
{
	struct virtio_vsock *vsock = vq->vdev->priv;

	if (!vsock)
		return;
	queue_work(virtio_vsock_workqueue, &vsock->tx_work);
}

static void virtio_vsock_rx_done(struct virtqueue *vq)
{
	struct virtio_vsock *vsock = vq->vdev->priv;

	if (!vsock)
		return;
	queue_work(virtio_vsock_workqueue, &vsock->rx_work);
}

static bool virtio_transport_seqpacket_allow(u32 remote_cid);

static struct virtio_transport virtio_transport = {
	.transport = {
		.module                   = THIS_MODULE,

		.get_local_cid            = virtio_transport_get_local_cid,

		.init                     = virtio_transport_do_socket_init,
		.destruct                 = virtio_transport_destruct,
		.release                  = virtio_transport_release,
		.connect                  = virtio_transport_connect,
		.shutdown                 = virtio_transport_shutdown,
		.cancel_pkt               = virtio_transport_cancel_pkt,

		.dgram_bind               = virtio_transport_dgram_bind,
		.dgram_dequeue            = virtio_transport_dgram_dequeue,
		.dgram_enqueue            = virtio_transport_dgram_enqueue,
		.dgram_allow              = virtio_transport_dgram_allow,

		.stream_dequeue           = virtio_transport_stream_dequeue,
		.stream_enqueue           = virtio_transport_stream_enqueue,
		.stream_has_data          = virtio_transport_stream_has_data,
		.stream_has_space         = virtio_transport_stream_has_space,
		.stream_rcvhiwat          = virtio_transport_stream_rcvhiwat,
		.stream_is_active         = virtio_transport_stream_is_active,
		.stream_allow             = virtio_transport_stream_allow,

		.seqpacket_dequeue        = virtio_transport_seqpacket_dequeue,
		.seqpacket_enqueue        = virtio_transport_seqpacket_enqueue,
		.seqpacket_allow          = virtio_transport_seqpacket_allow,
		.seqpacket_has_data       = virtio_transport_seqpacket_has_data,

		.notify_poll_in           = virtio_transport_notify_poll_in,
		.notify_poll_out          = virtio_transport_notify_poll_out,
		.notify_recv_init         = virtio_transport_notify_recv_init,
		.notify_recv_pre_block    = virtio_transport_notify_recv_pre_block,
		.notify_recv_pre_dequeue  = virtio_transport_notify_recv_pre_dequeue,
		.notify_recv_post_dequeue = virtio_transport_notify_recv_post_dequeue,
		.notify_send_init         = virtio_transport_notify_send_init,
		.notify_send_pre_block    = virtio_transport_notify_send_pre_block,
		.notify_send_pre_enqueue  = virtio_transport_notify_send_pre_enqueue,
		.notify_send_post_enqueue = virtio_transport_notify_send_post_enqueue,
		.notify_buffer_size       = virtio_transport_notify_buffer_size,
	},

	.send_pkt = virtio_transport_send_pkt,
};

static bool virtio_transport_seqpacket_allow(u32 remote_cid)
{
	struct virtio_vsock *vsock;
	bool seqpacket_allow;

	seqpacket_allow = false;
	rcu_read_lock();
	vsock = rcu_dereference(the_virtio_vsock);
	if (vsock)
		seqpacket_allow = vsock->seqpacket_allow;
	rcu_read_unlock();

	return seqpacket_allow;
}

static void virtio_transport_rx_work(struct work_struct *work)
{
	struct virtio_vsock *vsock =
		container_of(work, struct virtio_vsock, rx_work);
	struct virtqueue *vq;

	vq = vsock->vqs[VSOCK_VQ_RX];

	mutex_lock(&vsock->rx_lock);

	if (!vsock->rx_run)
		goto out;

	do {
		virtqueue_disable_cb(vq);
		for (;;) {
			struct virtio_vsock_pkt *pkt;
			unsigned int len;

			if (!virtio_transport_more_replies(vsock)) {
				/* Stop rx until the device processes already
				 * pending replies.  Leave rx virtqueue
				 * callbacks disabled.
				 */
				goto out;
			}

			pkt = virtqueue_get_buf(vq, &len);
			if (!pkt) {
				break;
			}

			vsock->rx_buf_nr--;

			/* Drop short/long packets */
			if (unlikely(len < sizeof(pkt->hdr) ||
				     len > sizeof(pkt->hdr) + pkt->len)) {
				virtio_transport_free_pkt(pkt);
				continue;
			}

			pkt->len = len - sizeof(pkt->hdr);
			virtio_transport_deliver_tap_pkt(pkt);
			virtio_transport_recv_pkt(&virtio_transport, pkt);
		}
	} while (!virtqueue_enable_cb(vq));

out:
	if (vsock->rx_buf_nr < vsock->rx_buf_max_nr / 2)
		virtio_vsock_rx_fill(vsock);
	mutex_unlock(&vsock->rx_lock);
}

static int virtio_vsock_probe(struct virtio_device *vdev)
{
	vq_callback_t *callbacks[] = {
		virtio_vsock_rx_done,
		virtio_vsock_tx_done,
		virtio_vsock_event_done,
	};
	static const char * const names[] = {
		"rx",
		"tx",
		"event",
	};
	struct net_device *dev = NULL;
	struct virtio_vsock *vsock = NULL;
	int ret;

	ret = mutex_lock_interruptible(&the_virtio_vsock_mutex);
	if (ret)
		return ret;

	/* Only one virtio-vsock device per guest is supported */
	if (rcu_dereference_protected(the_virtio_vsock,
				lockdep_is_held(&the_virtio_vsock_mutex))) {
		ret = -EBUSY;
		goto out;
	}

	vsock = kzalloc(sizeof(*vsock), GFP_KERNEL);
	if (!vsock) {
		ret = -ENOMEM;
		goto out;
	}

	vsock->vdev = vdev;

	ret = virtio_find_vqs(vsock->vdev, VSOCK_VQ_MAX,
			      vsock->vqs, callbacks, names,
			      NULL);
	if (ret < 0)
		goto out;

	virtio_vsock_update_guest_cid(vsock);

	vsock->rx_buf_nr = 0;
	vsock->rx_buf_max_nr = 0;
	atomic_set(&vsock->queued_replies, 0);

	spin_lock_init(&vsock->tx_spin_lock);
	mutex_init(&vsock->tx_lock);
	mutex_init(&vsock->rx_lock);
	mutex_init(&vsock->event_lock);
	spin_lock_init(&vsock->send_pkt_list_lock);
	INIT_LIST_HEAD(&vsock->send_pkt_list);
	INIT_WORK(&vsock->rx_work, virtio_transport_rx_work);
	INIT_WORK(&vsock->tx_work, virtio_transport_tx_work);
	INIT_WORK(&vsock->event_work, virtio_transport_event_work);
	INIT_WORK(&vsock->send_pkt_work, virtio_transport_send_pkt_work);

	mutex_lock(&vsock->tx_lock);
	vsock->tx_run = true;
	mutex_unlock(&vsock->tx_lock);

	mutex_lock(&vsock->rx_lock);
	virtio_vsock_rx_fill(vsock);
	vsock->rx_run = true;
	mutex_unlock(&vsock->rx_lock);

	mutex_lock(&vsock->event_lock);
	virtio_vsock_event_fill(vsock);
	vsock->event_run = true;
	mutex_unlock(&vsock->event_lock);

	if (virtio_has_feature(vdev, VIRTIO_VSOCK_F_SEQPACKET))
		vsock->seqpacket_allow = true;

	dev = alloc_netdev(0, "vvsk", NET_NAME_UNKNOWN, virtio_vsock_setup);
	if (!dev) {
		ret = -ENOMEM;
		goto out;
	}

	vsock->dev = dev;
	SET_NETDEV_DEV(dev, &vdev->dev);

	ret = register_netdev(dev);
	if (ret < 0)
		goto out_free_netdev;

	vdev->priv = vsock;

	rtnl_lock();
	if (dev_open(dev, NULL)) {
		ret = -ENOMEM;
		rtnl_unlock();
		goto out_unregister_netdev;
	}
	rtnl_unlock();

	rcu_assign_pointer(the_virtio_vsock, vsock);

	mutex_unlock(&the_virtio_vsock_mutex);

	return 0;

out_unregister_netdev:
	unregister_netdev(dev);

out_free_netdev:
	kfree(dev);

out:
	kfree(vsock);
	mutex_unlock(&the_virtio_vsock_mutex);
	return ret;
}

static void virtio_vsock_remove(struct virtio_device *vdev)
{
	struct virtio_vsock *vsock = vdev->priv;
	struct virtio_vsock_pkt *pkt;

	mutex_lock(&the_virtio_vsock_mutex);

	vdev->priv = NULL;
	rcu_assign_pointer(the_virtio_vsock, NULL);
	synchronize_rcu();

	/* Reset all connected sockets when the device disappear */
	vsock_for_each_connected_socket(&virtio_transport.transport,
					virtio_vsock_reset_sock);

	/* Stop all work handlers to make sure no one is accessing the device,
	 * so we can safely call virtio_reset_device().
	 */
	mutex_lock(&vsock->rx_lock);
	vsock->rx_run = false;
	mutex_unlock(&vsock->rx_lock);

	mutex_lock(&vsock->tx_lock);
	vsock->tx_run = false;
	mutex_unlock(&vsock->tx_lock);

	mutex_lock(&vsock->event_lock);
	vsock->event_run = false;
	mutex_unlock(&vsock->event_lock);

	/* Flush all device writes and interrupts, device will not use any
	 * more buffers.
	 */
	virtio_reset_device(vdev);

	mutex_lock(&vsock->rx_lock);
	while ((pkt = virtqueue_detach_unused_buf(vsock->vqs[VSOCK_VQ_RX])))
		virtio_transport_free_pkt(pkt);
	mutex_unlock(&vsock->rx_lock);

	mutex_lock(&vsock->tx_lock);
	while ((pkt = virtqueue_detach_unused_buf(vsock->vqs[VSOCK_VQ_TX])))
		virtio_transport_free_pkt(pkt);
	mutex_unlock(&vsock->tx_lock);

	spin_lock_bh(&vsock->send_pkt_list_lock);
	while (!list_empty(&vsock->send_pkt_list)) {
		pkt = list_first_entry(&vsock->send_pkt_list,
				       struct virtio_vsock_pkt, list);
		list_del(&pkt->list);
		virtio_transport_free_pkt(pkt);
	}
	spin_unlock_bh(&vsock->send_pkt_list_lock);

	/* Delete virtqueues and flush outstanding callbacks if any */
	vdev->config->del_vqs(vdev);

	/* Other works can be queued before 'config->del_vqs()', so we flush
	 * all works before to free the vsock object to avoid use after free.
	 */
	flush_work(&vsock->rx_work);
	flush_work(&vsock->tx_work);
	flush_work(&vsock->event_work);
	flush_work(&vsock->send_pkt_work);

	mutex_unlock(&the_virtio_vsock_mutex);

	kfree(vsock);
}

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_VSOCK, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static unsigned int features[] = {
	VIRTIO_VSOCK_F_SEQPACKET
};

static struct virtio_driver virtio_vsock_driver = {
	.feature_table = features,
	.feature_table_size = ARRAY_SIZE(features),
	.driver.name = KBUILD_MODNAME,
	.driver.owner = THIS_MODULE,
	.id_table = id_table,
	.probe = virtio_vsock_probe,
	.remove = virtio_vsock_remove,
};

static int __init virtio_vsock_init(void)
{
	int ret;

	virtio_vsock_workqueue = alloc_workqueue("virtio_vsock", 0, 0);
	if (!virtio_vsock_workqueue)
		return -ENOMEM;

	ret = vsock_core_register(&virtio_transport.transport,
				  VSOCK_TRANSPORT_F_G2H);
	if (ret)
		goto out_wq;

	ret = register_virtio_driver(&virtio_vsock_driver);
	if (ret)
		goto out_vci;

	return 0;

out_vci:
	vsock_core_unregister(&virtio_transport.transport);
out_wq:
	destroy_workqueue(virtio_vsock_workqueue);
	return ret;
}

static void __exit virtio_vsock_exit(void)
{
	unregister_virtio_driver(&virtio_vsock_driver);
	vsock_core_unregister(&virtio_transport.transport);
	destroy_workqueue(virtio_vsock_workqueue);
}

module_init(virtio_vsock_init);
module_exit(virtio_vsock_exit);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Asias He");
MODULE_DESCRIPTION("virtio transport for vsock");
MODULE_DEVICE_TABLE(virtio, id_table);
