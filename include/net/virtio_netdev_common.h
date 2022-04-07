#ifndef __H_VIRTIO_NETDEV_COMMON__
#define __H_VIRTIO_NETDEV_COMMON__

#include <linux/netdevice.h>
#include <linux/scatterlist.h>
#include <linux/virtio.h>
#include <linux/virtio_net.h>

struct virtio_netdev_common_info {
	void *priv;
	struct virtqueue *vq;

	int (*xmit_skb)(void *priv, struct sk_buff*);
	void (*free_old_xmit_skbs)(void *priv, bool in_napi);
	void (*update_stats)(void *priv);

	bool use_napi;
};

netdev_tx_t virtio_netdev_common_start_xmit(struct virtio_netdev_common_info *info, struct sk_buff *skb, struct net_device *dev);

#endif /* __H_VIRTIO_NETDEV_COMMON__ */
