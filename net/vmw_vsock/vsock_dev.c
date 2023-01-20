// SPDX-License-Identifier: GPL-2.0-only
#include <linux/ethtool.h>
#include <linux/etherdevice.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/if_arp.h>
#include <net/rtnetlink.h>
#include <net/sock.h>
#include <net/af_vsock.h>
#include <linux/virtio_vsock.h>
#include <uapi/linux/if_link.h>
#include <uapi/linux/if_ether.h>

#define VSOCK_DEV_MAX_INFLIGHT_SKB 1024

#define VSOCK_DEV_HASH_SIZE 256U
#define VSOCK_DEV_HASH(cid) ((cid) % VSOCK_DEV_HASH_SIZE)

extern vsock_send_fn *__vsock_send_pkt;

static struct list_head vsock_dev_table[VSOCK_DEV_HASH_SIZE];

static const struct nla_policy vsock_policy[IFLA_VSOCK_MAX + 1] = {
	[IFLA_VSOCK_CID] = { .type = NLA_U32 },
};

struct vsock_dev {
	struct list_head table;
	struct net_device *dev;
	int (*send_pkt)(struct sk_buff*);
	u32 cid;
	atomic_t inflight_skbs;
};

struct vsock_dev *vsock_dev_find_dev(u32 cid)
{
	struct list_head *list = &vsock_dev_table[VSOCK_DEV_HASH(cid)];
	struct vsock_dev *vdev = NULL;

	rcu_read_lock();
	if (list_empty(list))
		goto out;

	list_for_each_entry_rcu(vdev, list, table) {
		if (vdev->cid == cid)
			goto out;
	}
out:
	rcu_read_unlock();
	return vdev;
}
EXPORT_SYMBOL_GPL(vsock_dev_find_dev);

void vsock_dev_inc_skb(struct vsock_dev *vdev)
{
	int inflight;

	if (!vdev)
		return;

	inflight = atomic_inc_return(&vdev->inflight_skbs);
	if (inflight >= VSOCK_DEV_MAX_INFLIGHT_SKB)
		netif_stop_queue(vdev->dev);
}

void vsock_dev_dec_skb(u32 cid, int cnt)
{
	struct vsock_dev *vdev;
	int inflight;

	vdev = vsock_dev_find_dev(cid);
	if (!vdev) {
		trace_printk("no dev for cid %u", cid);
		return;
	}

	inflight = atomic_sub_return(cnt, &vdev->inflight_skbs);
	if (inflight == 0) {
		netif_start_queue(vdev->dev);
		trace_printk("netif_start_queue");
	}
}
EXPORT_SYMBOL_GPL(vsock_dev_dec_skb);

int vsock_dev_send_pkt(int (*send_pkt)(struct sk_buff *), struct sk_buff *skb, u32 dst_cid)
{
	struct vsock_dev *vdev;
	int len;

	if ((vdev = vsock_dev_find_dev(dst_cid)) != NULL) {
		len = skb->len;
		skb->dev = vdev->dev;
		skb->protocol = htons(ETH_P_VSOCK);
		vdev->send_pkt = send_pkt;
		dev_queue_xmit(skb);
		return len;
	}

	return send_pkt(skb);
}

static int vsock_dev_init(struct net_device *dev)
{
	dev->lstats = netdev_alloc_pcpu_stats(struct pcpu_lstats);
	if (!dev->lstats)
		return -ENOMEM;
	return 0;
}

static void vsock_dev_uninit(struct net_device *dev)
{
	free_percpu(dev->lstats);
}

static netdev_tx_t vsock_dev_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct vsock_dev *vdev = netdev_priv(dev);
	struct net_device_stats *stats = &dev->stats;

	if (vdev->send_pkt(skb) < 0) {
		stats->tx_errors++;
		return NETDEV_TX_OK;
	}

	stats->tx_packets++;
	stats->tx_bytes += skb->len;
	vsock_dev_inc_skb(vdev);

	return NETDEV_TX_OK;
}

static void
vsock_dev_get_stats64(struct net_device *dev, struct rtnl_link_stats64 *stats)
{
	dev_lstats_read(dev, &stats->rx_packets, &stats->rx_bytes);

	stats->tx_packets = 0;
	stats->tx_bytes = 0;
}

static const struct net_device_ops vsock_dev_ops = {
	.ndo_init = vsock_dev_init,
	.ndo_uninit = vsock_dev_uninit,
	.ndo_start_xmit = vsock_dev_xmit,
	.ndo_get_stats64 = vsock_dev_get_stats64,
};

static u32 always_on(struct net_device *dev)
{
	return 1;
}

static const struct ethtool_ops vsock_dev_ethtool_ops = {
	.get_link = always_on,
};

static void vsock_dev_setup(struct net_device *dev)
{
	dev->type = ARPHRD_VSOCK;
	dev->priv_flags |= IFF_NO_QUEUE;
	dev->netdev_ops = &vsock_dev_ops;
	dev->ethtool_ops = &vsock_dev_ethtool_ops;
	dev->needs_free_netdev = true;
	dev->mtu = VIRTIO_VSOCK_MAX_PKT_BUF_SIZE;
	dev->flags = IFF_NOARP;
}

static int vsock_dev_changelink(struct net_device *dev, struct nlattr *tb[],
				struct nlattr *data[],
				struct netlink_ext_ack *extack)
{
	struct vsock_dev *vdev = netdev_priv(dev);
	u32 cid;

	if (data && data[IFLA_VSOCK_CID]) {
		cid = nla_get_u32(data[IFLA_VSOCK_CID]);
		if (vsock_dev_find_dev(cid))
			return -EEXIST;
		vdev->cid = cid;
	}

	return 0;
}

static int vsock_dev_newlink(struct net *src_net, struct net_device *dev,
		       struct nlattr *tb[], struct nlattr *data[],
		       struct netlink_ext_ack *extack)
{
	struct vsock_dev *vdev = netdev_priv(dev);
	u32 cid;
	int ret;

	/* VMADDR_CID_ANY is used as the invalid cid because it must be
	 * resolved before sending packets.
	 */
	vdev->cid = VMADDR_CID_ANY;
	if (data && data[IFLA_VSOCK_CID]) {
		cid = nla_get_u32(data[IFLA_VSOCK_CID]);
		if (vsock_dev_find_dev(cid))
			return -EEXIST;
		vdev->cid = cid;
	}
	vdev->send_pkt = NULL;
	vdev->dev = dev;

	ret = register_netdevice(dev);
	if (ret < 0)
		return ret;

	list_add_tail_rcu(&vdev->table, &vsock_dev_table[VSOCK_DEV_HASH(vdev->cid)]);
	return 0;
}

static void vsock_dev_dellink(struct net_device *dev, struct list_head *head)
{
	struct vsock_dev *vdev = netdev_priv(dev);

	list_del_rcu(&vdev->table);
	unregister_netdevice_queue(dev, head);
}

static int vsock_dev_fill_info(struct sk_buff *skb, const struct net_device *dev)
{
	struct vsock_dev *vdev = netdev_priv(dev);

	if (nla_put_u32(skb, IFLA_VSOCK_CID, vdev->cid))
		return -EMSGSIZE;

	return 0;
}

static size_t vsock_dev_get_size(const struct net_device *dev)
{
	return nla_total_size(sizeof(u32));	/* IFLA_VSOCK_MASTER  */
}

static struct rtnl_link_ops vsock_dev_link_ops __read_mostly = {
	.kind			= "vsock",
	.priv_size		= sizeof(struct vsock_dev),
	.maxtype		= IFLA_VSOCK_MAX,
	.policy			= vsock_policy,
	.setup			= vsock_dev_setup,
	.changelink		= vsock_dev_changelink,
	.newlink		= vsock_dev_newlink,
	.dellink		= vsock_dev_dellink,
	.fill_info		= vsock_dev_fill_info,
	.get_size		= vsock_dev_get_size,
};

int vsock_dev_register(void)
{
	int i;
	int ret;

	for (i=0; i<VSOCK_DEV_HASH_SIZE; i++)
		INIT_LIST_HEAD(&vsock_dev_table[i]);

	ret =  rtnl_link_register(&vsock_dev_link_ops);

	/* Make sure that all module initialization is visible before
	 * publishing the new function.
	 */
	smp_store_release(&__vsock_send_pkt, &vsock_dev_send_pkt);

	return ret;
}

void vsock_dev_unregister(void)
{
	struct vsock_dev *vdev;
	int i;

	smp_store_release(&__vsock_send_pkt, NULL);

	for (i=0; i<VSOCK_DEV_HASH_SIZE; i++) {
		list_for_each_entry_rcu(vdev, &vsock_dev_table[i], table) {
			list_del_rcu(&vdev->table);
		}
	}

	rtnl_link_unregister(&vsock_dev_link_ops);
}
