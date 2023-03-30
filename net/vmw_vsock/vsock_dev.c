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

extern struct list_head vsock_dev_table[];

static const struct nla_policy vsock_policy[IFLA_VSOCK_MAX + 1] = {
	[IFLA_VSOCK_CID] = { .type = NLA_U32 },
};

static int vsock_dev_init(struct net_device *dev)
{
	dev->tstats = netdev_alloc_pcpu_stats(struct pcpu_sw_netstats);
	if (!dev->tstats)
		return -ENOMEM;
	return 0;
}

static void vsock_dev_uninit(struct net_device *dev)
{
	struct vsock_dev *vdev = netdev_priv(dev);

	free_percpu(dev->tstats);

	if (vdev->transport) {
		module_put(vdev->transport->module);
		vdev->transport = NULL;
	}
}

static netdev_tx_t vsock_dev_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct vsock_dev *vdev = netdev_priv(dev);

	if (vdev->transport->dev_send_pkt(skb) < 0) {
		/* This a hard error and implies a bug in queue management. */
		pr_err_ratelimited("vsock transport failing to send pkt, stopping queue...\n");
		dev->stats.tx_errors++;
		return NETDEV_TX_BUSY;
	}

	dev_sw_netstats_tx_add(dev, 1, skb->len);

	if (vdev->transport->get_pending_tx(vdev) >= vdev->dev->tx_queue_len)
		netif_stop_queue(vdev->dev);

	return NETDEV_TX_OK;
}

static const struct net_device_ops vsock_dev_ops = {
	.ndo_init = vsock_dev_init,
	.ndo_uninit = vsock_dev_uninit,
	.ndo_start_xmit = vsock_dev_xmit,
	.ndo_get_stats64 = dev_get_tstats64,
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

	vdev->dev = dev;
	ret = register_netdevice(dev);
	if (ret < 0) {
		vdev->dev = NULL;
		return ret;
	}

	vsock_dev_add_dev(vdev);
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

static int __init vsock_dev_module_init(void)
{
	vsock_dev_init_dev_table();
	return rtnl_link_register(&vsock_dev_link_ops);
}

static void __exit vsock_dev_module_exit(void)
{
	vsock_dev_deinit_dev_table();
	rtnl_link_unregister(&vsock_dev_link_ops);
}

module_init(vsock_dev_module_init);
module_exit(vsock_dev_module_exit);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Bobby Eshleman");
MODULE_DESCRIPTION("device for vsock sockets");
