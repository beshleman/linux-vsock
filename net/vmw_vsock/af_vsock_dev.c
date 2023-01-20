#include <linux/kernel.h>
#include <net/af_vsock.h>

#define VSOCK_DEV_HASH_SIZE 256U
#define VSOCK_DEV_HASH(cid) ((cid) % VSOCK_DEV_HASH_SIZE)

struct list_head vsock_dev_table[VSOCK_DEV_HASH_SIZE];
EXPORT_SYMBOL_GPL(vsock_dev_table);

void vsock_dev_add_dev(struct vsock_dev *vdev)
{
	list_add_tail_rcu(&vdev->table, &vsock_dev_table[VSOCK_DEV_HASH(vdev->cid)]);
}
EXPORT_SYMBOL_GPL(vsock_dev_add_dev);

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
EXPORT_SYMBOL_GPL(vsock_dev_send_pkt);

void vsock_dev_dec_skb(struct sk_buff *skb)
{
	struct vsock_dev *vdev;

	if (!skb->dev)
		return;

	vdev = netdev_priv(skb->dev);
	if (!vdev)
		return;

	if (atomic_dec_and_test(&vdev->inflight_skbs))
		netif_start_queue(vdev->dev);
}
EXPORT_SYMBOL_GPL(vsock_dev_dec_skb);

void vsock_dev_init_dev_table(void)
{
	int i;

	for (i = 0; i < VSOCK_DEV_HASH_SIZE; i++)
		INIT_LIST_HEAD(&vsock_dev_table[i]);
}
EXPORT_SYMBOL_GPL(vsock_dev_init_dev_table);

void vsock_dev_deinit_dev_table(void)
{
	struct vsock_dev *vdev;
	int i;

	for (i = 0; i < VSOCK_DEV_HASH_SIZE; i++)
		list_for_each_entry_rcu(vdev, &vsock_dev_table[i], table)
			list_del_rcu(&vdev->table);
}
EXPORT_SYMBOL_GPL(vsock_dev_deinit_dev_table);
