#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/virtio.h>
#include <net/virtio_netdev_common.h>

netdev_tx_t
virtio_netdev_common_start_xmit(struct virtio_netdev_common_info *info, struct sk_buff *skb, struct net_device *dev)
{
	struct virtqueue *vq = info->vq;
	int qnum = skb_get_queue_mapping(skb);
	struct netdev_queue *txq = netdev_get_tx_queue(dev, qnum);
	bool kick = !netdev_xmit_more();
	bool use_napi = info->use_napi;
	int err;

	/* The caller forgot to set the required methods */
	BUG_ON(!info->free_old_xmit_skbs || !info->xmit_skb);

	/* Free up any pending old buffers before queueing new ones. */
	do {
		if (use_napi)
			virtqueue_disable_cb(vq);

		if (!info->free_old_xmit_skbs)
			return NETDEV_TX_BUSY;

		info->free_old_xmit_skbs(info->priv, false);

	} while (use_napi && kick &&
	       unlikely(!virtqueue_enable_cb_delayed(vq)));

	/* timestamp packet in software */
	skb_tx_timestamp(skb);

	/* Try to transmit */
	err = info->xmit_skb(info->priv, skb);

	/* This should not happen! */
	if (unlikely(err)) {
		dev->stats.tx_fifo_errors++;
		if (net_ratelimit())
			dev_warn(&dev->dev,
				 "Unexpected TXQ (%d) queue failure: %d\n",
				 qnum, err);
		dev->stats.tx_dropped++;
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}

	/* Don't wait up for transmitted skbs to be freed. */
	if (!use_napi) {
		skb_orphan(skb);
		nf_reset_ct(skb);
	}

	/* If running out of space, stop queue to avoid getting packets that we
	 * are then unable to transmit.
	 * An alternative would be to force queuing layer to requeue the skb by
	 * returning NETDEV_TX_BUSY. However, NETDEV_TX_BUSY should not be
	 * returned in a normal path of operation: it means that driver is not
	 * maintaining the TX queue stop/start state properly, and causes
	 * the stack to do a non-trivial amount of useless work.
	 * Since most packets only take 1 or 2 ring slots, stopping the queue
	 * early means 16 slots are typically wasted.
	 */
	if (vq->num_free < 2+MAX_SKB_FRAGS) {
		netif_stop_subqueue(dev, qnum);
		if (!use_napi &&
		    unlikely(!virtqueue_enable_cb_delayed(vq))) {
			/* More just got used, free them then recheck. */
			info->free_old_xmit_skbs(info->priv, false);
			if (vq->num_free >= 2+MAX_SKB_FRAGS) {
				netif_start_subqueue(dev, qnum);
				virtqueue_disable_cb(vq);
			}
		}
	}

	if (kick || netif_xmit_stopped(txq)) {
		if (virtqueue_kick_prepare(vq) && virtqueue_notify(vq)) {
			if (info->update_stats) {
				info->update_stats(info->priv);
			}
		}
	}

	return NETDEV_TX_OK;
}
